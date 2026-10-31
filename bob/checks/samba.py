"""
Samba security audit check for BOB.

Analyses:
  - /etc/samba/smb.conf (server configuration)
  - SMB protocol version (SMB1 is critically insecure)
  - Null password authentication
  - Server signing enforcement
  - Guest/anonymous shares (writable and read-only)
  - map to guest setting
  - Network binding (bind interfaces only)

Usage:
    from bob.checks.samba import SambaSnapshot, check_samba

    snapshot = SambaSnapshot.from_system()
    result   = check_samba(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bob._atomic import read_text_capped
from bob.checks._run import TranslationFunc, _command_exists, _identity_t, path_exists, sed_ci
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SMB_CONF_PATH = Path("/etc/samba/smb.conf")


def _global_directive_cmd(directive: str, *clear_params: str) -> str:
    """A command that makes *directive* the effective value in ``[global]``.

    It **deletes** every existing assignment of the parameter (all *clear_params*
    spellings — e.g. ``min protocol`` and its synonym ``server min protocol``)
    and then inserts *directive* once under ``[global]``.

    The earlier version only *appended* the line, guarded by a ``grep`` so it
    would not add a second copy. Field-tested on a real Raspberry Pi (Samba
    4.22) against the configs that actually trigger these findings, that was a
    silent no-op — and worse. The findings only fire when the bad directive is
    *explicitly present* (``server min protocol = NT1``, ``server signing =
    disabled``, ``map to guest = bad user``); the default value fires nothing.
    Appending ``min protocol = SMB2`` above the existing ``NT1`` line left two
    assignments, and samba resolves duplicates **last-wins** — ``testparm``
    still answered ``NT1``, so the fix did not disable SMB1. BOB's own parser
    resolves duplicates the other way, so it read the inserted value and
    reported the finding *resolved* on a host still serving SMB1: a fix that
    lied. Deleting first, then inserting, makes the directive the only
    assignment, so samba and BOB agree and the finding truly clears. Idempotent:
    a re-run deletes the inserted line too and re-inserts it once.

    These are global-only parameters, so deleting every occurrence (rather than
    scoping the delete to ``[global]``) is safe and simpler; samba would reject
    them in any other section anyway.
    """
    params = clear_params or (directive.split("=", 1)[0].strip(),)
    # parameter names only — no regex metacharacters. Case-insensitive as samba
    # is, through sed_ci: BusyBox sed refuses GNU's ``/regex/I`` (v0.24.1).
    alts = "|".join(sed_ci(p) for p in params)
    delete = (f"sudo sed -i -E '/^[[:space:]]*({alts})[[:space:]]*=/d' "
              f"{_SMB_CONF_PATH}")
    insert = f"sudo sed -i '/^\\[global\\]/a {directive}' {_SMB_CONF_PATH}"
    return f"{delete} && {insert}"


# SMBv1 protocol identifiers (any of these → ALERT)
# smb.conf uses "NT1" as the canonical name; "smb1" is a defensive alias
# present in some distributions / Samba forks.
_SMB1_PROTOCOLS: frozenset[str] = frozenset({
    "core", "coreplus", "lanman1", "lanman2", "nt1", "smb1",
})

# Sections that are not file-share definitions
_META_SECTIONS: frozenset[str] = frozenset({
    "global", "homes", "printers", "print$", "ipc$",
})

# ---------------------------------------------------------------------------
# Sub-dataclass
# ---------------------------------------------------------------------------

@dataclass
class GuestShare:
    """A share that allows guest / anonymous access."""
    name:     str
    path:     str  = ""
    writable: bool = False

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class SambaSnapshot:
    """
    Raw snapshot of Samba configuration state.

    All file I/O and subprocess calls happen in from_system().
    check_samba() operates on this snapshot only (pure logic).
    """
    installed:            bool = False
    daemon_installed:     bool = False
    conf_readable:        bool = False

    # [global] settings
    smb1_enabled:         bool = False
    null_passwords:       bool = False
    server_signing:       str  = ""    # "disabled" | "auto" | "mandatory" | ""
    map_to_guest:         str  = ""    # "bad user" | "never" | "bad password" | ""
    bind_interfaces_only: bool = False

    # share-level findings
    guest_shares:         list[GuestShare] = field(default_factory=list)
    #: v0.29.0 — lines samba refuses: a yes/no or fixed-choice parameter BOB
    #: weighs, whose value carries "#" or ";" (see _CHOICE_PARAMS).
    conf_refused:         list[str] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "SambaSnapshot":
        snap = cls()

        # --- detect installation ---
        snap.daemon_installed = _command_exists("smbd") or _command_exists("samba")
        snap.installed = snap.daemon_installed or path_exists(_SMB_CONF_PATH)
        if not snap.installed:
            return snap

        # --- parse smb.conf ---
        if not path_exists(_SMB_CONF_PATH):
            return snap

        try:
            conf = _read_smb_conf(_SMB_CONF_PATH, refused=snap.conf_refused)
        except OSError:
            return snap

        snap.conf_readable = True

        # --- [global] settings ---
        glb = conf.get("global", {})

        # SMB protocol version.
        #
        # `server min protocol` is the current name and `min protocol` the
        # deprecated synonym; a modern smb.conf writes the former. Reading only
        # the short form answered "SMB1 disabled" for a host that had
        # explicitly enabled it — verified against `testparm`, which resolves
        # both spellings to the same effective protocol. The `client`-side
        # parameters are deliberately not consulted: they govern what this host
        # will speak *to* a server, not what it accepts as one.
        min_proto = _section_get(glb, "server min protocol", "min protocol").lower()
        max_proto = _section_get(glb, "server max protocol", "max protocol").lower()
        # SMB1 if max_protocol is an SMB1 value, or if min_protocol is SMB1
        # and max_protocol is not set (defaults to NT1 on many systems)
        if max_proto in _SMB1_PROTOCOLS:
            snap.smb1_enabled = True
        elif min_proto in _SMB1_PROTOCOLS and max_proto == "":
            snap.smb1_enabled = True

        # Null passwords
        snap.null_passwords = _is_yes(glb, "null passwords")

        # Server signing
        # Samba 4.x: yes/true/required/mandatory → signing enforced
        #            auto/default/""             → negotiated (not enforced)
        #            no/false/disabled/0         → signing off
        signing_raw = _section_get(glb, "server signing").lower()
        if signing_raw in ("disabled", "false", "no", "0"):
            snap.server_signing = "disabled"
        elif signing_raw in ("mandatory", "required", "yes", "true"):
            snap.server_signing = "mandatory"
        elif signing_raw in ("auto", "default"):
            snap.server_signing = "auto"
        else:
            snap.server_signing = ""  # not set — treated as auto by Samba

        # map to guest
        map_guest_raw = _section_get(glb, "map to guest").lower()
        if map_guest_raw in ("bad user", "bad_user"):
            snap.map_to_guest = "bad user"
        elif map_guest_raw in ("bad password", "bad_password"):
            snap.map_to_guest = "bad password"
        elif map_guest_raw in ("never", ""):
            snap.map_to_guest = "never" if map_guest_raw == "never" else ""
        else:
            snap.map_to_guest = map_guest_raw

        # bind interfaces only
        snap.bind_interfaces_only = _is_yes(glb, "bind interfaces only")

        # --- share sections ---
        for section_name, opts in conf.items():
            if section_name.lower() in _META_SECTIONS:
                continue
            # guest ok = yes  OR  public = yes
            is_guest = _is_yes(opts, "guest ok") or _is_yes(opts, "public")
            if not is_guest:
                continue
            # v0.15.4: ``writeable`` was missing from this set. samba accepts
            # both spellings — testparm resolves ``writeable = yes`` to
            # ``read only = No``, exactly like ``writable`` — so a world-writable
            # guest share written with the "e" was reported as read-only:
            # samba.guest_readonly (WARN, 1 point) instead of
            # samba.guest_writable (ALERT, 2 points).
            writable = (
                _is_yes(opts, "writable")
                or _is_yes(opts, "writeable")
                or _is_yes(opts, "write ok")
                or _section_get(opts, "read only").lower() in ("no", "false", "0")
            )
            share = GuestShare(
                name=section_name,
                # ``directory`` is samba's synonym for ``path`` (testparm
                # resolves it to ``path``); reading only the latter left the
                # finding naming an empty directory.
                path=_section_get(opts, "path", "directory"),
                writable=writable,
            )
            snap.guest_shares.append(share)

        return snap

# ---------------------------------------------------------------------------
# Main check function (pure logic — no I/O)
# ---------------------------------------------------------------------------

def check_samba(snapshot: SambaSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check Samba server security configuration.

    Args:
        snapshot: SambaSnapshot collected from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- Samba not installed ---
    if not snapshot.installed:
        return result  # silent — section skipped entirely

    # --- config found but no Samba daemon ---
    if snapshot.installed and not snapshot.daemon_installed:
        result.info(
            message=_t("samba.conf_only"),
            key="samba.conf_only",
        )

    # --- conf not readable ---
    if not snapshot.conf_readable:
        result.info(
            message=_t("samba.conf_unreadable"),
            detail=_t("samba.conf_unreadable_detail"),
            key="samba.conf_unreadable",
        )
        return result

    # --- v0.29.0: a file samba refuses to load ---
    # What follows weighs the file as written; samba does not run it, and
    # what a running smbd uses instead is not established (a ceiling).
    if snapshot.conf_refused:
        lines = "; ".join(snapshot.conf_refused[:3]) + (" …" if len(snapshot.conf_refused) > 3 else "")
        result.info(
            message=_t("samba.conf_refused", lines=lines),
            detail=_t("samba.conf_refused_detail"),
            key="samba.conf_refused",
            template_vars={"lines": lines},
        )

    # --- SMB1 (critical — EternalBlue/WannaCry vector) ---
    if snapshot.smb1_enabled:
        result.alert_with_deduction(
            key="samba.smb1_enabled",
            message=_t("samba.smb1_enabled"),
            points=2,
            nature="improvement",
            detail=_t("samba.smb1_enabled_detail"),
            cmd=_global_directive_cmd("min protocol = SMB2", "min protocol", "server min protocol"),
        )
    else:
        result.ok(message=_t("samba.smb1_disabled"), key="samba.smb1_disabled")

    # --- Null passwords ---
    if snapshot.null_passwords:
        result.alert_with_deduction(
            key="samba.null_passwords",
            message=_t("samba.null_passwords"),
            points=3,
            nature="improvement",
            detail=_t("samba.null_passwords_detail"),
        )
    else:
        result.ok(message=_t("samba.null_passwords_ok"), key="samba.null_passwords_ok")

    # --- Server signing ---
    if snapshot.server_signing == "disabled":
        result.warn_with_deduction(
            key="samba.server_signing_disabled",
            message=_t("samba.server_signing_disabled"),
            points=1,
            detail=_t("samba.server_signing_disabled_detail"),
            cmd=_global_directive_cmd("server signing = mandatory", "server signing"),
            nature="action",
        )
    elif snapshot.server_signing == "mandatory":
        result.ok(
            message=_t("samba.server_signing_mandatory"),
            key="samba.server_signing_mandatory",
        )
    else:
        result.info(
            message=_t("samba.server_signing_auto"),
            detail=_t("samba.server_signing_auto_detail"),
            key="samba.server_signing_auto",
        )

    # --- map to guest ---
    if snapshot.map_to_guest == "bad user":
        result.warn_with_deduction(
            key="samba.map_to_guest",
            message=_t("samba.map_to_guest"),
            points=1,
            detail=_t("samba.map_to_guest_detail"),
            cmd=_global_directive_cmd("map to guest = never", "map to guest"),
            nature="action",
        )

    # --- Guest shares ---
    writable_guest = [s for s in snapshot.guest_shares if s.writable]
    readonly_guest = [s for s in snapshot.guest_shares if not s.writable]

    for share in writable_guest:
        result.alert_with_deduction(
            key="samba.guest_writable",
            message=_t("samba.guest_writable", share=share.name),
            points=2,
            nature="improvement",
            detail=_t("samba.guest_writable_detail", share=share.name, path=share.path),
        )

    for share in readonly_guest:
        result.warn_with_deduction(
            key="samba.guest_readonly",
            message=_t("samba.guest_readonly", share=share.name),
            points=1,
            detail=_t("samba.guest_readonly_detail", share=share.name, path=share.path),
            nature="improvement",
        )

    # --- Bind interfaces only ---
    if not snapshot.bind_interfaces_only:
        result.info(
            message=_t("samba.bind_interfaces_not_set"),
            detail=_t("samba.bind_interfaces_not_set_detail"),
            key="samba.bind_interfaces_not_set",
        )

    return result

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _Params(dict):
    """A section's parameters, looked up as samba matches names (v0.28.0):
    case and whitespace in a parameter name do not matter (smb.conf(5):
    "internal whitespace in section and parameter names is irrelevant"). An
    underscore does: measured with testparm 4.22.11, `serverminprotocol = NT1`
    read NT1 and `server_min_protocol = NT1` was ignored (SMB2_02, the
    default) — reading it as NT1 would claim an SMB1 samba does not run."""

    @staticmethod
    def _norm(key: object) -> object:
        return re.sub(r"\s+", "", key).lower() if isinstance(key, str) else key

    def __setitem__(self, key, value):
        super().__setitem__(self._norm(key), value)

    def __getitem__(self, key):
        return super().__getitem__(self._norm(key))

    def __contains__(self, key):
        return super().__contains__(self._norm(key))

    def get(self, key, default=None):
        return super().get(self._norm(key), default)


#: v0.29.0 — the yes/no and fixed-choice parameters BOB weighs, normalised.
#: Measured on Debian 13 (samba 4.22.11): with "# …" or "; …" after the value
#: (even `mandatory#x`), each made testparm answer "Error loading services"
#: (exit 1) and smbd stop with "Failed to load config file!"; `path`,
#: `server string` and `restrict anonymous` with the same tail loaded.
_CHOICE_PARAMS = frozenset(re.sub(r"\s+", "", k) for k in (
    "server min protocol", "min protocol", "server max protocol", "max protocol", "server signing",
    "map to guest", "null passwords", "bind interfaces only", "guest ok", "public", "writable",
    "writeable", "write ok", "read only"))


def _read_smb_conf(path: Path, refused: "list[str] | None" = None) -> dict[str, dict[str, str]]:
    """
    Parse a smb.conf file and return {section: {parameter: value}}, as samba's
    own parser reads it (v0.28.0).

    Until 0.27.0 this was configparser, and it diverged from ``testparm``
    (measured on Debian 13, samba 4.22.11): a line indented deeper than the one
    before was read as that line's continuation, so ``server min protocol =
    NT1`` vanished; a ``\\`` continuation raised a parsing error; ``Server  Min
    Protocol`` (internal spaces) was not recognised — testparm read NT1 every
    time, BOB read nothing. samba's rules: a trailing backslash joins the next
    line; leading whitespace means nothing; a line starting with ``#`` or ``;``
    is a comment (no inline comments); only the first ``=`` counts; the value's
    leading and trailing whitespace is dropped; a repeated parameter keeps its
    last value and a repeated section merges.

    The bytes are read with ``read_text_capped`` (a FIFO or an oversized file is
    refused, v0.20.1) and an unreadable file raises OSError for the caller —
    never an empty config (v0.15.x).
    """
    text = read_text_capped(path, encoding="utf-8")
    result: dict[str, dict[str, str]] = {}
    state: "dict[str, dict[str, str] | None]" = {"current": None}

    def feed(text: str, seen: frozenset) -> None:
        pending = ""
        for raw in text.splitlines():
            line = pending + raw
            if line.endswith("\\"):
                pending = line[:-1]
                continue
            pending = ""
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("["):
                name = " ".join(line[1:].split("]", 1)[0].split()).lower()
                state["current"] = result.setdefault(name, _Params())
                continue
            current = state["current"]
            if current is None or "=" not in line:
                continue
            key, _eq, value = line.partition("=")
            if not key.strip():
                continue
            value = value.strip()
            if _Params._norm(key) == "include":
                # v0.28.0 — measured with testparm: the included file is read
                # in place (its unsectioned parameters join the current
                # section, its sections are created, the file goes on after
                # it); a missing one is skipped. A %-substituted path names a
                # file per client: no single file to follow.
                if "%" in value or not value or value in seen or len(seen) > 16:
                    continue
                try:
                    included = read_text_capped(Path(value), encoding="utf-8")
                except FileNotFoundError:
                    continue
                feed(included, seen | {value})
                continue
            current[key.strip()] = value
            if refused is not None and _Params._norm(key) in _CHOICE_PARAMS and ("#" in value or ";" in value):
                refused.append(f"{key.strip()} = {value}")

    feed(text, frozenset({str(path)}))
    return result


def _section_get(opts: dict[str, str], *keys: str) -> str:
    """Return the first present option among *keys*, or ''.

    Several parameters carry more than one spelling. Samba renamed
    ``min protocol`` to ``server min protocol`` and kept the short form as a
    deprecated synonym, so a current smb.conf uses the long one — and reading
    only the short one meant a host explicitly configured to accept SMB1 was
    reported as having it disabled. The order given is the order tried.
    """
    for key in keys:
        value = opts.get(key.strip().lower(), "").strip()
        if value:
            return value
    return ""

def _is_yes(opts: dict[str, str], key: str) -> bool:
    """Return True if opts[key] is a truthy Samba value (yes/true/1)."""
    return _section_get(opts, key).lower() in ("yes", "true", "1")
