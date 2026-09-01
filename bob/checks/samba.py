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

import configparser
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, path_exists
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SMB_CONF_PATH = Path("/etc/samba/smb.conf")

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
            conf = _read_smb_conf(_SMB_CONF_PATH)
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
            # writable = yes  OR  write ok = yes  OR  read only = no
            writable = (
                _is_yes(opts, "writable")
                or _is_yes(opts, "write ok")
                or _section_get(opts, "read only").lower() in ("no", "false", "0")
            )
            share = GuestShare(
                name=section_name,
                path=_section_get(opts, "path"),
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

    # --- SMB1 (critical — EternalBlue/WannaCry vector) ---
    if snapshot.smb1_enabled:
        result.alert_with_deduction(
            key="samba.smb1_enabled",
            message=_t("samba.smb1_enabled"),
            points=2,
            nature="improvement",
            detail=_t("samba.smb1_enabled_detail"),
            cmd='echo "min protocol = SMB2" | sudo tee -a /etc/samba/smb.conf',
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
            cmd='echo "server signing = mandatory" | sudo tee -a /etc/samba/smb.conf',
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
            cmd='echo "map to guest = never" | sudo tee -a /etc/samba/smb.conf',
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

def _read_smb_conf(path: Path) -> dict[str, dict[str, str]]:
    """
    Parse a smb.conf file and return a dict of {section: {key: value}}.

    Uses configparser with Samba-specific settings:
    - Comment prefixes: # and ;
    - Delimiter: = only (Samba uses spaces in key names like "min protocol")
    - optionxform normalises keys to lowercase and strips whitespace
    """
    parser = configparser.RawConfigParser(
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#", ";"),
        delimiters=("=",),
        strict=False,
    )
    # Preserve keys with spaces (e.g. "min protocol") by only lowercasing
    parser.optionxform = lambda opt: opt.strip().lower()  # type: ignore[assignment]

    # `RawConfigParser.read` takes a *list* of candidate files and silently
    # skips any it cannot open, returning only those it did read. That turned
    # an unreadable smb.conf into an empty config rather than an error, so the
    # caller's `except OSError` guard never fired and every setting fell back
    # to its default — the host was told SMB1 was disabled and null passwords
    # refused by a parser that had read nothing. Raise, so the guard works.
    if not parser.read(str(path), encoding="utf-8"):
        raise OSError(f"{path} could not be read")

    result: dict[str, dict[str, str]] = {}
    for section in parser.sections():
        opts: dict[str, str] = {}
        for key, val in parser.items(section):
            opts[key] = val.strip() if val else ""
        result[section.lower()] = opts

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
