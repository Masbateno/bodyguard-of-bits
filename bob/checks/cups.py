"""
CUPS printing service configuration check for BOB (CIS §2.2 / print services).

CUPS (`cupsd`) is installed by default on most desktops and many servers. Its
`/etc/cups/cupsd.conf` decides whether the print service is a localhost-only
convenience or a network-reachable daemon — and CUPS has a long CVE history
(the 2024 cups-browsed/`Browsing` remote-code-execution chain being the loudest
recent example). This check audits the *configuration*, complementing the
`ports` / `services` checks that see whether 631 is actually listening.

Two properties, both low-false-positive:

  1. **Listen address.** The shipped default is localhost-only
     (`Listen localhost:631` + the `/run/cups/cups.sock` domain socket). A
     `Listen 0.0.0.0:631`, `Listen <routable-ip>:631`, `Listen *:631` or a bare
     `Port 631` (which binds every interface) turns the print service into a
     network daemon. WARN.

  2. **Browsing.** `Browsing On` makes CUPS advertise/consume shared printers
     over the network (cups-browsed, UDP 631) — extra attack surface and the
     vector of the 2024 RCE chain. INFO (awareness; disabling it is the common
     hardening step but breaks auto-discovery some setups rely on).

Score impact:
  - CUPS / cupsd.conf not present:        INFO (n/a)
  - cupsd.conf present but unreadable:    INFO (illisible ≠ vide)
  - Listens on a non-loopback address:    WARN −1 pt
  - Localhost-only:                       OK
  - Browsing On:                          INFO (no deduction)

Split into:
  1. CupsSnapshot.from_system() — collects state from the live system.
  2. check_cups(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _command_exists,
    _identity_t,
    openrc_available,
    path_exists,
    read_text_capped,
    sed_ci,
    service_restart_cmd,
)
from bob.scoring import CheckResult

_CUPSD_CONF = "/etc/cups/cupsd.conf"

# `Listen <addr>[:port]` or `Port <n>`. Comments (#) are stripped first.
_LISTEN_RE = re.compile(r"^\s*Listen\s+(\S+)", re.IGNORECASE)
_PORT_RE = re.compile(r"^\s*Port\s+(\d+)", re.IGNORECASE)
_BROWSING_RE = re.compile(r"^\s*Browsing\s+(On|Yes|True)\b", re.IGNORECASE)


def _is_loopback_listen(value: str) -> bool:
    """True when a Listen value binds only the local host (or a domain socket)."""
    v = value.strip()
    if v.startswith("/"):
        return True  # UNIX domain socket — not a network exposure
    host = v
    # Strip the :port from host:port, and [::1]:port bracket form.
    if v.startswith("["):
        host = v[1:].split("]", 1)[0]
    elif ":" in v and v.count(":") == 1:
        host = v.rsplit(":", 1)[0]
    host = host.lower()
    return (
        host in ("localhost", "::1")
        or host.startswith("127.")
    )


@dataclass
class CupsSnapshot:
    """State collected about the CUPS print service configuration.

    Args:
        cfg_present:          True when /etc/cups/cupsd.conf exists.
        readable:            False when it exists but could not be read.
        listen_values:       Raw Listen/Port operands found (for the message).
        listens_non_loopback: True when at least one binds beyond localhost
                             (a routable Listen, `*`, `0.0.0.0`, or bare `Port`).
        browsing_on:         True when `Browsing On` is set.
    """
    cfg_present:          bool = False
    readable:             bool = True
    listen_values:        list[str] = field(default_factory=list)
    listens_non_loopback: bool = False
    browsing_on:          bool = False

    @classmethod
    def from_system(cls) -> "CupsSnapshot":
        """Detect CUPS config state from the live system. Never raises."""
        snap = cls()
        if not path_exists(Path(_CUPSD_CONF)):
            return snap
        snap.cfg_present = True
        try:
            text = read_text_capped(Path(_CUPSD_CONF), encoding="utf-8",
                                    errors="replace")
        except OSError:
            snap.readable = False
            return snap

        for raw in text.splitlines():
            line = raw.split("#", 1)[0]  # strip trailing comment
            m = _LISTEN_RE.match(line)
            if m:
                val = m.group(1)
                snap.listen_values.append(val)
                if not _is_loopback_listen(val):
                    snap.listens_non_loopback = True
                continue
            m = _PORT_RE.match(line)
            if m:
                # `Port N` binds every interface — a network exposure.
                snap.listen_values.append(f"Port {m.group(1)}")
                snap.listens_non_loopback = True
                continue
            if _BROWSING_RE.match(line):
                snap.browsing_on = True
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

#: What a Listen operand read from cupsd.conf may hold before BOB writes it into
#: a sed expression: host names, IPv4/IPv6 literals, ``*``, a port. Anything
#: else and no command is printed.
_SAFE_LISTEN = re.compile(r"^[A-Za-z0-9.:*\[\]-]+$")


def _listen_fix(values: "list[str]") -> "str | None":
    """Bind CUPS back to localhost: drop exactly the Listen/Port lines that
    expose it, keep a ``Listen localhost`` on each of their ports, restart.

    v0.25.0 — the command was ``cupsctl --no-remote-any``. Measured on
    Debian 13 and Fedora 43: with a hand-written ``Listen 0.0.0.0:631`` it
    exits 0 and changes nothing (cupsctl rewrites the file only when one of its
    settings changes); with every setting turned off it rewrites the file but
    cupsd keeps listening on 0.0.0.0 until restarted; on Alpine 3.22 root is not
    in CUPS's SystemGroup (lpadmin) and cupsctl answers "Forbidden". Editing the
    lines BOB read needs none of that.
    """
    exprs: "list[str]" = []
    ports: "list[str]" = []
    for v in values:
        if v.startswith("Port "):
            port = v.split()[1]
            exprs.append(f"/^[[:space:]]*{sed_ci('Port')}[[:space:]]+{port}([[:space:]]|#|$)/d")
        elif not _is_loopback_listen(v):
            if not _SAFE_LISTEN.match(v):
                return None
            port = v.rsplit(":", 1)[1] if ":" in v and not v.endswith("]") else "631"
            escaped = "".join(f"\\{c}" if c in ".*[]" else c for c in v)
            exprs.append(f"/^[[:space:]]*{sed_ci('Listen')}[[:space:]]+{escaped}([[:space:]]|#|$)/d")
        else:
            continue
        if not port.isdigit():
            return None
        if port not in ports:
            ports.append(port)
    if not exprs:
        return None
    edit = "sudo sed -i -E " + " ".join(f"-e '{e}'" for e in exprs) + f" {_CUPSD_CONF}"
    keep = " && ".join(
        f"{{ grep -qiE '^[[:space:]]*Listen[[:space:]]+localhost:{p}([[:space:]]|#|$)' {_CUPSD_CONF}"
        f" || echo 'Listen localhost:{p}' | sudo tee -a {_CUPSD_CONF} >/dev/null; }}" for p in ports)
    return f"{edit} && {keep} && {service_restart_cmd(_cups_unit())}"


def _cups_unit() -> str:
    """The CUPS service as this host's init system names it: ``cups`` under
    systemd, ``cupsd`` for OpenRC (measured on Alpine 3.22, which ships
    /etc/init.d/cupsd — v0.25.0: the fix said ``systemctl restart cups``)."""
    if openrc_available() and not _command_exists("systemctl") and path_exists(Path("/etc/init.d/cupsd")):
        return "cupsd"
    return "cups"


def check_cups(snapshot: CupsSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """Analyse CupsSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.cfg_present:
        result.info(
            message=_t("cups.not_present"),
            detail=_t("cups.not_present_detail"),
            key="cups.not_present",
        )
        return result

    if not snapshot.readable:
        result.info(
            message=_t("cups.cfg_unreadable"),
            detail=_t("cups.cfg_unreadable_detail"),
            key="cups.cfg_unreadable",
        )
        return result

    # --- Listen address ------------------------------------------------------
    if snapshot.listens_non_loopback:
        exposed = ", ".join(snapshot.listen_values) or "?"
        result.warn_with_deduction(
            key="cups.listen_exposed",
            message=_t("cups.listen_exposed", listen=exposed),
            reason=_t("cups.listen_exposed_reason"),
            points=1,
            detail=_t("cups.listen_exposed_detail"),
            cmd=_listen_fix(snapshot.listen_values),
            nature="action",
        )
    else:
        result.ok(
            message=_t("cups.listen_localhost"),
            key="cups.listen_localhost",
        )

    # --- Browsing ------------------------------------------------------------
    if snapshot.browsing_on:
        result.info(
            message=_t("cups.browsing_on"),
            detail=_t("cups.browsing_on_detail"),
            key="cups.browsing_on",
        )
    else:
        result.ok(
            message=_t("cups.browsing_off"),
            key="cups.browsing_off",
        )

    return result
