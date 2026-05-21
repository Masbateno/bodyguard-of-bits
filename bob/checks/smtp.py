"""
SMTP local exposure check for BOB.

Detects whether a local MTA (Postfix, Exim, Sendmail) is listening on
all interfaces (0.0.0.0:25 or :::25) vs. localhost only (127.0.0.1:25).

Listening on all interfaces means port 25 is reachable from the network,
which is intentional only on a real public mail server — unintentional on
workstations and most internal servers.

Split into:
  1. SmtpSnapshot.from_system() — collects data via ss / netstat.
  2. check_smtp(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from bob.checks._run import TranslationFunc, _C_LOCALE_ENV, _identity_t
from bob.scoring import CheckResult

# MTA binary names (process detection)
_MTA_BINARIES = ("postfix", "master", "exim", "exim4", "sendmail", "nullmailer", "ssmtp")

# Loopback bind addresses — considered safe (local-only delivery)
# Does NOT include "*" — in ss output "*" means all interfaces (exposed)
_LOCAL_BIND_RE = re.compile(r"^(127\.|::1$|localhost$)")


@dataclass
class SmtpSnapshot:
    """
    State collected from the system about port-25 usage.

    Args:
        installed:    True if an MTA binary is found in the process list.
        mta_name:     Name of the detected MTA process ("postfix", "exim4", …).
        listening:    True if any process is listening on port 25.
        bind_address: The bind address found (e.g. "0.0.0.0", "127.0.0.1", "").
        exposed:      True when bind_address is NOT loopback/localhost.
    """
    installed:    bool = False
    mta_name:     str  = ""
    listening:    bool = False
    bind_address: str  = ""
    exposed:      bool = False

    @classmethod
    def from_system(cls) -> "SmtpSnapshot":
        """Collect SMTP exposure state from the live system. Never raises."""
        snap = cls()

        # Step 1 — detect installed MTA via process list
        try:
            ps_out = subprocess.check_output(
                ["ps", "-eo", "comm"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
                env=_C_LOCALE_ENV,
            )
            for line in ps_out.splitlines():
                proc = line.strip().lower()
                for mta in _MTA_BINARIES:
                    if proc == mta or proc.startswith(mta):
                        snap.installed = True
                        snap.mta_name  = mta if mta != "master" else "postfix"
                        break
                if snap.installed:
                    break
        except (OSError, subprocess.SubprocessError):
            pass

        # Step 2 — check if port 25 is listening and on which address
        snap.listening, snap.bind_address = _check_port_25()
        if snap.listening:
            snap.exposed = not _LOCAL_BIND_RE.match(snap.bind_address)

        return snap


def _check_port_25() -> tuple[bool, str]:
    """
    Return (listening, worst_bind_address) for port 25.

    Collects all bind addresses found for port 25 and returns the most
    exposed one — if any bind is non-local, that address is returned so
    that exposed=True is set correctly even when both 127.0.0.1:25 and
    0.0.0.0:25 are present simultaneously.

    Brackets are stripped from IPv6 addresses (e.g. [::1] → ::1).
    Tries ss first, falls back to netstat.
    Returns (False, "") if neither tool is available or port is not listening.
    """
    for cmd in (
        ["ss", "-tlnp"],
        ["netstat", "-tlnp"],
    ):
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True, timeout=10,
                env=_C_LOCALE_ENV,
            )
            binds: list[str] = []
            for line in out.splitlines():
                if ":25" not in line:
                    continue
                # Extract bind address from "address:port" column.
                # ss format:  LISTEN 0 100 0.0.0.0:25 ...
                # ss IPv6:    LISTEN 0 100 :::25 ...  or  [::]:25
                # netstat:    tcp 0 0 0.0.0.0:25 ...
                addr_match = re.search(r"(\S+):25\b", line)
                if addr_match:
                    host = addr_match.group(1).strip("[]")
                    binds.append(host)
            if not binds:
                return False, ""
            # Worst-case wins: return the first exposed address if any
            for b in binds:
                if not _LOCAL_BIND_RE.match(b):
                    return True, b
            return True, binds[0]
        except (OSError, subprocess.SubprocessError):
            continue
    return False, ""


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_smtp(snapshot: SmtpSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse SMTP snapshot and return findings.

    Findings:
      - Not installed: OK (no MTA)
      - Listening on localhost only: INFO (safe, local mail delivery)
      - Listening on all interfaces: WARN −1 pt (exposed to network)
      - Installed but not listening on port 25: INFO
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.installed:
        result.ok(
            message=_t("smtp.not_installed"),
            key="smtp.not_installed",
        )
        return result

    if not snapshot.listening:
        result.info(
            message=_t("smtp.installed_not_listening", mta=snapshot.mta_name or "mta"),
            key="smtp.installed_not_listening",
        )
        return result

    if snapshot.exposed:
        mta = snapshot.mta_name or "mta"
        # Provide an actionable fix command only for Postfix (well-known one-liner).
        # For other MTAs the fix is MTA-specific and must be done manually.
        if mta in ("postfix", "master"):
            fix_cmd = "sudo postconf -e 'inet_interfaces = loopback-only'"
            fix_note = _t("smtp.exposed_restart_postfix")
        else:
            fix_cmd = ""
            fix_note = ""
        result.warn(
            message=_t("smtp.exposed", mta=mta, bind=snapshot.bind_address),
            detail=_t("smtp.exposed_detail"),
            cmd=fix_cmd,
            note=fix_note,
            nature="improvement",
            key="smtp.exposed",
        )
        result.add_deduction(
            reason=_t("smtp.exposed_reason", bind=snapshot.bind_address),
            points=1,
            context="public",
            key="smtp.exposed",
        )
    else:
        result.info(
            message=_t(
                "smtp.local_only",
                mta=snapshot.mta_name or "mta",
                bind=snapshot.bind_address,
            ),
            key="smtp.local_only",
        )

    return result
