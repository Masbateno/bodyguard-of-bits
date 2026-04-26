"""
Fail2ban audit check for BOB (CHECK 29).

Checks whether fail2ban is installed, its service is running, and at least
one jail is active.  An SSH-specific jail is highlighted separately.

Score impact:
  - Not installed:            INFO  (optional but recommended)
  - Installed, service down:  WARN  −1 pt
  - Running but no jails:     WARN  −1 pt
  - Running with jails:       OK

Split into:
  1. Fail2banSnapshot.from_system() — collects state via fail2ban-client / systemctl.
  2. check_fail2ban(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from bob.checks._run import _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# Jail names that protect SSH (checked via substring match)
_SSH_JAIL_PATTERNS = ("sshd", "ssh")


@dataclass
class Fail2banSnapshot:
    """
    State collected from the system about fail2ban.

    Args:
        installed:       True if fail2ban-client is present.
        service_active:  True if the fail2ban service is running.
        active_jails:    List of active jail names reported by fail2ban-client.
        ssh_jail:        Name of the SSH jail if one is active, else "".
    """
    installed:      bool        = False
    service_active: bool        = False
    active_jails:   List[str]   = field(default_factory=list)
    ssh_jail:       str         = ""

    @classmethod
    def from_system(cls) -> "Fail2banSnapshot":
        """Collect fail2ban state from the live system. Never raises."""
        snap = cls()

        if not _command_exists("fail2ban-client"):
            return snap

        snap.installed = True

        # Service status via systemctl
        if _command_exists("systemctl"):
            out = (_run("systemctl", "is-active", "fail2ban") or "").strip()
            snap.service_active = out == "active"
        else:
            # Fallback: try fail2ban-client ping (exit 0 when running)
            ping = _run("fail2ban-client", "ping") or ""
            snap.service_active = "pong" in ping.lower()

        if not snap.service_active:
            return snap

        # Active jails
        status_out = _run("fail2ban-client", "status") or ""
        snap.active_jails = _parse_jails(status_out)

        # Detect SSH jail
        snap.ssh_jail = next(
            (jail for jail in snap.active_jails
             if any(pat in jail.lower() for pat in _SSH_JAIL_PATTERNS)),
            "",
        )

        return snap


def _parse_jails(status_output: str) -> List[str]:
    """
    Parse jail names from ``fail2ban-client status`` output.

    Expected format::

        Status
        |- Number of jail:      2
        `- Jail list:   sshd, nginx-http-auth

    Returns a list of jail names (stripped), or [] if parsing fails.
    """
    for line in status_output.splitlines():
        lower = line.lower()
        if "jail list" in lower and ":" in line:
            _, _, value = line.partition(":")
            jails = [j.strip() for j in value.split(",") if j.strip()]
            return jails
    return []


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_fail2ban(snapshot: Fail2banSnapshot, t=None) -> CheckResult:
    """
    Analyse Fail2ban snapshot and return findings.

    Findings:
      - Not installed:           INFO  (no deduction — optional tool)
      - Service not running:     WARN  −1 pt
      - No active jails:         WARN  −1 pt
      - Running with jails:      OK
      - SSH jail active:         OK (additional finding)
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.installed:
        result.info(
            message=_t("fail2ban.not_installed"),
            detail=_t("fail2ban.not_installed_detail"),
            cmd="sudo apt install fail2ban",
            key="fail2ban.not_installed",
        )
        return result

    if not snapshot.service_active:
        result.warn(
            message=_t("fail2ban.service_inactive"),
            detail=_t("fail2ban.service_inactive_detail"),
            cmd="sudo systemctl enable --now fail2ban",
            nature="improvement",
            key="fail2ban.service_inactive",
        )
        result.add_deduction(
            reason=_t("fail2ban.service_inactive_reason"),
            points=1,
            context="local",
            key="fail2ban.service_inactive",
        )
        return result

    if not snapshot.active_jails:
        result.warn(
            message=_t("fail2ban.no_jails"),
            detail=_t("fail2ban.no_jails_detail"),
            cmd="sudo fail2ban-client status",
            cmd_type="check",
            nature="improvement",
            key="fail2ban.no_jails",
        )
        result.add_deduction(
            reason=_t("fail2ban.no_jails_reason"),
            points=1,
            context="local",
            key="fail2ban.no_jails",
        )
        return result

    # Running with at least one jail
    jail_count = len(snapshot.active_jails)
    result.ok(
        message=_t("fail2ban.active", count=jail_count),
        key="fail2ban.active",
    )

    if snapshot.ssh_jail:
        result.ok(
            message=_t("fail2ban.ssh_jail_active", jail=snapshot.ssh_jail),
            key="fail2ban.ssh_jail_active",
        )

    return result
