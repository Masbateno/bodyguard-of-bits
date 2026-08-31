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

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run, unit_active_state
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
        status_readable: False when fail2ban-client could not be queried.
    """
    installed:      bool        = False
    service_active: bool        = False
    active_jails:   list[str]   = field(default_factory=list)
    ssh_jail:       str         = ""
    # False when `fail2ban-client status` returned no jail list at all.
    status_readable: bool      = True

    @classmethod
    def from_system(cls) -> "Fail2banSnapshot":
        """Collect fail2ban state from the live system. Never raises."""
        snap = cls()

        if not _command_exists("fail2ban-client"):
            return snap

        snap.installed = True

        # Service status via systemctl, falling back to fail2ban's own answer
        # whenever systemd gives none — a present but failing systemctl used to
        # short-circuit straight to "inactive", warning that a running
        # fail2ban was down.
        state = unit_active_state("fail2ban") if _command_exists("systemctl") else None
        if state is not None:
            snap.service_active = state == "active"
        else:
            # Fallback: try fail2ban-client ping (exit 0 when running)
            ping = _run("fail2ban-client", "ping") or ""
            snap.service_active = "pong" in ping.lower()

        if not snap.service_active:
            return snap

        # Active jails.
        #
        # A successful `fail2ban-client status` always carries a "Jail list:"
        # line, even when the list is empty. Output without it means the query
        # failed — refused, timed out, or the socket was not ready — which is
        # not the same statement as "this host runs fail2ban with no jails",
        # and used to cost it a point all the same.
        status_out = _run("fail2ban-client", "status") or ""
        snap.status_readable = any(
            "jail list" in line.lower() for line in status_out.splitlines()
        )
        snap.active_jails = _parse_jails(status_out)

        # Detect SSH jail
        snap.ssh_jail = next(
            (jail for jail in snap.active_jails
             if any(pat in jail.lower() for pat in _SSH_JAIL_PATTERNS)),
            "",
        )

        return snap

def _parse_jails(status_output: str) -> list[str]:
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

def check_fail2ban(snapshot: Fail2banSnapshot, t: TranslationFunc | None = None) -> CheckResult:
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
        result.warn_with_deduction(
            key="fail2ban.service_inactive",
            message=_t("fail2ban.service_inactive"),
            reason=_t("fail2ban.service_inactive_reason"),
            points=1,
            detail=_t("fail2ban.service_inactive_detail"),
            cmd="sudo systemctl enable --now fail2ban",
            nature="action",
        )
        return result

    if not snapshot.status_readable:
        # No jail list came back at all: the query failed. That is not the same
        # statement as "fail2ban is running with no jails", and it used to carry
        # the same warning and the same deduction.
        result.info(
            message=_t("fail2ban.status_unreadable"),
            detail=_t("fail2ban.status_unreadable_detail"),
            key="fail2ban.status_unreadable",
        )
        return result

    if not snapshot.active_jails:
        result.warn_with_deduction(
            key="fail2ban.no_jails",
            message=_t("fail2ban.no_jails"),
            reason=_t("fail2ban.no_jails_reason"),
            points=1,
            detail=_t("fail2ban.no_jails_detail"),
            cmd="sudo fail2ban-client status",
            cmd_type="check",
            nature="action",
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
