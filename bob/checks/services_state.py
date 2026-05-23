"""
Systemd service state audit for BOB.

Checks for security-relevant services that are loaded but currently inactive
(stopped or failed). A crashed security service is a silent gap: the system
appears protected, but the protection is absent.

The check is split into two parts:
  1. ServicesStateSnapshot.from_system() — collects data via systemctl.
  2. check_services_state(snapshot)       — pure logic, returns a CheckResult.

Usage:
    from bob.checks.services_state import ServicesStateSnapshot, check_services_state

    snapshot = ServicesStateSnapshot.from_system()
    result   = check_services_state(snapshot)
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Security-relevant services to monitor
# ---------------------------------------------------------------------------

# Services whose unexpected inactivity is a direct security concern.
# Names must be lowercase — systemd unit names are case-sensitive and typically
# lowercase; from_system() normalises to lowercase before comparing.
SECURITY_SERVICES: frozenset[str] = frozenset({
    "ufw",
    "fail2ban",
    "apparmor",
    "auditd",
    "clamav-daemon",
    "clamav-freshclam",
    "ssh",
    "sshd",
    "crowdsec",
    "ossec",
})

# Maximum score deduction from this check (one point per inactive service).
_MAX_DEDUCTION: int = 3

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class ServicesStateSnapshot:
    """
    Raw snapshot of systemd service states relevant to security.

    Args:
        systemctl_available:   True if ``systemctl`` exists on this system.
        enabled_inactive:      List of security service names that are both
                               enabled (should auto-start) and currently
                               inactive or failed.
    """
    systemctl_available:  bool       = False
    enabled_inactive:     list[str]  = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "ServicesStateSnapshot":
        """
        Collect systemd service states from the live system.

        Uses ``systemctl list-units --type=service --all`` to enumerate all
        loaded services and their ACTIVE state.  ``--all`` is required to
        include inactive/failed units (omitted by default).

        Returns:
            Populated ServicesStateSnapshot. Never raises — errors reflected
            as defaults.
        """
        snap = cls()

        if not _command_exists("systemctl"):
            return snap

        snap.systemctl_available = True

        # Step 1: collect which security services are enabled (should auto-start).
        # Only enabled services being inactive represent a real security gap;
        # a disabled service being inactive is intentional and not a finding.
        enabled_services: set[str] = set()
        out_files = _run(
            "systemctl", "list-unit-files",
            "--type=service",
            "--no-pager",
            "--no-legend",
            timeout=15,
        )
        if out_files:
            for line in out_files.splitlines():
                parts = line.split()
                # Format: UNIT-FILE STATE [PRESET]
                if len(parts) < 2:
                    continue
                # Strip ".service" suffix AND the "@instance" part for
                # instantiated template units (e.g. "auditd@daily.service" → "auditd")
                unit_name = parts[0].removesuffix(".service").split("@", 1)[0].lower()
                # "enabled-runtime" covers transient enables (e.g. cloud-init)
                if parts[1] in ("enabled", "enabled-runtime"):
                    enabled_services.add(unit_name)

        # Step 2: find security services that are loaded but inactive/failed.
        out = _run(
            "systemctl", "list-units",
            "--type=service",
            "--all",          # include inactive/failed units, not just active ones
            "--no-pager",
            "--no-legend",
            timeout=15,
        )
        if not out:
            return snap

        enabled_inactive: list[str] = []
        seen: set[str] = set()

        for line in out.splitlines():
            parts = line.split()
            # Format: UNIT LOAD ACTIVE SUB [DESCRIPTION...]
            if len(parts) < 3:
                continue
            # Normalise to lowercase — systemd names are typically lowercase;
            # strip .service suffix AND "@instance" for templates so
            # "ssh.service" → "ssh" and "auditd@daily.service" → "auditd".
            unit_name = parts[0].removesuffix(".service").split("@", 1)[0].lower()
            active    = parts[2]  # active / inactive / failed / activating

            if unit_name not in SECURITY_SERVICES:
                continue
            if unit_name not in enabled_services:
                continue  # intentionally disabled — not a finding
            if active in ("inactive", "failed"):
                if unit_name not in seen:
                    enabled_inactive.append(unit_name)
                    seen.add(unit_name)

        snap.enabled_inactive = enabled_inactive
        return snap

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_services_state(snapshot: ServicesStateSnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit security-relevant systemd services for unexpected inactivity.

    Scoring:
      - Security service loaded but inactive/failed:  −1 pt per service
                                                      (capped at _MAX_DEDUCTION)
      - systemctl unavailable:                        INFO only, no deduction

    Args:
        snapshot: ServicesStateSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    if not snapshot.systemctl_available:
        result.info(
            message=_t("services_state.no_systemctl"),
            key="services_state.no_systemctl",
        )
        return result

    # Filter to known security services and deduplicate — defence in depth:
    # the check is responsible for its own filtering regardless of how the
    # snapshot was built.
    seen: set[str] = set()
    inactive: list[str] = []
    for svc in (snapshot.enabled_inactive or []):
        if svc in SECURITY_SERVICES and svc not in seen:
            inactive.append(svc)
            seen.add(svc)

    deducted = 0
    for svc in inactive:
        # M-11 (v0.5.5): cmd contained `&& sudo journalctl` chained via
        # shell operator. fixes._has_shell_ops rejected this under
        # --fix --apply, leaving the WARN unfixable. Drop the journalctl
        # diagnostic from the cmd (it's not part of the fix) and move
        # it to `note` for guidance.
        result.warn(
            message=_t("services_state.service_inactive", service=svc),
            detail=_t("services_state.service_inactive_detail", service=svc),
            cmd=f"sudo systemctl restart {shlex.quote(svc)}",
            note=f"sudo journalctl -u {shlex.quote(svc)} -n 50",
            nature="action",
            key="services_state.service_inactive",
        )
        if deducted < _MAX_DEDUCTION:
            result.add_deduction(
                reason=_t("services_state.service_inactive_reason", service=svc),
                points=1,
                context="local",
                key="services_state.service_inactive",
            )
            deducted += 1

    if not result.findings:
        result.ok(
            message=_t("services_state.ok"),
            key="services_state.ok",
        )

    return result
