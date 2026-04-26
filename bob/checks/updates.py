"""
System update status audit for BOB.

Checks:
  - Security packages pending update (apt-get -s upgrade, -security sources)
  - Regular packages pending update (informational)
  - unattended-upgrades installation and configuration

Usage:
    from bob.checks.updates import UpdatesSnapshot, check_updates

    snapshot = UpdatesSnapshot.from_system()
    result   = check_updates(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from bob.checks._run import _command_exists, _identity_t, _run
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class UpdatesSnapshot:
    """
    Raw snapshot of system update state.

    All I/O happens in from_system(). check_updates() is pure logic.
    """
    apt_available:          bool = False
    pending_security:       List[str] = field(default_factory=list)
    pending_regular:        List[str] = field(default_factory=list)
    unattended_installed:   bool = False
    unattended_enabled:     bool = False

    @classmethod
    def from_system(cls) -> "UpdatesSnapshot":
        """
        Collect update state from the live system.

        Returns:
            Populated UpdatesSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        if not _command_exists("apt-get"):
            return snap

        snap.apt_available = True
        snap.pending_security, snap.pending_regular = _collect_pending_updates()
        snap.unattended_installed, snap.unattended_enabled = _check_unattended()

        return snap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_pending_updates() -> tuple[list[str], list[str]]:
    """
    Run ``apt-get -s upgrade`` and parse Inst lines.

    Returns:
        (security, regular) — lists of package names by update type.
        Security packages are identified by a ``-security`` suite in the
        apt source field (e.g. ``jammy-security``, ``debian-security``).
    """
    security: list[str] = []
    regular:  list[str] = []

    out = _run("apt-get", "-s", "upgrade", timeout=30)
    if not out:
        return security, regular

    for line in out.splitlines():
        if not line.startswith("Inst "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pkg = parts[1]
        if re.search(r"-security\b", line, re.IGNORECASE):
            security.append(pkg)
        else:
            regular.append(pkg)

    # Deduplicate while preserving order (apt can emit the same package twice)
    return list(dict.fromkeys(security)), list(dict.fromkeys(regular))


def _check_unattended() -> tuple[bool, bool]:
    """
    Return (installed, enabled) for unattended-upgrades.

    installed — package present according to dpkg-query
    enabled   — configured to actually run (apt periodic config or systemd timer)
    """
    # Step 1 — package installed?
    dpkg_out = _run("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
    if not dpkg_out or "install ok installed" not in dpkg_out:
        return False, False

    # Step 2 — configured to run upgrades automatically?
    apt_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if apt_conf.exists():
        try:
            content = apt_conf.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', content):
                return True, True
        except OSError:
            pass

    # Step 3 — fallback: systemd timer active
    timer_out = _run("systemctl", "is-active", "apt-daily-upgrade.timer")
    enabled = (timer_out or "").strip() == "active"
    return True, enabled


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_updates(
    snapshot: UpdatesSnapshot,
    *,
    t=None,
    profile_name: str = "server",
) -> CheckResult:
    """
    Check system update status.

    Scoring:
      - Security packages pending:           −2 pts (flat, regardless of count)
      - Unattended-upgrades not configured
        AND security packages pending
        AND profile is not workstation:      −1 pt additional (compound risk)
      - On workstation profile, unattended not configured: INFO only (no deduction)
      - Regular packages pending:            INFO only, no deduction
      - Unattended-upgrades not configured
        AND system up to date:               INFO only

    Args:
        snapshot:     UpdatesSnapshot from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        profile_name: Active audit profile name. "workstation" demotes the
                      unattended-upgrades compound risk to INFO.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    # Guard against None being passed instead of an empty list
    security = snapshot.pending_security or []
    regular  = snapshot.pending_regular or []

    # --- apt not available (non-Debian/Ubuntu system) -----------------------
    if not snapshot.apt_available:
        result.info(
            message=_t("updates.no_apt"),
            key="updates.no_apt",
        )
        return result

    # --- Security packages pending ------------------------------------------
    if security:
        count = len(security)
        pkgs  = ", ".join(security[:5])
        if count > 5:
            pkgs += f" (+{count - 5})"
        result.warn(
            message=_t("updates.security_pending", count=count, packages=pkgs),
            detail=_t("updates.security_pending_detail"),
            cmd="sudo apt-get upgrade",
            key="updates.security_pending",
        )
        result.add_deduction(
            reason=_t("updates.security_pending_reason", count=count),
            points=2,
            context="local",
            key="updates.security_pending",
        )

    # --- Regular packages pending -------------------------------------------
    if regular:
        result.info(
            message=_t("updates.regular_pending",
                       count=len(regular)),
            key="updates.regular_pending",
        )

    # --- unattended-upgrades ------------------------------------------------
    uu_ok = snapshot.unattended_installed and snapshot.unattended_enabled

    if not uu_ok:
        if security and profile_name not in ("workstation", "desktop"):
            # Compound risk: security gap + no automation (server/default only)
            result.warn(
                message=_t("updates.unattended_not_configured"),
                detail=_t("updates.unattended_not_configured_detail"),
                cmd="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
                key="updates.unattended_not_configured",
            )
            result.add_deduction(
                reason=_t("updates.unattended_not_configured_reason"),
                points=1,
                context="local",
                key="updates.unattended_not_configured",
            )
        else:
            # Workstation profile, or system up to date — informational only
            result.info(
                message=_t("updates.unattended_not_configured"),
                detail=_t("updates.unattended_not_configured_detail"),
                key="updates.unattended_not_configured",
            )

    # --- All clear ----------------------------------------------------------
    if not result.findings:
        result.ok(
            message=_t("updates.ok"),
            key="updates.ok",
        )

    return result
