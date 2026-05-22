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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from bob.checks._run import _command_exists, _identity_t, _run, is_unit_active
from bob.scoring import CheckResult


# Age threshold (in seconds) above which the APT cache is considered stale.
# 7 days mirrors the typical unattended-upgrades refresh window; beyond this
# the cache will under-report upgrades available upstream.
_APT_CACHE_STALE_THRESHOLD = 7 * 86400  # 7 days

# pkgcache.bin is the binary APT cache; its mtime tracks the last successful
# `apt-get update`. /var/lib/apt/lists/ holds the InRelease files we could
# also stat, but pkgcache.bin is simpler and equally reliable in practice.
_APT_CACHE_FILE = Path("/var/cache/apt/pkgcache.bin")


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class UpdatesSnapshot:
    """
    Raw snapshot of system update state.

    All I/O happens in from_system(). check_updates() is pure logic.

    Fields:
        apt_available:        ``apt-get`` is on $PATH.
        pending_security:     Package names with a ``-security`` source suite.
        pending_regular:      Package names from other sources.
        unattended_installed: ``unattended-upgrades`` package present.
        unattended_enabled:   ``unattended-upgrades`` actually configured to run.
        apt_cache_age_days:   ``None`` if pkgcache.bin not found; otherwise
                              number of full days since the cache was refreshed.
        upgradable_count:     ``apt list --upgradable`` count (cross-check
                              against the simulated dist-upgrade). ``None`` if
                              the command isn't available or failed.
    """
    apt_available:          bool = False
    pending_security:       List[str] = field(default_factory=list)
    pending_regular:        List[str] = field(default_factory=list)
    unattended_installed:   bool = False
    unattended_enabled:     bool = False
    apt_cache_age_days:     int | None = None
    upgradable_count:       int | None = None

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
        snap.apt_cache_age_days = _apt_cache_age_days()
        snap.upgradable_count = _count_upgradable()

        return snap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_pending_updates() -> tuple[list[str], list[str]]:
    """
    Run ``apt-get -s dist-upgrade`` and parse Inst lines.

    Uses ``dist-upgrade`` (not ``upgrade``) because plain ``upgrade`` is
    conservative — it refuses to upgrade any package that would require
    installing a new package or removing an existing one. On Debian/Ubuntu
    this hides every security update bundled with a kernel transition or a
    new soname (e.g. ``linux-image-amd64 → linux-image-6.12.86-amd64``).

    Returns:
        (security, regular) — lists of package names by update type.
        Security packages are identified by a ``-security`` suite in the
        apt source field (e.g. ``jammy-security``, ``debian-security``).
    """
    security: list[str] = []
    regular:  list[str] = []

    out = _run("apt-get", "-s", "dist-upgrade", timeout=30)
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


def _apt_cache_age_days() -> int | None:
    """Return age of the APT cache in days, or ``None`` if it cannot be read.

    Reading /var/cache/apt/pkgcache.bin requires no privileges. We use mtime
    because it reflects the last successful ``apt-get update``.
    """
    try:
        mtime = _APT_CACHE_FILE.stat().st_mtime
    except OSError:
        return None
    age_seconds = time.time() - mtime
    if age_seconds < 0:
        return 0
    return int(age_seconds // 86400)


def _count_upgradable() -> int | None:
    """Return the count from ``apt list --upgradable``, or ``None`` on failure.

    Cross-check against the simulated dist-upgrade — if dist-upgrade reports 0
    pending while apt-list reports N > 0, the cache may be stale or a
    transitional state is in play and the user deserves a warning.

    Format::

        Listing... Done
        pkg/suite 1.1 amd64 [upgradable from: 1.0]
        ...
    """
    # apt list defaults to a coloured pager-aware output on TTY; force a
    # terminal-friendly mode with 2>/dev/null on the warning line apt emits
    # via stderr ("WARNING: apt does not have a stable CLI interface...").
    out = _run("apt", "list", "--upgradable", timeout=20)
    if not out:
        return None
    count = 0
    for line in out.splitlines():
        # Skip header / blank / WARNING lines.
        if "/" in line and "[upgradable from" in line:
            count += 1
    return count


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
    enabled = is_unit_active("apt-daily-upgrade.timer")
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

    # --- APT cache stale ----------------------------------------------------
    # Without a fresh cache, dist-upgrade simulation reports stale data.
    # We warn the user before reporting "0 pending" to avoid false reassurance.
    cache_age = snapshot.apt_cache_age_days
    if cache_age is not None and cache_age * 86400 >= _APT_CACHE_STALE_THRESHOLD:
        result.warn(
            message=_t("updates.apt_cache_stale", days=cache_age),
            detail=_t("updates.apt_cache_stale_detail"),
            cmd="sudo apt update",
            key="updates.apt_cache_stale",
        )

    # --- Cross-check dist-upgrade vs apt list --upgradable ------------------
    # If apt list reports upgradable packages while dist-upgrade returned
    # zero, the simulation likely failed silently (locked, broken state, etc.).
    # The cache_stale warning above already covers the stale-cache case.
    if (
        snapshot.upgradable_count is not None
        and snapshot.upgradable_count > 0
        and not security
        and not regular
    ):
        result.warn(
            message=_t(
                "updates.dist_upgrade_inconsistent",
                count=snapshot.upgradable_count,
            ),
            detail=_t("updates.dist_upgrade_inconsistent_detail"),
            cmd="sudo apt update && sudo apt list --upgradable",
            key="updates.dist_upgrade_inconsistent",
        )

    # --- Security packages pending ------------------------------------------
    if security:
        count = len(security)
        pkgs  = ", ".join(security[:5])
        if count > 5:
            pkgs += f" (+{count - 5})"
        result.warn_with_deduction(
            key="updates.security_pending",
            message=_t("updates.security_pending", count=count, packages=pkgs),
            reason=_t("updates.security_pending_reason", count=count),
            points=2,
            detail=_t("updates.security_pending_detail"),
            cmd="sudo apt-get upgrade",
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
            result.warn_with_deduction(
                key="updates.unattended_not_configured",
                message=_t("updates.unattended_not_configured"),
                reason=_t("updates.unattended_not_configured_reason"),
                points=1,
                detail=_t("updates.unattended_not_configured_detail"),
                cmd="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
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
