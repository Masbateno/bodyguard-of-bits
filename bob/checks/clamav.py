"""
ClamAV antivirus audit check for BOB.

Analyses:
  - ClamAV installation (clamscan / clamdscan)
  - Virus database freshness (daily.cld / daily.cvd mtime)
  - ClamAV daemon status (clamav-daemon / clamd)
  - Last scan date (parsed from standard log paths)

Score impact: deductions route to the "hardening" domain.

Usage:
    from bob.checks.clamav import ClamAVSnapshot, check_clamav

    snapshot = ClamAVSnapshot.from_system()
    result   = check_clamav(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Virus database files — checked in order of preference (daily > main)
_DB_CANDIDATES: list[Path] = [
    Path("/var/lib/clamav/daily.cld"),
    Path("/var/lib/clamav/daily.cvd"),
    Path("/var/lib/clamav/main.cld"),
    Path("/var/lib/clamav/main.cvd"),
]

# Standard log file paths where scan summaries may be written
_SCAN_LOG_CANDIDATES: list[Path] = [
    Path("/var/log/clamav/clamdscan.log"),
    Path("/var/log/clamav/clamscan.log"),
    Path("/var/log/clamav/scan.log"),
    Path("/var/log/clamav/clamav.log"),
]

# "End Date:   2026:04:10 15:30:06"  or  "End Date: 2026:04:10 15:30:06"
_END_DATE_RE = re.compile(
    r"(?i)End Date:\s+(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})"
)

# Database age thresholds (days)
_DB_WARN_DAYS:  int = 7
_DB_ALERT_DAYS: int = 30

# Scan age threshold (days)
_SCAN_WARN_DAYS:  int = 30
_SCAN_ALERT_DAYS: int = 90

# Lines to read from the end of each log file (performance guard)
_LOG_TAIL_LINES: int = 500

# Unix socket paths created by clamd when running (used as fallback when
# systemctl is unavailable, e.g. inside containers)
_CLAMD_SOCKETS: list[Path] = [
    Path("/run/clamav/clamd.ctl"),
    Path("/var/run/clamav/clamd.ctl"),
]


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class ClamAVSnapshot:
    """
    Raw snapshot of ClamAV installation and runtime state.

    All file I/O and subprocess calls happen in from_system().
    check_clamav() operates on this snapshot only (pure logic).
    """
    installed:            bool           = False  # clamscan or clamdscan found
    freshclam_installed:  bool           = False  # freshclam found
    clamd_active:         bool           = False  # clamav-daemon service running
    db_age_days:          Optional[int]  = None   # None = no DB file found
    last_scan_date:       Optional[str]  = None   # ISO date string or None
    install_cmd:          str            = "sudo apt install clamav clamav-daemon"

    @classmethod
    def from_system(cls) -> "ClamAVSnapshot":
        snap = cls()

        # --- detect installation ---
        snap.installed = (
            _command_exists("clamscan")
            or _command_exists("clamdscan")
            or _command_exists("freshclam")
        )
        snap.freshclam_installed = _command_exists("freshclam")

        if not snap.installed:
            return snap

        # --- clamd service status ---
        if _command_exists("systemctl"):
            for unit in ("clamav-daemon", "clamd", "clamd@scan"):
                out = (_run("systemctl", "is-active", unit) or "").strip()
                if out == "active":
                    snap.clamd_active = True
                    break
        # Fallback: check for the clamd Unix socket (present when daemon is running
        # even if systemctl is unavailable, e.g. inside containers).
        if not snap.clamd_active:
            for socket_path in _CLAMD_SOCKETS:
                if socket_path.exists():
                    snap.clamd_active = True
                    break

        # --- virus database freshness ---
        for db_path in _DB_CANDIDATES:
            if db_path.exists():
                try:
                    mtime_dt = datetime.fromtimestamp(
                        db_path.stat().st_mtime, tz=timezone.utc
                    )
                    snap.db_age_days = max(
                        0, (datetime.now(timezone.utc) - mtime_dt).days
                    )
                except OSError:
                    pass
                break

        # --- last scan date from logs ---
        snap.last_scan_date = _find_last_scan_date()

        return snap


# ---------------------------------------------------------------------------
# Main check function (pure logic — no I/O)
# ---------------------------------------------------------------------------

def check_clamav(snapshot: ClamAVSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check ClamAV antivirus installation and configuration.

    Args:
        snapshot: ClamAVSnapshot collected from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- Not installed ---
    if not snapshot.installed:
        result.info(
            message=_t("clamav.not_installed"),
            detail=_t("clamav.not_installed_detail"),
            cmd=snapshot.install_cmd,
            key="clamav.not_installed",
        )
        return result

    # --- Installed ---
    result.ok(message=_t("clamav.installed"), key="clamav.installed")

    # --- freshclam ---
    if not snapshot.freshclam_installed:
        result.warn(
            message=_t("clamav.freshclam_missing"),
            detail=_t("clamav.freshclam_missing_detail"),
            nature="improvement",
            cmd="sudo apt install clamav",
            key="clamav.freshclam_missing",
        )
        result.add_deduction(
            reason=_t("clamav.freshclam_missing"),
            points=1, context="local", key="clamav.freshclam_missing",
        )

    # --- Virus database ---
    if snapshot.db_age_days is None:
        result.warn(
            message=_t("clamav.db_not_found"),
            detail=_t("clamav.db_not_found_detail"),
            nature="improvement",
            cmd="sudo freshclam",
            key="clamav.db_not_found",
        )
        result.add_deduction(
            reason=_t("clamav.db_not_found"),
            points=1, context="local", key="clamav.db_not_found",
        )
    elif snapshot.db_age_days >= _DB_ALERT_DAYS:
        result.alert(
            message=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
            detail=_t("clamav.db_very_outdated_detail"),
            nature="improvement",
            cmd="sudo freshclam",
            key="clamav.db_very_outdated",
        )
        result.add_deduction(
            reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
            points=1, context="local", key="clamav.db_very_outdated",
        )
    elif snapshot.db_age_days >= _DB_WARN_DAYS:
        result.warn(
            message=_t("clamav.db_outdated", days=snapshot.db_age_days),
            detail=_t("clamav.db_outdated_detail"),
            nature="improvement",
            cmd="sudo freshclam",
            key="clamav.db_outdated",
        )
        result.add_deduction(
            reason=_t("clamav.db_outdated", days=snapshot.db_age_days),
            points=1, context="local", key="clamav.db_outdated",
        )
    else:
        result.ok(
            message=_t("clamav.db_ok", days=snapshot.db_age_days),
            key="clamav.db_ok",
        )

    # --- clamd daemon ---
    if not snapshot.clamd_active:
        result.info(
            message=_t("clamav.clamd_inactive"),
            detail=_t("clamav.clamd_inactive_detail"),
            cmd="sudo systemctl enable --now clamav-daemon",
            key="clamav.clamd_inactive",
        )

    # --- Last scan ---
    if snapshot.last_scan_date is None:
        result.info(
            message=_t("clamav.no_scan_log"),
            detail=_t("clamav.no_scan_log_detail"),
            cmd="sudo clamscan -r /home --infected --log=/var/log/clamav/clamscan.log",
            key="clamav.no_scan_log",
        )
    else:
        scan_age_days = _scan_age_days(snapshot.last_scan_date)
        if scan_age_days is not None and scan_age_days >= _SCAN_ALERT_DAYS:
            result.warn(
                message=_t("clamav.scan_very_old", days=scan_age_days, date=snapshot.last_scan_date),
                detail=_t("clamav.scan_very_old_detail"),
                nature="improvement",
                cmd="sudo clamscan -r /home --infected --log=/var/log/clamav/clamscan.log",
                key="clamav.scan_very_old",
            )
            result.add_deduction(
                reason=_t("clamav.scan_very_old", days=scan_age_days, date=snapshot.last_scan_date),
                points=1, context="local", key="clamav.scan_very_old",
            )
        elif scan_age_days is not None and scan_age_days >= _SCAN_WARN_DAYS:
            result.warn(
                message=_t("clamav.scan_old", days=scan_age_days, date=snapshot.last_scan_date),
                detail=_t("clamav.scan_old_detail"),
                nature="improvement",
                cmd="sudo clamscan -r /home --infected --log=/var/log/clamav/clamscan.log",
                key="clamav.scan_old",
            )
            result.add_deduction(
                reason=_t("clamav.scan_old", days=scan_age_days, date=snapshot.last_scan_date),
                points=1, context="local", key="clamav.scan_old",
            )
        else:
            result.ok(
                message=_t("clamav.scan_recent", date=snapshot.last_scan_date),
                key="clamav.scan_recent",
            )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_last_scan_date() -> Optional[str]:
    """
    Search standard ClamAV log paths for the most recent scan 'End Date:'.

    Returns:
        ISO date string (YYYY-MM-DD) of the most recent scan found across
        all candidate log paths, or None if no scan log line was found.
    """
    latest_dt: Optional[datetime] = None

    for log_path in _SCAN_LOG_CANDIDATES:
        if not log_path.exists():
            continue
        try:
            lines = _tail_lines(log_path, _LOG_TAIL_LINES)
        except OSError:
            continue

        for line in lines:
            m = _END_DATE_RE.search(line)
            if not m:
                continue
            try:
                # ClamAV logs timestamps in local time — keep naive for comparison.
                dt = datetime(
                    int(m.group(1)), int(m.group(2)), int(m.group(3)),
                    int(m.group(4)), int(m.group(5)), int(m.group(6)),
                )
            except ValueError:
                continue
            if latest_dt is None or dt > latest_dt:
                latest_dt = dt

    if latest_dt is None:
        return None
    return latest_dt.strftime("%Y-%m-%d")


def _tail_lines(path: Path, n: int) -> list[str]:
    """Return the last n lines of a text file efficiently."""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        if size == 0:
            return []
        # Read progressively larger chunks from the end
        chunk = min(size, n * 120)  # rough estimate: 120 chars/line
        fh.seek(max(0, size - chunk))
        data = fh.read()
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-n:]


def _scan_age_days(iso_date: str) -> Optional[int]:
    """Return the number of days since iso_date (YYYY-MM-DD), or None on error.

    Uses naive local time to match ClamAV log timestamps.
    """
    try:
        dt = datetime.strptime(iso_date, "%Y-%m-%d")
        return max(0, (datetime.now() - dt).days)
    except ValueError:
        return None
