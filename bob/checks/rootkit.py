"""
Rootkit and integrity audit check for BOB (CHECK 30).

Checks whether a rootkit scanner (rkhunter or chkrootkit) is installed,
whether its database is up to date, and when the last scan was run.

Score impact:
  - Neither installed:         INFO  (no deduction — optional tool)
  - Installed, db outdated:    WARN  −1 pt  (rkhunter only)
  - Installed, no recent scan: WARN  −1 pt
  - Installed, recent scan:    OK

Split into:
  1. RootkitSnapshot.from_system() — collects state via file inspection.
  2. check_rootkit(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t
from bob.scoring import CheckResult

# Age thresholds (days)
_DB_WARN_DAYS:   int = 7
_SCAN_WARN_DAYS: int = 30

# rkhunter database path
_RKHUNTER_DB = Path("/var/lib/rkhunter/db/rkhunter.dat")

# rkhunter log path
_RKHUNTER_LOG = Path("/var/log/rkhunter.log")

# chkrootkit log path (written by cron job on Debian/Ubuntu)
_CHKROOTKIT_LOG = Path("/var/log/chkrootkit/log.today")
_CHKROOTKIT_LOG_ALT = Path("/var/log/chkrootkit.log")

# Pattern to find a completed rkhunter scan in the log
_RKHUNTER_SCAN_RE = re.compile(
    r"System checks summary|Scan results|End date",
    re.IGNORECASE,
)

# Bytes to read from the end of the rkhunter log.
# Full scans generate large logs (130 KB+); 100 KB covers the summary section
# even on systems with many rootkit checks.
_LOG_TAIL_BYTES = 100_000

@dataclass
class RootkitSnapshot:
    """
    State collected from the system about rootkit scanners.

    Args:
        rkhunter_installed:   True if rkhunter binary is present.
        chkrootkit_installed: True if chkrootkit binary is present.
        tool:                 Name of the preferred detected tool ("rkhunter", "chkrootkit", "").
        db_age_days:          Days since rkhunter DB was last updated (None if unknown/N/A).
        last_scan_date:       ISO date of the last completed scan, or None.
    """
    rkhunter_installed:   bool          = False
    chkrootkit_installed: bool          = False
    tool:                 str           = ""
    db_age_days:          int | None = None
    last_scan_date:       str | None = None

    @classmethod
    def from_system(cls) -> "RootkitSnapshot":
        """Collect rootkit scanner state from the live system. Never raises."""
        snap = cls()

        snap.rkhunter_installed   = _command_exists("rkhunter")
        snap.chkrootkit_installed = _command_exists("chkrootkit")

        if snap.rkhunter_installed:
            snap.tool = "rkhunter"
            snap.db_age_days  = _rkhunter_db_age()
            snap.last_scan_date = _rkhunter_last_scan()
        elif snap.chkrootkit_installed:
            snap.tool = "chkrootkit"
            snap.last_scan_date = _chkrootkit_last_scan()

        return snap

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rkhunter_db_age() -> int | None:
    """Return age in days of the rkhunter database file, or None if absent."""
    try:
        if not _RKHUNTER_DB.exists():
            return None
        mtime_dt = datetime.fromtimestamp(
            _RKHUNTER_DB.stat().st_mtime, tz=timezone.utc
        )
        return max(0, (datetime.now(timezone.utc) - mtime_dt).days)
    except OSError:
        return None

def _rkhunter_last_scan() -> str | None:
    """
    Return the ISO date of the last rkhunter scan, or None if not found.

    Strategy:
      1. Read up to _LOG_TAIL_BYTES from the end of the log (rkhunter scans
         can produce 130 KB+ logs; a 200-line tail is often insufficient).
      2. Confirm a completed scan marker is present in that window.
      3. Return the log file's mtime as the scan date — robust against
         log timestamp format variations (rkhunter 1.4.x writes [HH:MM:SS]
         only, with no date on content lines).
    """
    try:
        if not _RKHUNTER_LOG.exists():
            return None
        stat = _RKHUNTER_LOG.stat()
        if stat.st_size == 0:
            return None
        with _RKHUNTER_LOG.open("rb") as fh:
            fh.seek(max(0, stat.st_size - _LOG_TAIL_BYTES))
            data = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    # Confirm a completed scan is present in the tail window
    if not _RKHUNTER_SCAN_RE.search(data):
        return None

    # Use file mtime as the scan date — format-independent
    try:
        mtime_dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        return mtime_dt.strftime("%Y-%m-%d")
    except OSError:
        return None

def _chkrootkit_last_scan() -> str | None:
    """Return the ISO date of the last chkrootkit scan, or None."""
    for log_path in (_CHKROOTKIT_LOG, _CHKROOTKIT_LOG_ALT):
        try:
            if not log_path.exists():
                continue
            mtime_dt = datetime.fromtimestamp(
                log_path.stat().st_mtime, tz=timezone.utc
            )
            return mtime_dt.strftime("%Y-%m-%d")
        except OSError:
            continue
    return None

def _scan_age_days(iso_date: str) -> int | None:
    """Return days since iso_date (YYYY-MM-DD), or None on parse error."""
    try:
        dt = datetime.strptime(iso_date, "%Y-%m-%d")
        return max(0, (datetime.now() - dt).days)
    except ValueError:
        return None

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_rootkit(snapshot: RootkitSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse rootkit scanner snapshot and return findings.

    Findings:
      - Neither installed:         INFO  (no deduction)
      - rkhunter db outdated:      WARN  −1 pt
      - No recent scan:            WARN  −1 pt
      - Recent scan, db ok:        OK
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.rkhunter_installed and not snapshot.chkrootkit_installed:
        result.info(
            message=_t("rootkit.not_installed"),
            detail=_t("rootkit.not_installed_detail"),
            cmd="sudo apt install rkhunter",
            key="rootkit.not_installed",
        )
        return result

    tool = snapshot.tool

    # rkhunter: check database freshness
    if snapshot.rkhunter_installed and snapshot.db_age_days is not None:
        if snapshot.db_age_days >= _DB_WARN_DAYS:
            result.warn_with_deduction(
                key="rootkit.db_outdated",
                message=_t("rootkit.db_outdated", tool=tool, days=snapshot.db_age_days),
                reason=_t("rootkit.db_outdated_reason", tool=tool, days=snapshot.db_age_days),
                points=1,
                detail=_t("rootkit.db_outdated_detail"),
                cmd="sudo rkhunter --update",
                nature="improvement",
            )

    # Last scan check
    if snapshot.last_scan_date is None:
        result.warn_with_deduction(
            key="rootkit.no_scan",
            message=_t("rootkit.no_scan", tool=tool),
            reason=_t("rootkit.no_scan_reason", tool=tool),
            points=1,
            detail=_t("rootkit.no_scan_detail"),
            cmd=f"sudo {tool} --checkall" if tool == "rkhunter" else f"sudo {tool}",
            nature="improvement",
        )
        return result

    scan_age = _scan_age_days(snapshot.last_scan_date)
    if scan_age is not None and scan_age >= _SCAN_WARN_DAYS:
        result.warn_with_deduction(
            key="rootkit.scan_old",
            message=_t("rootkit.scan_old", tool=tool, days=scan_age, date=snapshot.last_scan_date),
            reason=_t("rootkit.scan_old_reason", tool=tool, days=scan_age),
            points=1,
            detail=_t("rootkit.scan_old_detail"),
            cmd=f"sudo {tool} --checkall" if tool == "rkhunter" else f"sudo {tool}",
            nature="improvement",
        )
        return result

    result.ok(
        message=_t("rootkit.ok", tool=tool, date=snapshot.last_scan_date),
        key="rootkit.ok",
    )
    return result
