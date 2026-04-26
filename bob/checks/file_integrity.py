"""
File integrity check for BOB (CHECK 33).

Checks whether a file integrity monitor (AIDE or Tripwire) is installed,
whether its database has been initialised, and when the last check was run.
Without file integrity monitoring, unauthorised modifications to system
binaries, config files, or libraries go undetected.

Score impact:
  - Neither installed:              INFO  (no deduction — optional but recommended)
  - Installed, no database:         WARN  −1 pt
  - Installed, db ok, no recent check (> 30 days): WARN  −1 pt
  - Installed, db ok, recent check: OK

AIDE is preferred over Tripwire when both are present.

Split into:
  1. FileIntegritySnapshot.from_system() — collects state via file inspection.
  2. check_file_integrity(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bob.checks._run import _command_exists, _identity_t
from bob.scoring import CheckResult

# Age threshold before a stale check is flagged
_CHECK_WARN_DAYS: int = 30

# AIDE paths
_AIDE_DB_PATHS = (
    Path("/var/lib/aide/aide.db"),
    Path("/var/lib/aide/aide.db.gz"),
    Path("/var/lib/aide/aide.db.new"),
    Path("/var/lib/aide/aide.db.new.gz"),
)
_AIDE_LOG_PATHS = (
    Path("/var/log/aide/aide.log"),
    Path("/var/log/aide.log"),
)

# Tripwire paths
_TRIPWIRE_DB_DIR  = Path("/var/lib/tripwire")
_TRIPWIRE_LOG_DIR = Path("/var/log/tripwire")


@dataclass
class FileIntegritySnapshot:
    """
    State collected from the system about file integrity monitors.

    Args:
        tool:             Detected tool name ("aide", "tripwire", "").
        db_exists:        True if the integrity database file is present.
        last_check_date:  ISO date (YYYY-MM-DD) of the last check, or None.
    """
    tool:            str           = ""
    db_exists:       bool          = False
    last_check_date: Optional[str] = None

    @classmethod
    def from_system(cls) -> "FileIntegritySnapshot":
        """Collect file integrity state from the live system. Never raises."""
        snap = cls()

        if _command_exists("aide"):
            snap.tool      = "aide"
            snap.db_exists = any(p.exists() for p in _AIDE_DB_PATHS)
            snap.last_check_date = _last_run_from_logs(_AIDE_LOG_PATHS)
            return snap

        if _command_exists("tripwire"):
            snap.tool      = "tripwire"
            snap.db_exists = _tripwire_db_exists()
            snap.last_check_date = _last_run_from_dir(_TRIPWIRE_LOG_DIR, "*.txt")
            return snap

        return snap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mtime_iso(path: Path) -> Optional[str]:
    """Return the ISO date of ``path``'s mtime, or None on error."""
    try:
        mtime_dt = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        return mtime_dt.strftime("%Y-%m-%d")
    except OSError:
        return None


def _last_run_from_logs(log_paths: tuple) -> Optional[str]:
    """Return ISO date of the most recently modified log file, or None."""
    best: Optional[str] = None
    best_mtime: float = 0.0
    for p in log_paths:
        try:
            if not p.exists():
                continue
            mtime = p.stat().st_mtime
            if mtime > best_mtime:
                best_mtime = mtime
                best = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
        except OSError:
            continue
    return best


def _last_run_from_dir(directory: Path, pattern: str) -> Optional[str]:
    """Return ISO date of the most recently modified file matching pattern, or None."""
    try:
        files = list(directory.glob(pattern))
        if not files:
            return None
        newest = max(files, key=lambda p: p.stat().st_mtime)
        return _mtime_iso(newest)
    except OSError:
        return None


def _tripwire_db_exists() -> bool:
    """Return True if any Tripwire database file (.twd) exists."""
    try:
        return any(_TRIPWIRE_DB_DIR.glob("*.twd"))
    except OSError:
        return False


def _check_age_days(iso_date: str) -> Optional[int]:
    """Return days since iso_date (YYYY-MM-DD), or None on parse error."""
    try:
        dt = datetime.strptime(iso_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_file_integrity(snapshot: FileIntegritySnapshot, t=None) -> CheckResult:
    """
    Analyse FileIntegritySnapshot and return findings.

    Findings:
      - Not installed:          INFO  (no deduction)
      - No database:            WARN  −1 pt
      - No recent check:        WARN  −1 pt
      - Recent check, db ok:    OK
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.tool:
        result.info(
            message=_t("file_integrity.not_installed"),
            detail=_t("file_integrity.not_installed_detail"),
            cmd="sudo apt install aide && sudo aideinit",
            key="file_integrity.not_installed",
        )
        return result

    tool = snapshot.tool

    if not snapshot.db_exists:
        init_cmd = "sudo aideinit" if tool == "aide" else "sudo tripwire --init"
        result.warn(
            message=_t("file_integrity.no_db", tool=tool),
            detail=_t("file_integrity.no_db_detail", tool=tool),
            cmd=init_cmd,
            nature="improvement",
            key="file_integrity.no_db",
        )
        result.add_deduction(
            reason=_t("file_integrity.no_db_reason", tool=tool),
            points=1,
            context="local",
            key="file_integrity.no_db",
        )
        return result

    if snapshot.last_check_date is None:
        check_cmd = "sudo aide --check" if tool == "aide" else "sudo tripwire --check"
        result.warn(
            message=_t("file_integrity.no_check", tool=tool),
            detail=_t("file_integrity.no_check_detail", tool=tool),
            cmd=check_cmd,
            nature="improvement",
            key="file_integrity.no_check",
        )
        result.add_deduction(
            reason=_t("file_integrity.no_check_reason", tool=tool),
            points=1,
            context="local",
            key="file_integrity.no_check",
        )
        return result

    age = _check_age_days(snapshot.last_check_date)
    if age is not None and age >= _CHECK_WARN_DAYS:
        check_cmd = "sudo aide --check" if tool == "aide" else "sudo tripwire --check"
        result.warn(
            message=_t("file_integrity.check_old", tool=tool, days=age,
                       date=snapshot.last_check_date),
            detail=_t("file_integrity.check_old_detail"),
            cmd=check_cmd,
            nature="improvement",
            key="file_integrity.check_old",
        )
        result.add_deduction(
            reason=_t("file_integrity.check_old_reason", tool=tool, days=age),
            points=1,
            context="local",
            key="file_integrity.check_old",
        )
        return result

    result.ok(
        message=_t("file_integrity.ok", tool=tool, date=snapshot.last_check_date),
        key="file_integrity.ok",
    )
    return result
