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

from bob.checks._run import install_fix, TranslationFunc, _command_exists, _identity_t, path_exists
from bob.scoring import CheckResult
from bob._fs import strict_is_file

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
        db_readable:      False when the database location was denied — the
                          "database missing" verdict is then unknown, not a fact.
        last_check_date:  ISO date (YYYY-MM-DD) of the last check, or None.
    """
    tool:            str           = ""
    db_exists:       bool          = False
    db_readable:     bool          = True
    last_check_date: str | None = None

    @classmethod
    def from_system(cls) -> "FileIntegritySnapshot":
        """Collect file integrity state from the live system. Never raises."""
        snap = cls()

        if _command_exists("aide"):
            snap.tool      = "aide"
            snap.db_exists, snap.db_readable = _aide_db_state()
            snap.last_check_date = _last_run_from_logs(_AIDE_LOG_PATHS)
            return snap

        if _command_exists("tripwire"):
            snap.tool      = "tripwire"
            snap.db_exists, snap.db_readable = _tripwire_db_state()
            snap.last_check_date = _last_run_from_dir(_TRIPWIRE_LOG_DIR, "*.txt")
            return snap

        return snap

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mtime_iso(path: Path) -> str | None:
    """Return the ISO date of ``path``'s mtime, or None on error."""
    try:
        mtime_dt = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        return mtime_dt.strftime("%Y-%m-%d")
    except OSError:
        return None

def _last_run_from_logs(log_paths: tuple) -> str | None:
    """Return ISO date of the most recently modified log file, or None."""
    best: str | None = None
    best_mtime: float = 0.0
    for p in log_paths:
        try:
            if not path_exists(p):
                continue
            mtime = p.stat().st_mtime
            if mtime > best_mtime:
                best_mtime = mtime
                best = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
        except OSError:
            continue
    return best

def _last_run_from_dir(directory: Path, pattern: str) -> str | None:
    """Return ISO date of the most recently modified file matching pattern, or None."""
    try:
        files = list(directory.glob(pattern))
        if not files:
            return None
        newest = max(files, key=lambda p: p.stat().st_mtime)
        return _mtime_iso(newest)
    except OSError:
        return None

def _aide_db_state() -> tuple[bool, bool]:
    """Return ``(db_exists, db_readable)`` for the AIDE database.

    ``db_readable`` is False when the database location was denied. /var/lib/aide
    is root-owned; when it is not traversable, ``path_exists`` (like pathlib's
    predicates on 3.14) would swallow the denial and report the database
    missing — a WARN and a point on a host that may well have one. ``strict_is_file``
    raises on the denial instead, so it is told apart from a real absence
    (ENOENT, when AIDE is installed but never initialised, stays a true "no db").
    """
    found = False
    for p in _AIDE_DB_PATHS:
        try:
            if strict_is_file(p):
                found = True
        except OSError:
            return (False, False)
    return (found, True)


def _tripwire_db_state() -> tuple[bool, bool]:
    """Return ``(db_exists, db_readable)`` for /var/lib/tripwire/*.twd.

    ``glob()`` swallows a read denial and returns [], which would report the
    database missing; ``iterdir()`` raises, so a locked DB directory is told
    apart from a genuinely absent or empty one.
    """
    try:
        for entry in _TRIPWIRE_DB_DIR.iterdir():
            if entry.suffix == ".twd":
                return (True, True)
        return (False, True)
    except FileNotFoundError:
        return (False, True)   # not initialised — a real "no database"
    except OSError:
        return (False, False)  # denied — the verdict is unknown

def _check_age_days(iso_date: str) -> int | None:
    """Return days since iso_date (YYYY-MM-DD), or None on parse error."""
    try:
        dt = datetime.strptime(iso_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_file_integrity(snapshot: FileIntegritySnapshot, t: TranslationFunc | None = None) -> CheckResult:
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
        # `aideinit` is Debian's wrapper. Fedora's aide wants `aide --init`, and
        # appending Debian's name to a dnf command would hand the operator a
        # remedy whose second half cannot run.
        _cmd, _detail = install_fix(
            _t, _t("file_integrity.not_installed_detail"), "aide",
            then_apt="sudo aideinit")
        result.info(
            message=_t("file_integrity.not_installed"),
            detail=_detail,
            cmd=_cmd,
            key="file_integrity.not_installed",
        )
        return result

    tool = snapshot.tool

    if not snapshot.db_exists and not snapshot.db_readable:
        # The tool is installed but its database directory was denied. "No
        # database" here is a guess, not a reading — so no WARN and no point.
        result.info(
            message=_t("file_integrity.db_unknown", tool=tool),
            detail=_t("file_integrity.db_unknown_detail", tool=tool),
            key="file_integrity.db_unknown",
        )
        return result

    if not snapshot.db_exists:
        init_cmd = "sudo aideinit" if tool == "aide" else "sudo tripwire --init"
        result.warn_with_deduction(
            key="file_integrity.no_db",
            message=_t("file_integrity.no_db", tool=tool),
            reason=_t("file_integrity.no_db_reason", tool=tool),
            points=1,
            detail=_t("file_integrity.no_db_detail", tool=tool),
            cmd=init_cmd,
            nature="improvement",
        )
        return result

    if snapshot.last_check_date is None:
        check_cmd = "sudo aide --check" if tool == "aide" else "sudo tripwire --check"
        result.warn_with_deduction(
            key="file_integrity.no_check",
            message=_t("file_integrity.no_check", tool=tool),
            reason=_t("file_integrity.no_check_reason", tool=tool),
            points=1,
            detail=_t("file_integrity.no_check_detail", tool=tool),
            cmd=check_cmd,
            nature="improvement",
        )
        return result

    age = _check_age_days(snapshot.last_check_date)
    if age is not None and age >= _CHECK_WARN_DAYS:
        check_cmd = "sudo aide --check" if tool == "aide" else "sudo tripwire --check"
        result.warn_with_deduction(
            key="file_integrity.check_old",
            message=_t("file_integrity.check_old", tool=tool, days=age,
                       date=snapshot.last_check_date),
            reason=_t("file_integrity.check_old_reason", tool=tool, days=age),
            points=1,
            detail=_t("file_integrity.check_old_detail"),
            cmd=check_cmd,
            nature="improvement",
        )
        return result

    result.ok(
        message=_t("file_integrity.ok", tool=tool, date=snapshot.last_check_date),
        key="file_integrity.ok",
    )
    return result
