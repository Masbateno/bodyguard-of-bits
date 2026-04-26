"""
Unit tests for bob.checks.clamav module.

All tests use ClamAVSnapshot instances built directly — no subprocess calls
and no real file I/O (log parsing tested separately with tmp_path).

Run with: python -m pytest tests/test_clamav.py -v
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from datetime import datetime, timedelta

import pytest

from bob.checks.clamav import (
    ClamAVSnapshot,
    check_clamav,
    _find_last_scan_date,
    _scan_age_days,
    _tail_lines,
    _DB_WARN_DAYS,
    _DB_ALERT_DAYS,
    _SCAN_WARN_DAYS,
    _SCAN_ALERT_DAYS,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(**kwargs) -> ClamAVSnapshot:
    defaults = dict(
        installed=True,
        freshclam_installed=True,
        clamd_active=True,
        db_path="/var/lib/clamav/daily.cld",
        db_age_days=1,
        last_scan_date=days_ago_iso(1),
        last_scan_log_path="/var/log/clamav/clamscan.log",
        install_cmd="sudo apt install clamav clamav-daemon",
    )
    defaults.update(kwargs)
    return ClamAVSnapshot(**defaults)


def keys(result) -> list[str]:
    return [f.key for f in result.findings]


def has_level(result, level: FindingLevel) -> bool:
    return any(f.level == level for f in result.findings)


def deduction_points(result) -> int:
    return sum(d.points for d in result.deductions)


def today_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def days_ago_iso(n: int) -> str:
    dt = datetime.now() - timedelta(days=n)
    return dt.strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Not installed
# ---------------------------------------------------------------------------

class TestNotInstalled:
    def test_not_installed_returns_info(self):
        snap = make_snap(installed=False)
        result = check_clamav(snap, t=_t)
        assert has_level(result, FindingLevel.INFO)

    def test_not_installed_key(self):
        snap = make_snap(installed=False)
        result = check_clamav(snap, t=_t)
        assert "clamav.not_installed" in keys(result)

    def test_not_installed_no_deductions(self):
        snap = make_snap(installed=False)
        result = check_clamav(snap, t=_t)
        assert deduction_points(result) == 0

    def test_not_installed_only_one_finding(self):
        snap = make_snap(installed=False)
        result = check_clamav(snap, t=_t)
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Installed
# ---------------------------------------------------------------------------

class TestInstalled:
    def test_installed_ok_finding(self):
        snap = make_snap()
        result = check_clamav(snap, t=_t)
        ok_findings = [f for f in result.findings if f.key == "clamav.installed"]
        assert len(ok_findings) == 1

    def test_installed_ok_level(self):
        snap = make_snap()
        result = check_clamav(snap, t=_t)
        installed_f = next(f for f in result.findings if f.key == "clamav.installed")
        assert installed_f.level == FindingLevel.OK


# ---------------------------------------------------------------------------
# freshclam missing
# ---------------------------------------------------------------------------

class TestFreshclamMissing:
    def test_freshclam_missing_is_warn(self):
        snap = make_snap(freshclam_installed=False)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.freshclam_missing"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_freshclam_missing_deducts_1(self):
        snap = make_snap(freshclam_installed=False)
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.freshclam_missing")
        assert pts == 1

    def test_freshclam_present_no_finding(self):
        snap = make_snap(freshclam_installed=True)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.freshclam_missing"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Virus database age
# ---------------------------------------------------------------------------

class TestDatabaseAge:
    def test_db_not_found_is_warn(self):
        snap = make_snap(db_age_days=None, db_path="")
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_not_found"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_db_not_found_deducts_1(self):
        snap = make_snap(db_age_days=None, db_path="")
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.db_not_found")
        assert pts == 1

    def test_db_very_outdated_is_alert(self):
        snap = make_snap(db_age_days=_DB_ALERT_DAYS)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_very_outdated"]
        assert findings and findings[0].level == FindingLevel.ALERT

    def test_db_very_outdated_deducts_2(self):
        snap = make_snap(db_age_days=_DB_ALERT_DAYS + 10)
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.db_very_outdated")
        assert pts == 2

    def test_db_outdated_is_warn(self):
        snap = make_snap(db_age_days=_DB_WARN_DAYS)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_outdated"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_db_outdated_deducts_1(self):
        snap = make_snap(db_age_days=_DB_WARN_DAYS + 2)
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.db_outdated")
        assert pts == 1

    def test_db_fresh_is_ok(self):
        snap = make_snap(db_age_days=0)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_ok"]
        assert findings and findings[0].level == FindingLevel.OK

    def test_db_1_day_is_ok(self):
        snap = make_snap(db_age_days=1)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_ok"]
        assert len(findings) == 1

    def test_db_warn_threshold_exact(self):
        snap = make_snap(db_age_days=_DB_WARN_DAYS)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_outdated"]
        assert len(findings) == 1

    def test_db_alert_threshold_exact(self):
        snap = make_snap(db_age_days=_DB_ALERT_DAYS)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.db_very_outdated"]
        assert len(findings) == 1

    def test_db_alert_overrides_warn(self):
        """When db_age >= ALERT threshold, only alert is produced, not warn."""
        snap = make_snap(db_age_days=_DB_ALERT_DAYS + 5)
        result = check_clamav(snap, t=_t)
        warn_findings = [f for f in result.findings if f.key == "clamav.db_outdated"]
        alert_findings = [f for f in result.findings if f.key == "clamav.db_very_outdated"]
        assert len(warn_findings) == 0
        assert len(alert_findings) == 1


# ---------------------------------------------------------------------------
# clamd daemon
# ---------------------------------------------------------------------------

class TestClamdDaemon:
    def test_clamd_inactive_is_info(self):
        snap = make_snap(clamd_active=False)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.clamd_inactive"]
        assert findings and findings[0].level == FindingLevel.INFO

    def test_clamd_inactive_no_deduction(self):
        snap = make_snap(clamd_active=False)
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.clamd_inactive")
        assert pts == 0

    def test_clamd_active_no_finding(self):
        snap = make_snap(clamd_active=True)
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.clamd_inactive"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Last scan
# ---------------------------------------------------------------------------

class TestLastScan:
    def test_no_scan_log_is_info(self):
        snap = make_snap(last_scan_date=None, last_scan_log_path="")
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.no_scan_log"]
        assert findings and findings[0].level == FindingLevel.INFO

    def test_no_scan_log_no_deduction(self):
        snap = make_snap(last_scan_date=None, last_scan_log_path="")
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.no_scan_log")
        assert pts == 0

    def test_scan_very_old_is_warn(self):
        snap = make_snap(last_scan_date=days_ago_iso(_SCAN_ALERT_DAYS))
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.scan_very_old"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_scan_very_old_deducts_1(self):
        snap = make_snap(last_scan_date=days_ago_iso(_SCAN_ALERT_DAYS + 10))
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.scan_very_old")
        assert pts == 1

    def test_scan_old_is_warn(self):
        snap = make_snap(last_scan_date=days_ago_iso(_SCAN_WARN_DAYS))
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.scan_old"]
        assert findings and findings[0].level == FindingLevel.WARN

    def test_scan_old_deducts_1(self):
        snap = make_snap(last_scan_date=days_ago_iso(_SCAN_WARN_DAYS + 5))
        result = check_clamav(snap, t=_t)
        pts = sum(d.points for d in result.deductions if d.key == "clamav.scan_old")
        assert pts == 1

    def test_scan_recent_is_ok(self):
        snap = make_snap(last_scan_date=today_iso())
        result = check_clamav(snap, t=_t)
        findings = [f for f in result.findings if f.key == "clamav.scan_recent"]
        assert findings and findings[0].level == FindingLevel.OK

    def test_scan_alert_overrides_warn(self):
        """Very old scan: only scan_very_old produced, not scan_old."""
        snap = make_snap(last_scan_date=days_ago_iso(_SCAN_ALERT_DAYS + 1))
        result = check_clamav(snap, t=_t)
        old_findings  = [f for f in result.findings if f.key == "clamav.scan_old"]
        vold_findings = [f for f in result.findings if f.key == "clamav.scan_very_old"]
        assert len(old_findings)  == 0
        assert len(vold_findings) == 1


# ---------------------------------------------------------------------------
# Cumulative deductions
# ---------------------------------------------------------------------------

class TestCumulativeDeductions:
    def test_perfect_config_no_deductions(self):
        snap = make_snap(
            freshclam_installed=True,
            clamd_active=True,
            db_age_days=1,
            last_scan_date=today_iso(),
        )
        result = check_clamav(snap, t=_t)
        assert deduction_points(result) == 0

    def test_worst_case(self):
        snap = make_snap(
            freshclam_installed=False,
            db_age_days=_DB_ALERT_DAYS + 5,
            last_scan_date=days_ago_iso(_SCAN_ALERT_DAYS + 5),
        )
        result = check_clamav(snap, t=_t)
        # freshclam: 1, db_very_outdated: 2, scan_very_old: 1 → 4
        assert deduction_points(result) == 4


# ---------------------------------------------------------------------------
# _scan_age_days helper
# ---------------------------------------------------------------------------

class TestScanAgeDays:
    def test_today_is_zero(self):
        assert _scan_age_days(today_iso()) == 0

    def test_yesterday_is_one(self):
        assert _scan_age_days(days_ago_iso(1)) == 1

    def test_30_days_ago(self):
        assert _scan_age_days(days_ago_iso(30)) == 30

    def test_invalid_returns_none(self):
        assert _scan_age_days("not-a-date") is None

    def test_empty_returns_none(self):
        assert _scan_age_days("") is None


# ---------------------------------------------------------------------------
# _tail_lines helper
# ---------------------------------------------------------------------------

class TestTailLines:
    def test_returns_last_n_lines(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_bytes(b"line1\nline2\nline3\nline4\nline5\n")
        result = _tail_lines(f, 3)
        assert result == ["line3", "line4", "line5"]

    def test_fewer_lines_than_n(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_bytes(b"line1\nline2\n")
        result = _tail_lines(f, 10)
        assert "line1" in result
        assert "line2" in result

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.log"
        f.write_bytes(b"")
        result = _tail_lines(f, 10)
        assert result == []


# ---------------------------------------------------------------------------
# _find_last_scan_date — log parsing
# ---------------------------------------------------------------------------

class TestFindLastScanDate:
    def _write_scan_log(self, path: Path, date_str: str) -> None:
        """Write a minimal ClamAV scan summary with the given End Date."""
        content = textwrap.dedent(f"""\
            ----------- SCAN SUMMARY -----------
            Known viruses: 8680480
            Engine version: 0.103.11
            Scanned files: 100
            Infected files: 0
            End Date:   {date_str}
            """)
        path.write_text(content, encoding="utf-8")

    def test_parses_end_date(self, tmp_path, monkeypatch):
        import bob.checks.clamav as clamav_mod
        log = tmp_path / "clamscan.log"
        self._write_scan_log(log, "2026:04:10 15:30:06")
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [log])
        date, path = _find_last_scan_date()
        assert date == "2026-04-10"
        assert path == str(log)

    def test_no_logs_returns_none(self, tmp_path, monkeypatch):
        import bob.checks.clamav as clamav_mod
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [
            tmp_path / "nonexistent.log"
        ])
        date, path = _find_last_scan_date()
        assert date is None
        assert path == ""

    def test_picks_most_recent_across_logs(self, tmp_path, monkeypatch):
        import bob.checks.clamav as clamav_mod
        log1 = tmp_path / "clamscan.log"
        log2 = tmp_path / "clamdscan.log"
        self._write_scan_log(log1, "2026:03:01 10:00:00")
        self._write_scan_log(log2, "2026:04:10 15:30:06")
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [log1, log2])
        date, path = _find_last_scan_date()
        assert date == "2026-04-10"
        assert path == str(log2)

    def test_multiple_summaries_picks_latest(self, tmp_path, monkeypatch):
        import bob.checks.clamav as clamav_mod
        log = tmp_path / "clamscan.log"
        content = textwrap.dedent("""\
            ----------- SCAN SUMMARY -----------
            End Date:   2026:03:01 10:00:00

            ----------- SCAN SUMMARY -----------
            End Date:   2026:04:10 15:30:06
            """)
        log.write_text(content, encoding="utf-8")
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [log])
        date, _ = _find_last_scan_date()
        assert date == "2026-04-10"

    def test_log_without_scan_summary(self, tmp_path, monkeypatch):
        import bob.checks.clamav as clamav_mod
        log = tmp_path / "clamav.log"
        log.write_text("freshclam update completed\n", encoding="utf-8")
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [log])
        date, _ = _find_last_scan_date()
        assert date is None


# ---------------------------------------------------------------------------
# ClamAVSnapshot.from_system — not installed path
# ---------------------------------------------------------------------------

class TestFromSystemNotInstalled:
    def test_no_binary_returns_not_installed(self, monkeypatch):
        import bob.checks.clamav as clamav_mod
        monkeypatch.setattr(clamav_mod, "_command_exists", lambda name: False)
        snap = ClamAVSnapshot.from_system()
        assert not snap.installed

    def test_clamscan_found_marks_installed(self, monkeypatch):
        import bob.checks.clamav as clamav_mod
        monkeypatch.setattr(
            clamav_mod, "_command_exists",
            lambda name: name == "clamscan",
        )
        monkeypatch.setattr(clamav_mod, "_DB_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_run", lambda *a, **k: "")
        snap = ClamAVSnapshot.from_system()
        assert snap.installed

    def test_db_age_computed(self, monkeypatch, tmp_path):
        import bob.checks.clamav as clamav_mod
        db = tmp_path / "daily.cld"
        db.write_bytes(b"fake")
        # Force mtime to 5 days ago
        import time
        mtime = time.time() - 5 * 86400
        import os
        os.utime(db, (mtime, mtime))
        monkeypatch.setattr(
            clamav_mod, "_command_exists",
            lambda name: name in ("clamscan", "freshclam"),
        )
        monkeypatch.setattr(clamav_mod, "_DB_CANDIDATES", [db])
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_run", lambda *a, **k: "")
        snap = ClamAVSnapshot.from_system()
        assert snap.db_age_days == 5
        assert snap.db_path == str(db)

    def test_freshclam_only_marks_installed(self, monkeypatch):
        """freshclam present without clamscan/clamdscan still marks installed=True."""
        import bob.checks.clamav as clamav_mod
        monkeypatch.setattr(
            clamav_mod, "_command_exists",
            lambda name: name == "freshclam",
        )
        monkeypatch.setattr(clamav_mod, "_DB_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_run", lambda *a, **k: "")
        snap = ClamAVSnapshot.from_system()
        assert snap.installed

    def test_clamd_socket_fallback(self, monkeypatch, tmp_path):
        """When systemctl is unavailable, a clamd socket file marks clamd_active=True."""
        import bob.checks.clamav as clamav_mod
        socket_file = tmp_path / "clamd.ctl"
        socket_file.write_bytes(b"")
        monkeypatch.setattr(
            clamav_mod, "_command_exists",
            lambda name: name != "systemctl",
        )
        monkeypatch.setattr(
            clamav_mod,
            "_CLAMD_SOCKETS",
            [socket_file],
        )
        monkeypatch.setattr(clamav_mod, "_DB_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [])
        snap = ClamAVSnapshot.from_system()
        assert snap.clamd_active

    def test_clamd_socket_missing_stays_inactive(self, monkeypatch, tmp_path):
        """No systemctl, no socket file → clamd_active stays False."""
        import bob.checks.clamav as clamav_mod
        monkeypatch.setattr(
            clamav_mod, "_command_exists",
            lambda name: name != "systemctl",
        )
        monkeypatch.setattr(
            clamav_mod,
            "_CLAMD_SOCKETS",
            [tmp_path / "nonexistent.ctl"],
        )
        monkeypatch.setattr(clamav_mod, "_DB_CANDIDATES", [])
        monkeypatch.setattr(clamav_mod, "_SCAN_LOG_CANDIDATES", [])
        snap = ClamAVSnapshot.from_system()
        assert not snap.clamd_active
