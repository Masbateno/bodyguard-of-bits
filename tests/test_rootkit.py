"""Tests for CHECK 30 — Rootkit & integrity scan."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bob.checks.rootkit import (
    RootkitSnapshot,
    _rkhunter_db_age,
    _rkhunter_last_scan,
    _chkrootkit_last_scan,
    _scan_age_days,
    check_rootkit,
)
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# _scan_age_days helper
# ---------------------------------------------------------------------------

class TestScanAgeDays:
    def test_today_is_zero(self):
        today = datetime.now().strftime("%Y-%m-%d")
        assert _scan_age_days(today) == 0

    def test_yesterday_is_one(self):
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        assert _scan_age_days(yesterday) == 1

    def test_thirty_days_ago(self):
        d = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        assert _scan_age_days(d) == 30

    def test_invalid_returns_none(self):
        assert _scan_age_days("not-a-date") is None

    def test_empty_returns_none(self):
        assert _scan_age_days("") is None


# ---------------------------------------------------------------------------
# RootkitSnapshot dataclass defaults
# ---------------------------------------------------------------------------

class TestRootkitSnapshotDefaults:
    def test_rkhunter_installed_default_false(self):
        assert not RootkitSnapshot().rkhunter_installed

    def test_chkrootkit_installed_default_false(self):
        assert not RootkitSnapshot().chkrootkit_installed

    def test_tool_default_empty(self):
        assert RootkitSnapshot().tool == ""

    def test_db_age_days_default_none(self):
        assert RootkitSnapshot().db_age_days is None

    def test_last_scan_date_default_none(self):
        assert RootkitSnapshot().last_scan_date is None


# ---------------------------------------------------------------------------
# RootkitSnapshot.from_system()
# ---------------------------------------------------------------------------

class TestRootkitFromSystemNotInstalled:
    def test_neither_installed(self):
        with patch("bob.checks.rootkit._command_exists", return_value=False):
            snap = RootkitSnapshot.from_system()
        assert not snap.rkhunter_installed
        assert not snap.chkrootkit_installed
        assert snap.tool == ""

    def test_no_db_age_when_not_installed(self):
        with patch("bob.checks.rootkit._command_exists", return_value=False):
            snap = RootkitSnapshot.from_system()
        assert snap.db_age_days is None

    def test_no_last_scan_when_not_installed(self):
        with patch("bob.checks.rootkit._command_exists", return_value=False):
            snap = RootkitSnapshot.from_system()
        assert snap.last_scan_date is None


class TestRootkitFromSystemRkhunter:
    def test_rkhunter_installed_true(self):
        def _cmd(name):
            return name == "rkhunter"
        with patch("bob.checks.rootkit._command_exists", side_effect=_cmd), \
             patch("bob.checks.rootkit._rkhunter_db_age", return_value=3), \
             patch("bob.checks.rootkit._rkhunter_last_scan", return_value="2026-04-10"):
            snap = RootkitSnapshot.from_system()
        assert snap.rkhunter_installed
        assert snap.tool == "rkhunter"
        assert snap.db_age_days == 3
        assert snap.last_scan_date == "2026-04-10"

    def test_tool_rkhunter_takes_priority_over_chkrootkit(self):
        def _cmd(name):
            return name in ("rkhunter", "chkrootkit")
        with patch("bob.checks.rootkit._command_exists", side_effect=_cmd), \
             patch("bob.checks.rootkit._rkhunter_db_age", return_value=1), \
             patch("bob.checks.rootkit._rkhunter_last_scan", return_value="2026-04-11"):
            snap = RootkitSnapshot.from_system()
        assert snap.tool == "rkhunter"


class TestRootkitFromSystemChkrootkit:
    def test_chkrootkit_installed_true(self):
        def _cmd(name):
            return name == "chkrootkit"
        with patch("bob.checks.rootkit._command_exists", side_effect=_cmd), \
             patch("bob.checks.rootkit._chkrootkit_last_scan", return_value="2026-04-08"):
            snap = RootkitSnapshot.from_system()
        assert snap.chkrootkit_installed
        assert snap.tool == "chkrootkit"
        assert snap.last_scan_date == "2026-04-08"
        assert snap.db_age_days is None  # chkrootkit has no update DB


# ---------------------------------------------------------------------------
# check_rootkit() — not installed
# ---------------------------------------------------------------------------

class TestCheckRootkitNotInstalled:
    def test_info_finding(self):
        snap = RootkitSnapshot()
        result = check_rootkit(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.INFO in levels

    def test_no_deduction(self):
        snap = RootkitSnapshot()
        result = check_rootkit(snap)
        assert result.deductions == []

    def test_finding_key(self):
        snap = RootkitSnapshot()
        result = check_rootkit(snap)
        assert result.findings[0].key == "rootkit.not_installed"

    def test_install_cmd_present(self):
        snap = RootkitSnapshot()
        result = check_rootkit(snap)
        assert "rkhunter" in result.findings[0].cmd


# ---------------------------------------------------------------------------
# check_rootkit() — db outdated
# ---------------------------------------------------------------------------

class TestCheckRootkitDbOutdated:
    def test_warn_finding(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=10, last_scan_date="2026-04-11",
        )
        result = check_rootkit(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=10, last_scan_date="2026-04-11",
        )
        result = check_rootkit(snap)
        keys = [d.key for d in result.deductions]
        assert "rootkit.db_outdated" in keys
        deduction = next(d for d in result.deductions if d.key == "rootkit.db_outdated")
        assert deduction.points == 1

    def test_finding_key(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=10, last_scan_date="2026-04-11",
        )
        result = check_rootkit(snap)
        keys = [f.key for f in result.findings]
        assert "rootkit.db_outdated" in keys

    def test_no_db_warning_when_db_fresh(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date="2026-04-11",
        )
        result = check_rootkit(snap)
        keys = [f.key for f in result.findings]
        assert "rootkit.db_outdated" not in keys

    def test_no_db_warning_for_chkrootkit(self):
        snap = RootkitSnapshot(
            chkrootkit_installed=True, tool="chkrootkit",
            db_age_days=None, last_scan_date="2026-04-11",
        )
        result = check_rootkit(snap)
        keys = [f.key for f in result.findings]
        assert "rootkit.db_outdated" not in keys


# ---------------------------------------------------------------------------
# check_rootkit() — no scan on record
# ---------------------------------------------------------------------------

class TestCheckRootkitNoScan:
    def test_warn_finding(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=None,
        )
        result = check_rootkit(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=None,
        )
        result = check_rootkit(snap)
        keys = [d.key for d in result.deductions]
        assert "rootkit.no_scan" in keys
        deduction = next(d for d in result.deductions if d.key == "rootkit.no_scan")
        assert deduction.points == 1

    def test_finding_key(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=None,
        )
        result = check_rootkit(snap)
        keys = [f.key for f in result.findings]
        assert "rootkit.no_scan" in keys

    def test_cmd_contains_tool(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=None,
        )
        result = check_rootkit(snap)
        no_scan = next(f for f in result.findings if f.key == "rootkit.no_scan")
        assert "rkhunter" in no_scan.cmd

    def test_chkrootkit_cmd(self):
        snap = RootkitSnapshot(
            chkrootkit_installed=True, tool="chkrootkit",
            last_scan_date=None,
        )
        result = check_rootkit(snap)
        no_scan = next(f for f in result.findings if f.key == "rootkit.no_scan")
        assert "chkrootkit" in no_scan.cmd


# ---------------------------------------------------------------------------
# check_rootkit() — scan too old
# ---------------------------------------------------------------------------

class TestCheckRootkitScanOld:
    def _old_date(self):
        return (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d")

    def test_warn_finding(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=self._old_date(),
        )
        result = check_rootkit(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=self._old_date(),
        )
        result = check_rootkit(snap)
        keys = [d.key for d in result.deductions]
        assert "rootkit.scan_old" in keys

    def test_finding_key(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=self._old_date(),
        )
        result = check_rootkit(snap)
        keys = [f.key for f in result.findings]
        assert "rootkit.scan_old" in keys


# ---------------------------------------------------------------------------
# check_rootkit() — all OK
# ---------------------------------------------------------------------------

class TestCheckRootkitOk:
    def _recent_date(self):
        return (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d")

    def test_ok_finding(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=self._recent_date(),
        )
        result = check_rootkit(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.OK in levels

    def test_no_deduction(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=self._recent_date(),
        )
        result = check_rootkit(snap)
        assert result.deductions == []

    def test_ok_key(self):
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=3, last_scan_date=self._recent_date(),
        )
        result = check_rootkit(snap)
        ok_finding = next(f for f in result.findings if f.key == "rootkit.ok")
        assert ok_finding is not None

    def test_chkrootkit_ok(self):
        snap = RootkitSnapshot(
            chkrootkit_installed=True, tool="chkrootkit",
            last_scan_date=self._recent_date(),
        )
        result = check_rootkit(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.OK in levels

    def test_db_outdated_plus_ok_scan(self):
        """Outdated DB + recent scan → 2 findings, 1 deduction (db_outdated)."""
        snap = RootkitSnapshot(
            rkhunter_installed=True, tool="rkhunter",
            db_age_days=10, last_scan_date=self._recent_date(),
        )
        result = check_rootkit(snap)
        keys = [f.key for f in result.findings]
        assert "rootkit.db_outdated" in keys
        assert "rootkit.ok" in keys
        assert len(result.deductions) == 1
        assert result.deductions[0].key == "rootkit.db_outdated"
