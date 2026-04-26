"""
Unit tests for bob.checks.file_integrity module.

All tests use FileIntegritySnapshot instances built directly — no filesystem calls.

Run with: python -m pytest tests/test_file_integrity.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.file_integrity import (
    FileIntegritySnapshot,
    _check_age_days,
    check_file_integrity,
)
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(**overrides) -> FileIntegritySnapshot:
    defaults = dict(
        tool="aide",
        db_exists=True,
        last_check_date="2099-01-01",   # far future → never "old"
    )
    defaults.update(overrides)
    return FileIntegritySnapshot(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


# ---------------------------------------------------------------------------
# Not installed
# ---------------------------------------------------------------------------

class TestNotInstalled:
    def test_info_when_not_installed(self):
        snap = FileIntegritySnapshot()
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_not_installed(self):
        snap = FileIntegritySnapshot()
        result = check_file_integrity(snap, t=_t)
        assert total_deductions(result) == 0

    def test_key_when_not_installed(self):
        snap = FileIntegritySnapshot()
        result = check_file_integrity(snap, t=_t)
        assert "file_integrity.not_installed" in finding_keys(result)

    def test_install_cmd_present(self):
        snap = FileIntegritySnapshot()
        result = check_file_integrity(snap, t=_t)
        matches = [f for f in result.findings if f.key == "file_integrity.not_installed"]
        assert matches, "missing finding file_integrity.not_installed"
        assert "aide" in (matches[0].cmd or "").lower()


# ---------------------------------------------------------------------------
# Database not initialised
# ---------------------------------------------------------------------------

class TestNoDatabase:
    def test_warn_when_no_db(self):
        snap = make_snap(db_exists=False, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_no_db(self):
        snap = make_snap(db_exists=False, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        assert total_deductions(result) == 1

    def test_key_when_no_db(self):
        snap = make_snap(db_exists=False, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        assert "file_integrity.no_db" in finding_keys(result)

    def test_init_cmd_for_aide(self):
        snap = make_snap(tool="aide", db_exists=False, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        matches = [f for f in result.findings if f.key == "file_integrity.no_db"]
        assert matches
        assert "aideinit" in (matches[0].cmd or "")

    def test_init_cmd_for_tripwire(self):
        snap = make_snap(tool="tripwire", db_exists=False, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        matches = [f for f in result.findings if f.key == "file_integrity.no_db"]
        assert matches
        assert "tripwire --init" in (matches[0].cmd or "")


# ---------------------------------------------------------------------------
# No check run yet
# ---------------------------------------------------------------------------

class TestNoCheck:
    def test_warn_when_no_check(self):
        snap = make_snap(db_exists=True, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_no_check(self):
        snap = make_snap(db_exists=True, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        assert total_deductions(result) == 1

    def test_key_when_no_check(self):
        snap = make_snap(db_exists=True, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        assert "file_integrity.no_check" in finding_keys(result)

    def test_check_cmd_aide(self):
        snap = make_snap(tool="aide", db_exists=True, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        matches = [f for f in result.findings if f.key == "file_integrity.no_check"]
        assert matches
        assert "aide --check" in (matches[0].cmd or "")

    def test_check_cmd_tripwire(self):
        snap = make_snap(tool="tripwire", db_exists=True, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        matches = [f for f in result.findings if f.key == "file_integrity.no_check"]
        assert matches
        assert "tripwire --check" in (matches[0].cmd or "")


# ---------------------------------------------------------------------------
# Check too old
# ---------------------------------------------------------------------------

class TestCheckTooOld:
    def test_warn_when_check_old(self):
        snap = make_snap(last_check_date="2000-01-01")
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_check_old(self):
        snap = make_snap(last_check_date="2000-01-01")
        result = check_file_integrity(snap, t=_t)
        assert total_deductions(result) == 1

    def test_key_when_check_old(self):
        snap = make_snap(last_check_date="2000-01-01")
        result = check_file_integrity(snap, t=_t)
        assert "file_integrity.check_old" in finding_keys(result)

    def test_date_and_days_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            received[key] = kwargs
            return key

        snap = make_snap(last_check_date="2000-01-01")
        check_file_integrity(snap, t=_capture)
        kwargs = received.get("file_integrity.check_old", {})
        assert "days" in kwargs
        assert kwargs.get("date") == "2000-01-01"
        assert kwargs["days"] > 30


# ---------------------------------------------------------------------------
# Clean system
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_recent_check(self):
        result = check_file_integrity(make_snap(), t=_t)
        assert has_level(result, "ok")

    def test_no_deduction_when_recent_check(self):
        result = check_file_integrity(make_snap(), t=_t)
        assert total_deductions(result) == 0

    def test_key_when_ok(self):
        result = check_file_integrity(make_snap(), t=_t)
        assert "file_integrity.ok" in finding_keys(result)

    def test_tool_and_date_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            received[key] = kwargs
            return key

        check_file_integrity(make_snap(tool="aide", last_check_date="2099-01-01"), t=_capture)
        kwargs = received.get("file_integrity.ok", {})
        assert kwargs.get("tool") == "aide"
        assert kwargs.get("date") == "2099-01-01"

    def test_tripwire_also_produces_ok(self):
        snap = make_snap(tool="tripwire")
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "ok")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Clean system — finding count
# ---------------------------------------------------------------------------

class TestCleanSystemFindingCount:
    def test_exactly_one_finding_when_ok(self):
        """A clean system must not produce parasitic extra findings."""
        result = check_file_integrity(make_snap(), t=_t)
        assert len(result.findings) == 1

    def test_exactly_one_finding_for_tripwire_ok(self):
        result = check_file_integrity(make_snap(tool="tripwire"), t=_t)
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_invalid_date_treated_as_ok(self):
        """An unparseable last_check_date → age=None → no stale-check warning → ok."""
        snap = make_snap(last_check_date="not-a-date")
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "ok")
        assert total_deductions(result) == 0

    def test_no_db_takes_priority_over_old_date(self):
        """db_exists=False must produce no_db, not check_old, even if date is old."""
        snap = make_snap(db_exists=False, last_check_date="2000-01-01")
        result = check_file_integrity(snap, t=_t)
        assert "file_integrity.no_db" in finding_keys(result)
        assert "file_integrity.check_old" not in finding_keys(result)

    def test_unknown_tool_produces_ok(self):
        """A tool name other than aide/tripwire still works — ok, no deduction."""
        snap = make_snap(tool="samhain")
        result = check_file_integrity(snap, t=_t)
        assert has_level(result, "ok")
        assert total_deductions(result) == 0

    def test_unknown_tool_no_db_uses_fallback_cmd(self):
        """An unknown tool with no db falls back to the tripwire init cmd."""
        snap = make_snap(tool="samhain", db_exists=False, last_check_date=None)
        result = check_file_integrity(snap, t=_t)
        matches = [f for f in result.findings if f.key == "file_integrity.no_db"]
        assert matches
        assert "tripwire --init" in (matches[0].cmd or "")


# ---------------------------------------------------------------------------
# _check_age_days
# ---------------------------------------------------------------------------

class TestCheckAgeDays:
    def test_old_date_returns_large_number(self):
        age = _check_age_days("2000-01-01")
        assert age is not None
        assert age > 365 * 10

    def test_future_date_returns_zero(self):
        age = _check_age_days("2099-12-31")
        assert age == 0

    def test_invalid_format_returns_none(self):
        assert _check_age_days("not-a-date") is None

    def test_empty_string_returns_none(self):
        assert _check_age_days("") is None
