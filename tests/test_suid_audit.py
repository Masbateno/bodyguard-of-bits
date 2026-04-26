"""
Tests for checks/suid_audit.py — CHECK 37.

Covers:
  - Scan skipped (timeout / OSError)
  - All-safe baseline (no unexpected SUID/SGID)
  - Unexpected SUID: WARN + deduction
  - Unexpected SGID: INFO, no deduction
  - Whitelist matching by basename
  - Truncation at 10 paths with "+N more" suffix
  - Deduction invariants
  - _is_root_owned helper
  - SuidSnapshot defaults
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from bob.checks.suid_audit import (
    SuidSnapshot,
    _is_root_owned,
    check_suid_audit,
)
from bob.scoring import FindingLevel
from tests.helpers import _keys, _deduction_points


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(**kwargs) -> SuidSnapshot:
    """Build a snapshot with all-safe defaults, overriding with kwargs."""
    defaults = dict(
        suid_paths=[],
        sgid_paths=[],
        unexpected_suid=[],
        unexpected_sgid=[],
        scan_skipped=False,
    )
    defaults.update(kwargs)
    return SuidSnapshot(**defaults)


def _level(result, key: str) -> FindingLevel:
    for f in result.findings:
        if f.key == key:
            return f.level
    raise KeyError(key)


def _finding(result, key: str):
    for f in result.findings:
        if f.key == key:
            return f
    raise KeyError(key)


def _t_format(key: str, **kwargs) -> str:
    """Minimal t() that returns '{key}: k=v ...' for testing formatted output."""
    parts = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    return f"{key}: {parts}" if parts else key


# ---------------------------------------------------------------------------
# Scan skipped
# ---------------------------------------------------------------------------

class TestScanSkipped:
    def test_scan_skipped_returns_info(self):
        result = check_suid_audit(_snap(scan_skipped=True))
        assert _level(result, "suid_audit.scan_skipped") == FindingLevel.INFO

    def test_scan_skipped_no_deduction(self):
        result = check_suid_audit(_snap(scan_skipped=True))
        assert _deduction_points(result) == 0

    def test_scan_skipped_only_one_finding(self):
        result = check_suid_audit(_snap(scan_skipped=True))
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# All-safe baseline
# ---------------------------------------------------------------------------

class TestAllSafe:
    def test_ok_finding_when_no_unexpected(self):
        result = check_suid_audit(_snap(
            suid_paths=["/usr/bin/sudo"],
            sgid_paths=["/usr/bin/wall"],
        ))
        assert _level(result, "suid_audit.ok") == FindingLevel.OK

    def test_no_deductions_when_all_safe(self):
        result = check_suid_audit(_snap())
        assert _deduction_points(result) == 0

    def test_ok_message_contains_counts(self):
        result = check_suid_audit(_snap(
            suid_paths=["/usr/bin/sudo", "/usr/bin/su"],
            sgid_paths=["/usr/bin/wall"],
        ), t=_t_format)
        f = _finding(result, "suid_audit.ok")
        assert "2" in (f.message or "")   # suid_count=2
        assert "1" in (f.message or "")   # sgid_count=1


# ---------------------------------------------------------------------------
# Unexpected SUID
# ---------------------------------------------------------------------------

class TestUnexpectedSuid:
    def test_unexpected_suid_is_warn(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        assert _level(result, "suid_audit.unexpected_suid") == FindingLevel.WARN

    def test_unexpected_suid_deducts_1(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        assert _deduction_points(result) == 1

    def test_unexpected_suid_deducts_1_regardless_of_count(self):
        """Multiple unexpected SUID binaries still only −1 pt."""
        result = check_suid_audit(_snap(
            unexpected_suid=[f"/opt/bin{i}" for i in range(5)],
        ))
        assert _deduction_points(result) == 1

    def test_unexpected_suid_deduction_key(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        assert any(d.key == "suid_audit.unexpected_suid" for d in result.deductions)

    def test_unexpected_suid_path_in_cmd(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "/opt/custom/backdoor" in (f.cmd or "")

    def test_unexpected_suid_cmd_type_check(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        f = _finding(result, "suid_audit.unexpected_suid")
        assert f.cmd_type == "check"

    def test_unexpected_suid_cmd_not_none(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/custom/backdoor"],
        ))
        f = _finding(result, "suid_audit.unexpected_suid")
        assert f.cmd is not None

    def test_unexpected_suid_cmd_limited_to_5(self):
        paths = [f"/opt/bin{i}" for i in range(10)]
        result = check_suid_audit(_snap(unexpected_suid=paths))
        f = _finding(result, "suid_audit.unexpected_suid")
        # at most 5 sub-commands joined by &&
        assert (f.cmd or "").count(" && ") <= 4

    def test_unexpected_suid_cmd_quotes_paths_with_spaces(self):
        result = check_suid_audit(_snap(unexpected_suid=["/opt/my bin/evil"]))
        f = _finding(result, "suid_audit.unexpected_suid")
        # shlex.quote wraps paths containing spaces in single quotes
        assert "'/opt/my bin/evil'" in (f.cmd or "")


# ---------------------------------------------------------------------------
# Unexpected SGID
# ---------------------------------------------------------------------------

class TestUnexpectedSgid:
    def test_unexpected_sgid_is_info(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        assert _level(result, "suid_audit.unexpected_sgid") == FindingLevel.INFO

    def test_unexpected_sgid_no_deduction(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        assert _deduction_points(result) == 0

    def test_unexpected_sgid_path_in_cmd(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert "/opt/custom/grpbin" in (f.cmd or "")

    def test_unexpected_sgid_cmd_type_check(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert f.cmd_type == "check"

    def test_unexpected_sgid_detail_present(self):
        result = check_suid_audit(_snap(
            unexpected_sgid=["/opt/custom/grpbin"],
        ))
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert f.detail is not None


# ---------------------------------------------------------------------------
# Combined: unexpected SUID + unexpected SGID
# ---------------------------------------------------------------------------

class TestCombined:
    def test_both_unexpected_findings_present(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/backdoor"],
            unexpected_sgid=["/opt/grpbin"],
        ))
        assert "suid_audit.unexpected_suid" in _keys(result)
        assert "suid_audit.unexpected_sgid" in _keys(result)

    def test_combined_deduction_still_1(self):
        result = check_suid_audit(_snap(
            unexpected_suid=["/opt/backdoor"],
            unexpected_sgid=["/opt/grpbin"],
        ))
        assert _deduction_points(result) == 1

    def test_no_ok_finding_when_unexpected_suid(self):
        result = check_suid_audit(_snap(unexpected_suid=["/opt/backdoor"]))
        assert "suid_audit.ok" not in _keys(result)

    def test_ok_present_when_suid_clean_despite_unexpected_sgid(self):
        """Design: OK refers only to SUID safety — unexpected SGID (INFO-only) does not suppress it."""
        result = check_suid_audit(_snap(
            unexpected_suid=[],
            unexpected_sgid=["/usr/local/bin/suspicious"],
        ))
        assert "suid_audit.ok" in _keys(result)
        assert "suid_audit.unexpected_sgid" in _keys(result)

    def test_ok_message_says_suid_safe_not_sgid(self):
        """The OK message explicitly refers to SUID, not SGID — accurate when SGID has issues."""
        from bob import i18n
        i18n.init(lang="en")
        result = check_suid_audit(_snap(unexpected_sgid=["/tmp/suspicious"]), t=i18n.t)
        ok_finding = next(f for f in result.findings if f.key == "suid_audit.ok")
        assert "SUID" in ok_finding.message


# ---------------------------------------------------------------------------
# Path ordering in cmd
# ---------------------------------------------------------------------------

class TestCmdPathOrder:
    def test_suid_cmd_reflects_snapshot_order(self):
        """The stat cmd lists paths in the order they appear in unexpected_suid[:5]."""
        paths = ["/a/bin", "/b/bin", "/c/bin"]
        result = check_suid_audit(_snap(unexpected_suid=paths))
        f = next(f for f in result.findings if f.key == "suid_audit.unexpected_suid")
        cmd = f.cmd or ""
        assert cmd.index("/a/bin") < cmd.index("/b/bin") < cmd.index("/c/bin")

    def test_sgid_cmd_reflects_snapshot_order(self):
        paths = ["/x/lib", "/y/lib", "/z/lib"]
        result = check_suid_audit(_snap(unexpected_sgid=paths))
        f = next(f for f in result.findings if f.key == "suid_audit.unexpected_sgid")
        cmd = f.cmd or ""
        assert cmd.index("/x/lib") < cmd.index("/y/lib") < cmd.index("/z/lib")

    def test_cmd_limited_to_5_when_more_than_5_suid(self):
        """Existing: cmd capped at 5 paths."""
        paths = [f"/opt/bad{i}" for i in range(8)]
        result = check_suid_audit(_snap(unexpected_suid=paths))
        f = next(f for f in result.findings if f.key == "suid_audit.unexpected_suid")
        # Only first 5 paths in cmd
        assert "/opt/bad5" not in (f.cmd or "")
        assert "/opt/bad4" in (f.cmd or "")


# ---------------------------------------------------------------------------
# Path truncation (10+ unexpected)
# ---------------------------------------------------------------------------

class TestTruncation:
    def _make_paths(self, n: int) -> list[str]:
        return [f"/opt/bin{i}" for i in range(n)]

    def test_exactly_10_no_suffix(self):
        paths = self._make_paths(10)
        result = check_suid_audit(_snap(unexpected_suid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "+0 more" not in (f.message or "")
        assert "more" not in (f.message or "")

    def test_11_shows_plus_1_more(self):
        paths = self._make_paths(11)
        result = check_suid_audit(_snap(unexpected_suid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "+1 more" in (f.message or "")

    def test_20_shows_plus_10_more(self):
        paths = self._make_paths(20)
        result = check_suid_audit(_snap(unexpected_suid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_suid")
        assert "+10 more" in (f.message or "")

    def test_sgid_truncation_11(self):
        paths = self._make_paths(11)
        result = check_suid_audit(_snap(unexpected_sgid=paths), t=_t_format)
        f = _finding(result, "suid_audit.unexpected_sgid")
        assert "+1 more" in (f.message or "")


# ---------------------------------------------------------------------------
# Whitelist: basename matching
# ---------------------------------------------------------------------------

class TestWhitelistBasename:
    def test_known_suid_in_different_dir_not_unexpected(self):
        """sudo in /usr/local/bin still whitelisted by basename."""
        snap = SuidSnapshot(
            suid_paths=["/usr/local/bin/sudo"],
            sgid_paths=[],
            unexpected_suid=[],   # whitelist already applied in from_system()
            unexpected_sgid=[],
            scan_skipped=False,
        )
        result = check_suid_audit(snap)
        assert _level(result, "suid_audit.ok") == FindingLevel.OK

    def test_unknown_basename_is_unexpected(self):
        snap = SuidSnapshot(
            suid_paths=["/opt/my_custom_tool"],
            sgid_paths=[],
            unexpected_suid=["/opt/my_custom_tool"],
            unexpected_sgid=[],
            scan_skipped=False,
        )
        result = check_suid_audit(snap)
        assert _level(result, "suid_audit.unexpected_suid") == FindingLevel.WARN


# ---------------------------------------------------------------------------
# SuidSnapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_default_suid_paths_empty(self):
        assert SuidSnapshot().suid_paths == []

    def test_default_sgid_paths_empty(self):
        assert SuidSnapshot().sgid_paths == []

    def test_default_unexpected_suid_empty(self):
        assert SuidSnapshot().unexpected_suid == []

    def test_default_unexpected_sgid_empty(self):
        assert SuidSnapshot().unexpected_sgid == []

    def test_default_scan_skipped_false(self):
        assert not SuidSnapshot().scan_skipped


# ---------------------------------------------------------------------------
# _is_root_owned helper
# ---------------------------------------------------------------------------

class TestIsRootOwned:
    def test_nonexistent_path_returns_false(self):
        assert not _is_root_owned("/nonexistent/path/that/cannot/exist")

    def test_current_user_file_not_root_owned_when_not_root(self):
        if os.getuid() == 0:
            pytest.skip("Running as root — all new files are root-owned")
        with tempfile.NamedTemporaryFile() as f:
            assert not _is_root_owned(f.name)
