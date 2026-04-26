"""
Unit tests for bob.checks.disk module.

All tests use DiskSnapshot instances built directly — no subprocess calls.
Check logic is exercised in isolation.

Run with: python -m pytest tests/test_disk.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.disk import (
    DiskSnapshot,
    SmartResult,
    PartitionInfo,
    check_disk,
    _parse_smart_attr,
    _WARN_USAGE_PCT,
    _INFO_USAGE_PCT,
    _ATTR_REALLOCATED_SECTORS,
    _ATTR_PENDING_SECTORS,
    _ATTR_UNCORRECTABLE,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(**kwargs) -> DiskSnapshot:
    defaults = dict(
        smartctl_available=True,
        smart_results=[],
        partitions=[],
    )
    defaults.update(kwargs)
    return DiskSnapshot(**defaults)


def make_smart(device="/dev/sda", **kwargs) -> SmartResult:
    defaults = dict(
        device=device,
        model="TestDisk 1TB",
        passed=True,
        virtual=False,
        reallocated_sectors=0,
        pending_sectors=0,
        uncorrectable_errors=0,
    )
    defaults.update(kwargs)
    return SmartResult(**defaults)


def make_part(mountpoint="/", used_pct=50, **kwargs) -> PartitionInfo:
    defaults = dict(
        mountpoint=mountpoint,
        device="/dev/sda1",
        size_gb=100.0,
        used_pct=used_pct,
    )
    defaults.update(kwargs)
    return PartitionInfo(**defaults)


def run(snap: DiskSnapshot):
    return check_disk(snap, t=_t)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def finding_keys(result):
    return [f.key for f in result.findings]


def deduction_points(result) -> int:
    return sum(d.points for d in result.deductions)


def deduction_keys(result):
    return [d.key for d in result.deductions]


# ---------------------------------------------------------------------------
# Snapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_smartctl_available_default_false(self):
        s = DiskSnapshot()
        assert not s.smartctl_available

    def test_smart_results_default_empty(self):
        s = DiskSnapshot()
        assert s.smart_results == []

    def test_partitions_default_empty(self):
        s = DiskSnapshot()
        assert s.partitions == []

    def test_smart_result_passed_default_none(self):
        sr = SmartResult(device="/dev/sda")
        assert sr.passed is None

    def test_smart_result_virtual_default_false(self):
        sr = SmartResult(device="/dev/sda")
        assert not sr.virtual

    def test_smart_result_reallocated_default_zero(self):
        sr = SmartResult(device="/dev/sda")
        assert sr.reallocated_sectors == 0


# ---------------------------------------------------------------------------
# smartctl missing
# ---------------------------------------------------------------------------

class TestSmartctlMissing:
    def test_smartctl_missing_produces_info(self):
        result = run(make_snap(smartctl_available=False))
        assert has_level(result, "info")

    def test_smartctl_missing_key(self):
        result = run(make_snap(smartctl_available=False))
        assert "disk.smartctl_missing" in finding_keys(result)

    def test_smartctl_missing_no_deduction(self):
        result = run(make_snap(smartctl_available=False))
        assert deduction_points(result) == 0

    def test_smartctl_missing_has_install_cmd(self):
        result = run(make_snap(smartctl_available=False))
        f = next(f for f in result.findings if f.key == "disk.smartctl_missing")
        assert "smartmontools" in f.cmd


# ---------------------------------------------------------------------------
# SMART — virtual / unsupported
# ---------------------------------------------------------------------------

class TestSmartVirtual:
    def test_virtual_device_produces_info(self):
        result = run(make_snap(smart_results=[make_smart(virtual=True, passed=None)]))
        assert "disk.smart_virtual" in finding_keys(result)

    def test_virtual_device_no_deduction(self):
        result = run(make_snap(smart_results=[make_smart(virtual=True, passed=None)]))
        assert deduction_points(result) == 0

    def test_virtual_device_skips_attribute_checks(self):
        """Virtual device with reallocated sectors still produces only virtual info."""
        sr = make_smart(virtual=True, passed=None, reallocated_sectors=10)
        result = run(make_snap(smart_results=[sr]))
        assert "disk.reallocated_sectors" not in finding_keys(result)


# ---------------------------------------------------------------------------
# SMART — unknown health
# ---------------------------------------------------------------------------

class TestSmartUnknown:
    def test_unknown_produces_info(self):
        result = run(make_snap(smart_results=[make_smart(passed=None)]))
        assert "disk.smart_unknown" in finding_keys(result)

    def test_unknown_no_deduction(self):
        result = run(make_snap(smart_results=[make_smart(passed=None)]))
        assert deduction_points(result) == 0


# ---------------------------------------------------------------------------
# SMART — passed
# ---------------------------------------------------------------------------

class TestSmartPassed:
    def test_passed_produces_ok(self):
        result = run(make_snap(smart_results=[make_smart(passed=True)]))
        assert "disk.smart_ok" in finding_keys(result)

    def test_passed_no_deduction(self):
        result = run(make_snap(smart_results=[make_smart(passed=True)]))
        assert deduction_points(result) == 0

    def test_all_clear_ok_when_no_issues(self):
        result = run(make_snap(smart_results=[make_smart(passed=True)]))
        assert "disk.ok" in finding_keys(result)


# ---------------------------------------------------------------------------
# SMART — failed
# ---------------------------------------------------------------------------

class TestSmartFailed:
    def test_failed_produces_alert(self):
        result = run(make_snap(smart_results=[make_smart(passed=False)]))
        assert has_level(result, "alert")

    def test_failed_key(self):
        result = run(make_snap(smart_results=[make_smart(passed=False)]))
        assert "disk.smart_failed" in finding_keys(result)

    def test_failed_deducts_3_points(self):
        result = run(make_snap(smart_results=[make_smart(passed=False)]))
        assert deduction_points(result) == 3

    def test_failed_deduction_key(self):
        result = run(make_snap(smart_results=[make_smart(passed=False)]))
        assert "disk.smart_failed" in deduction_keys(result)

    def test_failed_no_all_clear_ok(self):
        result = run(make_snap(smart_results=[make_smart(passed=False)]))
        assert "disk.ok" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Critical SMART attributes
# ---------------------------------------------------------------------------

class TestSmartAttributes:
    def test_reallocated_sectors_produces_warn(self):
        result = run(make_snap(smart_results=[make_smart(reallocated_sectors=5)]))
        assert "disk.reallocated_sectors" in finding_keys(result)

    def test_reallocated_sectors_deducts_1_point(self):
        result = run(make_snap(smart_results=[make_smart(reallocated_sectors=5)]))
        assert deduction_points(result) == 1

    def test_reallocated_zero_no_warn(self):
        result = run(make_snap(smart_results=[make_smart(reallocated_sectors=0)]))
        assert "disk.reallocated_sectors" not in finding_keys(result)

    def test_pending_sectors_produces_warn(self):
        result = run(make_snap(smart_results=[make_smart(pending_sectors=3)]))
        assert "disk.pending_sectors" in finding_keys(result)

    def test_pending_sectors_deducts_1_point(self):
        result = run(make_snap(smart_results=[make_smart(pending_sectors=3)]))
        assert deduction_points(result) == 1

    def test_pending_zero_no_warn(self):
        result = run(make_snap(smart_results=[make_smart(pending_sectors=0)]))
        assert "disk.pending_sectors" not in finding_keys(result)

    def test_uncorrectable_errors_produces_warn(self):
        result = run(make_snap(smart_results=[make_smart(uncorrectable_errors=1)]))
        assert "disk.uncorrectable_errors" in finding_keys(result)

    def test_uncorrectable_errors_deducts_1_point(self):
        result = run(make_snap(smart_results=[make_smart(uncorrectable_errors=1)]))
        assert deduction_points(result) == 1

    def test_uncorrectable_zero_no_warn(self):
        result = run(make_snap(smart_results=[make_smart(uncorrectable_errors=0)]))
        assert "disk.uncorrectable_errors" not in finding_keys(result)

    def test_all_three_attrs_three_points(self):
        sr = make_smart(
            reallocated_sectors=5,
            pending_sectors=2,
            uncorrectable_errors=1,
        )
        result = run(make_snap(smart_results=[sr]))
        assert deduction_points(result) == 3

    def test_failed_plus_reallocated_four_points(self):
        sr = make_smart(passed=False, reallocated_sectors=10)
        result = run(make_snap(smart_results=[sr]))
        assert deduction_points(result) == 4

    def test_deductions_are_cumulative(self):
        """SMART fail + all three critical attrs = 3+1+1+1 = 6 pts."""
        sr = make_smart(
            passed=False,
            reallocated_sectors=5,
            pending_sectors=2,
            uncorrectable_errors=1,
        )
        result = run(make_snap(smart_results=[sr]))
        assert deduction_points(result) == 6


# ---------------------------------------------------------------------------
# Multiple disks
# ---------------------------------------------------------------------------

class TestMultipleDisks:
    def test_two_passed_disks_two_ok_findings(self):
        snap = make_snap(smart_results=[
            make_smart("/dev/sda", passed=True),
            make_smart("/dev/sdb", passed=True),
        ])
        result = run(snap)
        ok_keys = [f.key for f in result.findings if f.key == "disk.smart_ok"]
        assert len(ok_keys) == 2

    def test_one_failed_one_ok_three_points(self):
        snap = make_snap(smart_results=[
            make_smart("/dev/sda", passed=False),
            make_smart("/dev/sdb", passed=True),
        ])
        assert deduction_points(run(snap)) == 3

    def test_two_failed_disks_six_points(self):
        snap = make_snap(smart_results=[
            make_smart("/dev/sda", passed=False),
            make_smart("/dev/sdb", passed=False),
        ])
        assert deduction_points(run(snap)) == 6


# ---------------------------------------------------------------------------
# Partition usage
# ---------------------------------------------------------------------------

class TestPartitionUsage:
    def test_partition_at_warn_threshold_produces_warn(self):
        snap = make_snap(partitions=[make_part(used_pct=_WARN_USAGE_PCT)])
        assert "disk.partition_critical" in finding_keys(run(snap))

    def test_partition_above_warn_threshold_produces_warn(self):
        snap = make_snap(partitions=[make_part(used_pct=_WARN_USAGE_PCT + 5)])
        assert "disk.partition_critical" in finding_keys(run(snap))

    def test_partition_critical_deducts_1_point(self):
        snap = make_snap(partitions=[make_part(used_pct=_WARN_USAGE_PCT)])
        assert deduction_points(run(snap)) == 1

    def test_partition_at_info_threshold_produces_info(self):
        snap = make_snap(partitions=[make_part(used_pct=_INFO_USAGE_PCT)])
        assert "disk.partition_warn" in finding_keys(run(snap))

    def test_partition_at_info_threshold_no_deduction(self):
        snap = make_snap(partitions=[make_part(used_pct=_INFO_USAGE_PCT)])
        assert deduction_points(run(snap)) == 0

    def test_partition_below_info_threshold_no_finding(self):
        snap = make_snap(partitions=[make_part(used_pct=_INFO_USAGE_PCT - 1)])
        result = run(snap)
        assert "disk.partition_warn" not in finding_keys(result)
        assert "disk.partition_critical" not in finding_keys(result)

    def test_two_critical_partitions_two_deductions(self):
        snap = make_snap(partitions=[
            make_part("/", used_pct=95),
            make_part("/home", used_pct=92),
        ])
        assert deduction_points(run(snap)) == 2


# ---------------------------------------------------------------------------
# All-clear logic
# ---------------------------------------------------------------------------

class TestAllClear:
    def test_ok_shown_with_no_issues_and_smart_available(self):
        snap = make_snap(
            smartctl_available=True,
            smart_results=[make_smart(passed=True)],
            partitions=[make_part(used_pct=10)],
        )
        assert "disk.ok" in finding_keys(run(snap))

    def test_ok_not_shown_without_smartctl(self):
        snap = make_snap(smartctl_available=False, smart_results=[], partitions=[])
        assert "disk.ok" not in finding_keys(run(snap))

    def test_ok_not_shown_when_issues_found(self):
        snap = make_snap(smart_results=[make_smart(passed=False)])
        assert "disk.ok" not in finding_keys(run(snap))

    def test_ok_not_shown_without_smart_results(self):
        """smartctl available but no disks detected — no ok."""
        snap = make_snap(smartctl_available=True, smart_results=[])
        assert "disk.ok" not in finding_keys(run(snap))


# ---------------------------------------------------------------------------
# _parse_smart_attr
# ---------------------------------------------------------------------------

class TestParseSmartAttr:
    _SAMPLE = (
        "  5 Reallocated_Sector_Ct   0x0032   100   100   000    Old_age   Always       -       3\n"
        "197 Current_Pending_Sector  0x0032   100   100   000    Old_age   Always       -       0\n"
        "198 Offline_Uncorrectable   0x0030   100   100   000    Old_age   Offline      -       1\n"
    )

    def test_parse_reallocated(self):
        assert _parse_smart_attr(self._SAMPLE, _ATTR_REALLOCATED_SECTORS) == 3

    def test_parse_pending(self):
        assert _parse_smart_attr(self._SAMPLE, _ATTR_PENDING_SECTORS) == 0

    def test_parse_uncorrectable(self):
        assert _parse_smart_attr(self._SAMPLE, _ATTR_UNCORRECTABLE) == 1

    def test_missing_attr_returns_zero(self):
        assert _parse_smart_attr(self._SAMPLE, 999) == 0

    def test_empty_output_returns_zero(self):
        assert _parse_smart_attr("", _ATTR_REALLOCATED_SECTORS) == 0

    def test_raw_with_parenthetical(self):
        """RAW_VALUE with space-separated parens → take index-9 token."""
        line = "  5 Reallocated_Sector_Ct   0x0032   100   100   000    Old_age   Always       -       7 (0 200 0)\n"
        assert _parse_smart_attr(line, _ATTR_REALLOCATED_SECTORS) == 7

    def test_nvme_style_no_crash(self):
        """NVMe output uses different format — should return 0 without raising."""
        nvme = "SMART overall-health self-assessment test result: PASSED\n"
        assert _parse_smart_attr(nvme, _ATTR_REALLOCATED_SECTORS) == 0

    def test_malformed_line_returns_zero(self):
        """Fewer than 10 fields → skip silently, return 0."""
        malformed = "  5 Reallocated_Sector_Ct   0x0032\n"
        assert _parse_smart_attr(malformed, _ATTR_REALLOCATED_SECTORS) == 0

    def test_non_integer_raw_value_returns_zero(self):
        """Non-numeric RAW_VALUE → return 0 without raising."""
        bad = "  5 Reallocated_Sector_Ct   0x0032   100   100   000    Old_age   Always       -       N/A\n"
        assert _parse_smart_attr(bad, _ATTR_REALLOCATED_SECTORS) == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestCmdType:
    def test_smart_failed_cmd_type_is_check(self):
        result = run(make_snap(smart_results=[make_smart(passed=False)]))
        f = next(f for f in result.findings if f.key == "disk.smart_failed")
        assert f.cmd_type == "check"

    def test_reallocated_sectors_cmd_type_is_check(self):
        result = run(make_snap(smart_results=[make_smart(reallocated_sectors=5)]))
        f = next(f for f in result.findings if f.key == "disk.reallocated_sectors")
        assert f.cmd_type == "check"

    def test_pending_sectors_cmd_type_is_check(self):
        result = run(make_snap(smart_results=[make_smart(pending_sectors=3)]))
        f = next(f for f in result.findings if f.key == "disk.pending_sectors")
        assert f.cmd_type == "check"

    def test_uncorrectable_errors_cmd_type_is_check(self):
        result = run(make_snap(smart_results=[make_smart(uncorrectable_errors=2)]))
        f = next(f for f in result.findings if f.key == "disk.uncorrectable_errors")
        assert f.cmd_type == "check"

    def test_partition_critical_cmd_type_is_check(self):
        result = run(make_snap(partitions=[make_part(used_pct=_WARN_USAGE_PCT)]))
        f = next(f for f in result.findings if f.key == "disk.partition_critical")
        assert f.cmd_type == "check"

    def test_smart_tips_cmd_type_is_check(self):
        result = run(make_snap(
            smartctl_available=True,
            smart_results=[make_smart(passed=True)],
        ))
        f = next(f for f in result.findings if f.key == "disk.smart_tips")
        assert f.cmd_type == "check"


class TestEdgeCases:
    def test_no_t_does_not_crash(self):
        result = check_disk(make_snap())
        assert isinstance(result.findings, list)

    def test_empty_snapshot_no_crash(self):
        result = run(DiskSnapshot())
        assert isinstance(result.findings, list)
        assert isinstance(result.deductions, list)

    def test_constants_sanity(self):
        assert 0 < _INFO_USAGE_PCT < _WARN_USAGE_PCT <= 100
        assert _ATTR_REALLOCATED_SECTORS == 5
        assert _ATTR_PENDING_SECTORS == 197
        assert _ATTR_UNCORRECTABLE == 198
