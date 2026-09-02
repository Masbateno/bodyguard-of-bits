"""
Unit tests for bob.checks.memory module.

All tests use MemorySnapshot instances built directly — no filesystem reads.
Check logic is exercised in isolation.

Run with: python -m pytest tests/test_memory.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.memory import (
    MemorySnapshot,
    check_memory,
    _SSD_SWAPPINESS_THRESHOLD,
    _RAM_FREE_THRESHOLD,
    _MIN_SWAP_USED_KB,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(**kwargs) -> MemorySnapshot:
    defaults = dict(
        mem_total_kb=8 * 1024 * 1024,       # 8 GB
        mem_available_kb=6 * 1024 * 1024,   # 6 GB free (75%)
        swap_total_kb=2 * 1024 * 1024,      # 2 GB swap
        swap_free_kb=2 * 1024 * 1024,       # all free (no swap in use)
        swappiness=60,
        swap_on_ssd=False,
        swap_devices=["/dev/sda5"],
    )
    defaults.update(kwargs)
    return MemorySnapshot(**defaults)


def run(snap: MemorySnapshot, **kwargs):
    return check_memory(snap, t=_t, **kwargs)


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
    def test_mem_total_default_zero(self):
        s = MemorySnapshot()
        assert s.mem_total_kb == 0

    def test_swappiness_default_is_unknown_not_sixty(self):
        """v0.15.5: the default used to be 60, which the SSD-wear branch then
        compared against a threshold of 30 — so an unreadable
        /proc/sys/vm/swappiness produced a WARN and a deduction for a value BOB
        never measured. Unknown is now unknown."""
        s = MemorySnapshot()
        assert s.swappiness is None

    def test_swap_on_ssd_default_false(self):
        s = MemorySnapshot()
        assert not s.swap_on_ssd

    def test_swap_devices_default_empty(self):
        s = MemorySnapshot()
        assert s.swap_devices == []


# ---------------------------------------------------------------------------
# No swap configured
# ---------------------------------------------------------------------------

class TestNoSwap:
    def test_no_swap_produces_info(self):
        result = run(make_snap(swap_total_kb=0))
        assert has_level(result, "info")

    def test_no_swap_key(self):
        result = run(make_snap(swap_total_kb=0))
        assert "memory.no_swap" in finding_keys(result)

    def test_no_swap_no_deduction(self):
        result = run(make_snap(swap_total_kb=0))
        assert deduction_points(result) == 0

    def test_no_swap_disables_all_other_checks(self):
        """No swap → only memory.no_swap; SSD wear and stats checks are skipped."""
        result = run(make_snap(swap_total_kb=0, swap_on_ssd=True, swappiness=100))
        assert finding_keys(result) == ["memory.no_swap"]


# ---------------------------------------------------------------------------
# SSD wear warning
# ---------------------------------------------------------------------------

class TestSsdWear:
    def test_ssd_high_swappiness_produces_warn(self):
        result = run(make_snap(swap_on_ssd=True, swappiness=_SSD_SWAPPINESS_THRESHOLD + 1))
        assert has_level(result, "warn")

    def test_ssd_high_swappiness_key(self):
        result = run(make_snap(swap_on_ssd=True, swappiness=_SSD_SWAPPINESS_THRESHOLD + 1))
        assert "memory.swappiness_ssd_wear" in finding_keys(result)

    def test_ssd_high_swappiness_deducts_1_point(self):
        result = run(make_snap(swap_on_ssd=True, swappiness=_SSD_SWAPPINESS_THRESHOLD + 1))
        assert deduction_points(result) == 1

    def test_ssd_high_swappiness_deduction_key(self):
        result = run(make_snap(swap_on_ssd=True, swappiness=_SSD_SWAPPINESS_THRESHOLD + 1))
        assert "memory.swappiness_ssd_wear" in deduction_keys(result)

    def test_ssd_at_threshold_no_warn(self):
        """Exactly at threshold — no warn (must be strictly above)."""
        result = run(make_snap(swap_on_ssd=True, swappiness=_SSD_SWAPPINESS_THRESHOLD))
        assert "memory.swappiness_ssd_wear" not in finding_keys(result)

    def test_hdd_high_swappiness_no_ssd_warn(self):
        result = run(make_snap(swap_on_ssd=False, swappiness=_SSD_SWAPPINESS_THRESHOLD + 1))
        assert "memory.swappiness_ssd_wear" not in finding_keys(result)

    def test_ssd_low_swappiness_no_warn(self):
        result = run(make_snap(swap_on_ssd=True, swappiness=10))
        assert "memory.swappiness_ssd_wear" not in finding_keys(result)

    def test_ssd_wear_takes_priority_over_unjustified(self):
        """SSD wear condition (if) fires before unjustified (elif) — only one warning."""
        total_kb = 8 * 1024 * 1024
        avail_kb = int(total_kb * 0.75)   # 75% RAM free → unjustified condition met
        swap_kb  = 2 * 1024 * 1024
        snap = make_snap(
            mem_total_kb=total_kb,
            mem_available_kb=avail_kb,
            swap_total_kb=swap_kb,
            swap_free_kb=swap_kb // 2,    # 50% used → unjustified condition met
            swap_on_ssd=True,
            swappiness=_SSD_SWAPPINESS_THRESHOLD + 1,
        )
        result = run(snap)
        assert "memory.swappiness_ssd_wear" in finding_keys(result)
        assert "memory.swappiness_unjustified" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Unjustified swap
# ---------------------------------------------------------------------------

class TestUnjustifiedSwap:
    def _unjustified_snap(self) -> MemorySnapshot:
        """RAM 75% free, swap 50% used — unjustified."""
        total_kb  = 8 * 1024 * 1024
        avail_kb  = int(total_kb * 0.75)      # 75% free
        swap_kb   = 2 * 1024 * 1024
        swap_free = swap_kb // 2              # 50% used
        return make_snap(
            mem_total_kb=total_kb,
            mem_available_kb=avail_kb,
            swap_total_kb=swap_kb,
            swap_free_kb=swap_free,
            swap_on_ssd=False,
            swappiness=60,
        )

    def test_unjustified_swap_produces_warn(self):
        result = run(self._unjustified_snap())
        assert "memory.swappiness_unjustified" in finding_keys(result)

    def test_unjustified_swap_no_deduction(self):
        """Unjustified swap is WARN but no score deduction (no SSD)."""
        result = run(self._unjustified_snap())
        assert deduction_points(result) == 0

    def test_justified_swap_no_unjustified_warn(self):
        """Swap used + RAM almost full → not unjustified."""
        total_kb  = 8 * 1024 * 1024
        avail_kb  = int(total_kb * 0.10)      # only 10% RAM free
        swap_kb   = 2 * 1024 * 1024
        snap = make_snap(
            mem_total_kb=total_kb,
            mem_available_kb=avail_kb,
            swap_total_kb=swap_kb,
            swap_free_kb=swap_kb // 2,
            swap_on_ssd=False,
        )
        result = run(snap)
        assert "memory.swappiness_unjustified" not in finding_keys(result)

    def test_tiny_swap_below_min_threshold_no_warn(self):
        """Swap used < _MIN_SWAP_USED_KB — considered noise, no warn."""
        total_kb = 8 * 1024 * 1024
        avail_kb = int(total_kb * 0.80)
        swap_kb  = 2 * 1024 * 1024
        snap = make_snap(
            mem_total_kb=total_kb,
            mem_available_kb=avail_kb,
            swap_total_kb=swap_kb,
            swap_free_kb=swap_kb - (_MIN_SWAP_USED_KB - 1),  # just below threshold
            swap_on_ssd=False,
        )
        result = run(snap)
        assert "memory.swappiness_unjustified" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Suboptimal swappiness (default, not SSD, no active swap)
# ---------------------------------------------------------------------------

class TestSuboptimalSwappiness:
    def test_default_swappiness_server_produces_info(self):
        result = run(make_snap(swappiness=60, swap_on_ssd=False), profile_name="server")
        assert "memory.swappiness_suboptimal" in finding_keys(result)

    def test_default_swappiness_desktop_produces_info(self):
        result = run(make_snap(swappiness=60, swap_on_ssd=False), profile_name="desktop")
        assert "memory.swappiness_suboptimal" in finding_keys(result)

    def test_already_optimal_server_produces_ok(self):
        result = run(make_snap(swappiness=1, swap_on_ssd=False), profile_name="server")
        assert "memory.swappiness_ok" in finding_keys(result)

    def test_already_optimal_desktop_produces_ok(self):
        result = run(make_snap(swappiness=10, swap_on_ssd=False), profile_name="desktop")
        assert "memory.swappiness_ok" in finding_keys(result)

    def test_suboptimal_no_deduction(self):
        result = run(make_snap(swappiness=60, swap_on_ssd=False))
        assert deduction_points(result) == 0

    def test_suboptimal_cmd_contains_recommended_value(self):
        """Suboptimal INFO finding must include the fix command with exact value."""
        result = run(make_snap(swappiness=60, swap_on_ssd=False), profile_name="server")
        f = next(f for f in result.findings if f.key == "memory.swappiness_suboptimal")
        assert "vm.swappiness=1" in (f.cmd or "")

    def test_suboptimal_cmd_uses_double_ampersand(self):
        """cmd must use && to chain commands (persists across reboots)."""
        result = run(make_snap(swappiness=60, swap_on_ssd=False), profile_name="server")
        f = next(f for f in result.findings if f.key == "memory.swappiness_suboptimal")
        assert "&&" in (f.cmd or "")


# ---------------------------------------------------------------------------
# Profile-aware recommended swappiness
# ---------------------------------------------------------------------------

class TestProfileAware:
    def test_server_recommended_swappiness_1(self):
        """Server profile cmd should recommend swappiness=1."""
        result = run(make_snap(swap_on_ssd=True, swappiness=60), profile_name="server")
        warn = next(f for f in result.findings if f.key == "memory.swappiness_ssd_wear")
        assert "vm.swappiness=1" in (warn.cmd or "")

    def test_desktop_recommended_swappiness_10(self):
        """Desktop profile cmd should recommend swappiness=10."""
        result = run(make_snap(swap_on_ssd=True, swappiness=60), profile_name="desktop")
        warn = next(f for f in result.findings if f.key == "memory.swappiness_ssd_wear")
        assert "vm.swappiness=10" in (warn.cmd or "")

    def test_server_and_desktop_differ(self):
        """The two profiles must not recommend the same value."""
        snap = make_snap(swap_on_ssd=True, swappiness=60)
        server_warn = next(
            f for f in run(snap, profile_name="server").findings
            if f.key == "memory.swappiness_ssd_wear"
        )
        desktop_warn = next(
            f for f in run(snap, profile_name="desktop").findings
            if f.key == "memory.swappiness_ssd_wear"
        )
        assert server_warn.cmd != desktop_warn.cmd


# ---------------------------------------------------------------------------
# Swap stats always present
# ---------------------------------------------------------------------------

class TestSwapStats:
    def test_swap_stats_always_shown_when_swap_present(self):
        result = run(make_snap())
        assert "memory.swap_stats" in finding_keys(result)

    def test_swap_stats_not_shown_when_no_swap(self):
        result = run(make_snap(swap_total_kb=0))
        assert "memory.swap_stats" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_zero_mem_total_no_crash(self):
        result = run(make_snap(mem_total_kb=0, mem_available_kb=0))
        assert isinstance(result.findings, list)

    def test_no_t_does_not_crash(self):
        result = check_memory(make_snap())
        assert isinstance(result.findings, list)

    def test_mem_available_exceeds_total_no_crash(self):
        """Incoherent system values (avail > total) must not crash."""
        snap = make_snap(mem_total_kb=1024, mem_available_kb=8 * 1024 * 1024)
        result = run(snap)
        assert isinstance(result.findings, list)

    def test_swap_free_exceeds_total_no_crash(self):
        """Incoherent swap values (free > total) must not crash."""
        snap = make_snap(swap_total_kb=1024, swap_free_kb=2 * 1024 * 1024)
        result = run(snap)
        assert isinstance(result.findings, list)

    def test_constants_sanity(self):
        assert 0 <= _SSD_SWAPPINESS_THRESHOLD <= 100
        assert 0.0 < _RAM_FREE_THRESHOLD < 1.0
        assert _MIN_SWAP_USED_KB > 0
