"""
Unit tests for bob.checks.hardening module.

All tests use HardeningSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_hardening.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.hardening import (
    HardeningSnapshot,
    check_hardening,
)
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snapshot(**overrides) -> HardeningSnapshot:
    """Return a fully-hardened HardeningSnapshot with optional overrides."""
    defaults = dict(
        rp_filter=1,
        accept_redirects=False,
        log_martians=True,
        icmp_echo_ignore_broadcasts=True,
        tcp_syncookies=1,
        accept_source_route=False,
        accept_redirects_v6=False,
        send_redirects=False,
        protected_hardlinks=True,
        protected_symlinks=True,
    )
    defaults.update(overrides)
    return HardeningSnapshot(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# Clean (fully hardened) system
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_deductions_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert not has_level(result, "warn")

    def test_no_alert_when_fully_hardened(self):
        result = check_hardening(make_snapshot(), t=_t)
        assert not has_level(result, "alert")


# ---------------------------------------------------------------------------
# rp_filter
# ---------------------------------------------------------------------------

class TestRpFilter:
    def test_ok_when_rp_filter_1(self):
        result = check_hardening(make_snapshot(rp_filter=1), t=_t)
        assert has_level(result, "ok")

    def test_info_when_rp_filter_2(self):
        """Loose mode (2) is sub-optimal — INFO, no deduction."""
        result = check_hardening(make_snapshot(rp_filter=2), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_rp_filter_2(self):
        result = check_hardening(make_snapshot(rp_filter=2), t=_t)
        rp_deductions = [d for d in result.deductions if "rp_filter" in d.reason]
        assert rp_deductions == []

    def test_warn_when_rp_filter_0(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_rp_filter_0(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        assert total_deductions(result) >= 1

    def test_deduction_key_rp_filter(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        reasons = [d.reason for d in result.deductions]
        assert "hardening.rp_filter_disabled" in reasons

    def test_rp_filter_cmd_is_persistent(self):
        result = check_hardening(make_snapshot(rp_filter=0), t=_t)
        f = next(f for f in result.findings if f.key == "hardening.rp_filter_disabled")
        assert "tee" in f.cmd and "sysctl.d" in f.cmd


# ---------------------------------------------------------------------------
# ICMP redirects
# ---------------------------------------------------------------------------

class TestAcceptRedirects:
    def test_ok_when_redirects_disabled(self):
        result = check_hardening(make_snapshot(accept_redirects=False), t=_t)
        assert has_level(result, "ok")

    def test_warn_when_redirects_enabled(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_redirects_enabled(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        assert total_deductions(result) >= 1

    def test_deduction_key_redirects(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        reasons = [d.reason for d in result.deductions]
        assert "hardening.redirects_enabled" in reasons

    def test_redirects_cmd_is_persistent(self):
        result = check_hardening(make_snapshot(accept_redirects=True), t=_t)
        f = next(f for f in result.findings if f.key == "hardening.redirects_enabled")
        assert "tee" in f.cmd and "sysctl.d" in f.cmd


# ---------------------------------------------------------------------------
# log_martians
# ---------------------------------------------------------------------------

class TestLogMartians:
    def test_ok_when_enabled(self):
        result = check_hardening(make_snapshot(log_martians=True), t=_t)
        assert has_level(result, "ok")

    def test_info_when_disabled(self):
        result = check_hardening(make_snapshot(log_martians=False), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_disabled(self):
        """log_martians is INFO-only."""
        result = check_hardening(make_snapshot(log_martians=False), t=_t)
        martian_deductions = [d for d in result.deductions if "martian" in d.reason]
        assert martian_deductions == []

    def test_log_martians_cmd_is_persistent(self):
        result = check_hardening(make_snapshot(log_martians=False), t=_t)
        f = next(f for f in result.findings if f.key == "hardening.log_martians_disabled")
        assert "tee" in f.cmd and "sysctl.d" in f.cmd


# ---------------------------------------------------------------------------
# ICMP broadcast echo
# ---------------------------------------------------------------------------

class TestIcmpBroadcast:
    def test_ok_when_ignored(self):
        result = check_hardening(make_snapshot(icmp_echo_ignore_broadcasts=True), t=_t)
        assert has_level(result, "ok")

    def test_info_when_not_ignored(self):
        result = check_hardening(make_snapshot(icmp_echo_ignore_broadcasts=False), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_not_ignored(self):
        """ICMP broadcast is INFO-only."""
        result = check_hardening(make_snapshot(icmp_echo_ignore_broadcasts=False), t=_t)
        broadcast_deductions = [d for d in result.deductions if "broadcast" in d.reason or "icmp" in d.reason.lower()]
        assert broadcast_deductions == []


# ---------------------------------------------------------------------------
# Cumulative deductions
# ---------------------------------------------------------------------------

class TestCumulativeDeductions:
    def test_two_issues_two_deductions(self):
        """rp_filter=0 + accept_redirects = 2 points."""
        snap = make_snapshot(
            rp_filter=0,
            accept_redirects=True,
        )
        result = check_hardening(snap, t=_t)
        assert total_deductions(result) == 2

    def test_no_deductions_for_info_only_fields(self):
        """log_martians + icmp_broadcast = 0 deductions."""
        snap = make_snapshot(
            log_martians=False,
            icmp_echo_ignore_broadcasts=False,
        )
        result = check_hardening(snap, t=_t)
        assert total_deductions(result) == 0

    def test_mixed_warn_and_info_coexist(self):
        """rp_filter=0 (WARN) + log_martians=False (INFO) must both appear."""
        snap = make_snapshot(
            rp_filter=0,
            log_martians=False,
        )
        result = check_hardening(snap, t=_t)
        assert has_level(result, "warn")
        assert has_level(result, "info")
        assert total_deductions(result) == 1

    def test_mixed_ok_info_warn_all_present(self):
        """Verify all three _levels can coexist in one result."""
        snap = make_snapshot(
            rp_filter=0,          # WARN
            log_martians=False,   # INFO
        )
        result = check_hardening(snap, t=_t)
        assert has_level(result, "ok")
        assert has_level(result, "info")
        assert has_level(result, "warn")


# ---------------------------------------------------------------------------
# tcp_syncookies
# ---------------------------------------------------------------------------

class TestTcpSyncookies:
    def test_syncookies_1_is_ok(self):
        result = check_hardening(make_snapshot(tcp_syncookies=1), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.tcp_syncookies_ok" in keys

    def test_syncookies_2_is_ok(self):
        result = check_hardening(make_snapshot(tcp_syncookies=2), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.tcp_syncookies_ok" in keys

    def test_syncookies_0_is_warn(self):
        result = check_hardening(make_snapshot(tcp_syncookies=0), t=_t)
        assert has_level(result, "warn")
        keys = [f.key for f in result.findings]
        assert "hardening.tcp_syncookies_disabled" in keys

    def test_syncookies_0_deduction(self):
        result = check_hardening(make_snapshot(tcp_syncookies=0), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.tcp_syncookies_disabled" in deduction_keys

    def test_syncookies_0_deduction_1pt(self):
        result = check_hardening(make_snapshot(tcp_syncookies=0), t=_t)
        pts = sum(d.points for d in result.deductions
                  if d.key == "hardening.tcp_syncookies_disabled")
        assert pts == 1

    def test_syncookies_ok_no_deduction(self):
        result = check_hardening(make_snapshot(tcp_syncookies=1), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.tcp_syncookies_disabled" not in deduction_keys


# ---------------------------------------------------------------------------
# accept_source_route
# ---------------------------------------------------------------------------

class TestAcceptSourceRoute:
    def test_source_route_disabled_is_ok(self):
        result = check_hardening(make_snapshot(accept_source_route=False), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.accept_source_route_ok" in keys

    def test_source_route_enabled_is_warn(self):
        result = check_hardening(make_snapshot(accept_source_route=True), t=_t)
        assert has_level(result, "warn")
        keys = [f.key for f in result.findings]
        assert "hardening.accept_source_route_enabled" in keys

    def test_source_route_enabled_deduction(self):
        result = check_hardening(make_snapshot(accept_source_route=True), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.accept_source_route_enabled" in deduction_keys

    def test_source_route_enabled_deduction_1pt(self):
        result = check_hardening(make_snapshot(accept_source_route=True), t=_t)
        pts = sum(d.points for d in result.deductions
                  if d.key == "hardening.accept_source_route_enabled")
        assert pts == 1

    def test_source_route_disabled_no_deduction(self):
        result = check_hardening(make_snapshot(accept_source_route=False), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.accept_source_route_enabled" not in deduction_keys


# ---------------------------------------------------------------------------
# accept_redirects_v6
# ---------------------------------------------------------------------------

class TestAcceptRedirectsV6:
    def test_v6_redirects_disabled_is_ok(self):
        result = check_hardening(make_snapshot(accept_redirects_v6=False), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.accept_redirects_v6_ok" in keys

    def test_v6_redirects_enabled_is_warn(self):
        result = check_hardening(make_snapshot(accept_redirects_v6=True), t=_t)
        assert has_level(result, "warn")
        keys = [f.key for f in result.findings]
        assert "hardening.accept_redirects_v6_enabled" in keys

    def test_v6_redirects_enabled_deduction(self):
        result = check_hardening(make_snapshot(accept_redirects_v6=True), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.accept_redirects_v6_enabled" in deduction_keys

    def test_v6_redirects_enabled_deduction_1pt(self):
        result = check_hardening(make_snapshot(accept_redirects_v6=True), t=_t)
        pts = sum(d.points for d in result.deductions
                  if d.key == "hardening.accept_redirects_v6_enabled")
        assert pts == 1

    def test_v6_redirects_disabled_no_deduction(self):
        result = check_hardening(make_snapshot(accept_redirects_v6=False), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.accept_redirects_v6_enabled" not in deduction_keys


# ---------------------------------------------------------------------------
# send_redirects
# ---------------------------------------------------------------------------

class TestSendRedirects:
    def test_send_redirects_disabled_is_ok(self):
        result = check_hardening(make_snapshot(send_redirects=False), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.send_redirects_ok" in keys

    def test_send_redirects_enabled_is_warn(self):
        result = check_hardening(make_snapshot(send_redirects=True), t=_t)
        assert has_level(result, "warn")
        keys = [f.key for f in result.findings]
        assert "hardening.send_redirects_enabled" in keys

    def test_send_redirects_enabled_deduction(self):
        result = check_hardening(make_snapshot(send_redirects=True), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.send_redirects_enabled" in deduction_keys

    def test_send_redirects_enabled_deduction_1pt(self):
        result = check_hardening(make_snapshot(send_redirects=True), t=_t)
        pts = sum(d.points for d in result.deductions
                  if d.key == "hardening.send_redirects_enabled")
        assert pts == 1

    def test_send_redirects_disabled_no_deduction(self):
        result = check_hardening(make_snapshot(send_redirects=False), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.send_redirects_enabled" not in deduction_keys


# ---------------------------------------------------------------------------
# fs.protected_hardlinks
# ---------------------------------------------------------------------------

class TestProtectedHardlinks:
    def test_enabled_is_ok(self):
        result = check_hardening(make_snapshot(protected_hardlinks=True), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.protected_hardlinks_ok" in keys

    def test_disabled_is_warn(self):
        result = check_hardening(make_snapshot(protected_hardlinks=False), t=_t)
        assert has_level(result, "warn")
        keys = [f.key for f in result.findings]
        assert "hardening.protected_hardlinks_disabled" in keys

    def test_disabled_deduction_1pt(self):
        result = check_hardening(make_snapshot(protected_hardlinks=False), t=_t)
        pts = sum(d.points for d in result.deductions
                  if d.key == "hardening.protected_hardlinks_disabled")
        assert pts == 1

    def test_enabled_no_deduction(self):
        result = check_hardening(make_snapshot(protected_hardlinks=True), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.protected_hardlinks_disabled" not in deduction_keys


# ---------------------------------------------------------------------------
# fs.protected_symlinks
# ---------------------------------------------------------------------------

class TestProtectedSymlinks:
    def test_enabled_is_ok(self):
        result = check_hardening(make_snapshot(protected_symlinks=True), t=_t)
        keys = [f.key for f in result.findings]
        assert "hardening.protected_symlinks_ok" in keys

    def test_disabled_is_warn(self):
        result = check_hardening(make_snapshot(protected_symlinks=False), t=_t)
        assert has_level(result, "warn")
        keys = [f.key for f in result.findings]
        assert "hardening.protected_symlinks_disabled" in keys

    def test_disabled_deduction_1pt(self):
        result = check_hardening(make_snapshot(protected_symlinks=False), t=_t)
        pts = sum(d.points for d in result.deductions
                  if d.key == "hardening.protected_symlinks_disabled")
        assert pts == 1

    def test_enabled_no_deduction(self):
        result = check_hardening(make_snapshot(protected_symlinks=True), t=_t)
        deduction_keys = [d.key for d in result.deductions]
        assert "hardening.protected_symlinks_disabled" not in deduction_keys

