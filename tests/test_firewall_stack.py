"""
Unit tests for bob.checks.firewall_stack module.

All tests use FirewallStackSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_firewall_stack.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.firewall_stack import (
    FirewallStackSnapshot,
    _has_user_nft_rules,
    _parse_raw_accepts,
    _read_ip_forward,
    check_firewall_stack,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snapshot(**overrides) -> FirewallStackSnapshot:
    """Return a clean (no issues) FirewallStackSnapshot with optional overrides."""
    defaults = dict(
        input_raw_accepts=[],
        forward_raw_accepts=[],
        nftables_active=False,
        ip_forward=False,
        docker_present=False,
        wireguard_present=False,
        libvirt_present=False,
    )
    defaults.update(overrides)
    return FirewallStackSnapshot(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# check_firewall_stack — clean system
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_no_issues(self):
        result = check_firewall_stack(make_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_deductions_when_clean(self):
        result = check_firewall_stack(make_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_when_clean(self):
        result = check_firewall_stack(make_snapshot(), t=_t)
        assert not has_level(result, "warn")

    def test_no_alert_when_clean(self):
        result = check_firewall_stack(make_snapshot(), t=_t)
        assert not has_level(result, "alert")


# ---------------------------------------------------------------------------
# INPUT chain bypass detection
# ---------------------------------------------------------------------------

class TestInputChainBypass:
    def test_warn_on_raw_accept_in_input(self):
        snap = make_snapshot(input_raw_accepts=["ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0"])
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_on_raw_accept_in_input(self):
        snap = make_snapshot(input_raw_accepts=["ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0"])
        result = check_firewall_stack(snap, t=_t)
        assert total_deductions(result) >= 2

    def test_multiple_raw_accepts_multiple_warnings(self):
        snap = make_snapshot(input_raw_accepts=[
            "ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0",
            "ACCEPT udp -- 10.0.0.0/8 0.0.0.0/0",
        ])
        result = check_firewall_stack(snap, t=_t)
        warn_count = sum(1 for f in result.findings if f.level.value == "warn")
        assert warn_count == 2

    def test_rule_text_in_finding_message(self):
        """The rule text must be passed to the translation function."""
        received = {}

        def _t_capture(key, **kwargs):
            received.update(kwargs)
            return key

        rule = "ACCEPT tcp -- 192.168.1.0/24 0.0.0.0/0"
        snap = make_snapshot(input_raw_accepts=[rule])
        check_firewall_stack(snap, t=_t_capture)
        assert received.get("rule") == rule


# ---------------------------------------------------------------------------
# FORWARD chain — Docker/WireGuard suppression
# ---------------------------------------------------------------------------

class TestForwardChain:
    def test_warn_on_forward_accept_without_docker(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
            docker_present=False,
            wireguard_present=False,
        )
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "warn")

    def test_no_warn_on_forward_accept_with_docker(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
            docker_present=True,
        )
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")

    def test_info_on_forward_accept_with_docker(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
            docker_present=True,
        )
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "info")

    def test_no_warn_on_forward_accept_with_wireguard(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
            wireguard_present=True,
        )
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")

    def test_deduction_on_forward_accept_without_routing(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
        )
        result = check_firewall_stack(snap, t=_t)
        assert total_deductions(result) >= 1

    def test_no_deduction_on_forward_accept_with_docker(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
            docker_present=True,
        )
        result = check_firewall_stack(snap, t=_t)
        assert total_deductions(result) == 0

    def test_no_warn_on_forward_accept_with_libvirt(self):
        snap = make_snapshot(
            forward_raw_accepts=["ACCEPT all -- 0.0.0.0/0 0.0.0.0/0"],
            libvirt_present=True,
        )
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")


# ---------------------------------------------------------------------------
# nftables parallel detection
# ---------------------------------------------------------------------------

class TestNftables:
    def test_warn_when_nftables_active(self):
        snap = make_snapshot(nftables_active=True)
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_nftables_active(self):
        snap = make_snapshot(nftables_active=True)
        result = check_firewall_stack(snap, t=_t)
        assert total_deductions(result) >= 1

    def test_no_warn_when_nftables_inactive(self):
        snap = make_snapshot(nftables_active=False)
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")


# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------

class TestIPForwarding:
    def test_warn_when_ip_forward_no_routing(self):
        snap = make_snapshot(ip_forward=True, docker_present=False, wireguard_present=False)
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_ip_forward_no_routing(self):
        snap = make_snapshot(ip_forward=True)
        result = check_firewall_stack(snap, t=_t)
        assert total_deductions(result) >= 1

    def test_ok_when_ip_forward_with_docker(self):
        snap = make_snapshot(ip_forward=True, docker_present=True)
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "ok")

    def test_no_warn_when_ip_forward_with_docker(self):
        snap = make_snapshot(ip_forward=True, docker_present=True)
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")

    def test_ok_when_ip_forward_with_wireguard(self):
        snap = make_snapshot(ip_forward=True, wireguard_present=True)
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "ok")

    def test_ok_when_ip_forward_with_libvirt(self):
        snap = make_snapshot(ip_forward=True, libvirt_present=True)
        result = check_firewall_stack(snap, t=_t)
        assert has_level(result, "ok")

    def test_no_warn_when_ip_forward_with_libvirt(self):
        snap = make_snapshot(ip_forward=True, libvirt_present=True)
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")

    def test_no_warn_when_ip_forward_disabled(self):
        snap = make_snapshot(ip_forward=False)
        result = check_firewall_stack(snap, t=_t)
        assert not has_level(result, "warn")


# ---------------------------------------------------------------------------
# _parse_raw_accepts
# ---------------------------------------------------------------------------

class TestParseRawAccepts:
    CLEAN_INPUT = (
        "Chain INPUT (policy DROP)\n"
        "target     prot opt source               destination\n"
        "ufw-before-logging-input  all  --  0.0.0.0/0            0.0.0.0/0\n"
        "ufw-before-input  all  --  0.0.0.0/0            0.0.0.0/0\n"
        "ufw-after-input   all  --  0.0.0.0/0            0.0.0.0/0\n"
    )

    BYPASS_INPUT = (
        "Chain INPUT (policy DROP)\n"
        "target     prot opt source               destination\n"
        "ufw-before-input  all  --  0.0.0.0/0            0.0.0.0/0\n"
        "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0\n"
    )

    def test_no_accepts_from_clean_chain(self):
        assert _parse_raw_accepts(self.CLEAN_INPUT) == []

    def test_detects_raw_accept(self):
        result = _parse_raw_accepts(self.BYPASS_INPUT)
        assert len(result) == 1

    def test_raw_accept_content(self):
        result = _parse_raw_accepts(self.BYPASS_INPUT)
        assert "ACCEPT" in result[0]

    def test_empty_string_returns_empty(self):
        assert _parse_raw_accepts("") == []

    def test_skips_ufw_jumps(self):
        output = (
            "Chain INPUT (policy DROP)\n"
            "target     prot opt source               destination\n"
            "ufw-user-input  all  --  0.0.0.0/0  0.0.0.0/0\n"
        )
        assert _parse_raw_accepts(output) == []


# ---------------------------------------------------------------------------
# _has_user_nft_rules
# ---------------------------------------------------------------------------

class TestHasUserNftRules:
    def test_empty_returns_false(self):
        assert not _has_user_nft_rules("")

    def test_ufw_table_only_returns_false(self):
        nft_output = "table ip ufw6 {\n  chain user-input {\n  }\n}\n"
        assert not _has_user_nft_rules(nft_output)

    def test_non_ufw_table_returns_true(self):
        nft_output = "table inet my_firewall {\n  chain input {\n  }\n}\n"
        assert _has_user_nft_rules(nft_output)

    def test_mixed_tables_returns_true(self):
        nft_output = (
            "table ip ufw6 {\n}\n"
            "table inet custom_rules {\n}\n"
        )
        assert _has_user_nft_rules(nft_output)

    def test_whitespace_only_returns_false(self):
        assert not _has_user_nft_rules("   \n  \n")

    def test_iptables_compat_tables_ignored(self):
        """filter/nat/mangle created by iptables-nft must not trigger the warning."""
        nft_output = (
            "table ip filter {\n}\n"
            "table ip nat {\n}\n"
            "table ip mangle {\n}\n"
        )
        assert not _has_user_nft_rules(nft_output)

    def test_raw_security_compat_tables_ignored(self):
        nft_output = (
            "table ip raw {\n}\n"
            "table ip security {\n}\n"
        )
        assert not _has_user_nft_rules(nft_output)
