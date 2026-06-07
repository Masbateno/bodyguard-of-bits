"""
Unit tests for bob.checks.iptables_nftables (CHECK 46).

All tests build IptablesNftSnapshot directly — no subprocess calls.

Run with: python3 -m pytest tests/test_iptables_nftables.py -v
"""

from __future__ import annotations

import pytest

from bob.checks.iptables_nftables import (
    IptablesNftSnapshot,
    _ipt_has_conntrack,
    _ipt_has_loopback,
    _ipt_policy,
    _nft_has_conntrack,
    _nft_has_loopback,
    _nft_policy,
    check_iptables_nftables,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(**kwargs) -> IptablesNftSnapshot:
    defaults = dict(
        backend="iptables",
        input_policy="DROP",
        forward_policy="DROP",
        has_loopback_rule=True,
        has_conntrack_rule=True,
    )
    defaults.update(kwargs)
    return IptablesNftSnapshot(**defaults)


# ---------------------------------------------------------------------------
# Parser — iptables
# ---------------------------------------------------------------------------

_IPT_RULES_DROP = (
    "-P INPUT DROP\n"
    "-P FORWARD DROP\n"
    "-P OUTPUT ACCEPT\n"
    "-A INPUT -i lo -j ACCEPT\n"
    "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
)

_IPT_RULES_ACCEPT = (
    "-P INPUT ACCEPT\n"
    "-P FORWARD ACCEPT\n"
    "-P OUTPUT ACCEPT\n"
)

_IPT_RULES_MINIMAL = (
    "-P INPUT DROP\n"
    "-P FORWARD DROP\n"
    "-P OUTPUT ACCEPT\n"
)


class TestIptableParsers:
    def test_policy_drop(self):
        assert _ipt_policy(_IPT_RULES_DROP, "INPUT") == "DROP"

    def test_policy_accept(self):
        assert _ipt_policy(_IPT_RULES_ACCEPT, "INPUT") == "ACCEPT"

    def test_policy_forward_drop(self):
        assert _ipt_policy(_IPT_RULES_DROP, "FORWARD") == "DROP"

    def test_policy_unknown_when_missing(self):
        assert _ipt_policy("", "INPUT") == "unknown"

    def test_has_loopback_true(self):
        assert _ipt_has_loopback(_IPT_RULES_DROP) is True

    def test_has_loopback_false(self):
        assert _ipt_has_loopback(_IPT_RULES_MINIMAL) is False

    def test_has_conntrack_ctstate(self):
        assert _ipt_has_conntrack(_IPT_RULES_DROP) is True

    def test_has_conntrack_state_form(self):
        rules = "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
        assert _ipt_has_conntrack(rules) is True

    def test_has_conntrack_false(self):
        assert _ipt_has_conntrack(_IPT_RULES_MINIMAL) is False

    def test_has_conntrack_drop_action_is_false(self):
        """--ctstate ESTABLISHED with -j DROP must not be mistaken for a valid conntrack rule."""
        rules = "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j DROP\n"
        assert _ipt_has_conntrack(rules) is False

    def test_has_conntrack_state_form_without_accept_is_false(self):
        rules = "-A INPUT -m state --state ESTABLISHED,RELATED -j REJECT\n"
        assert _ipt_has_conntrack(rules) is False


# ---------------------------------------------------------------------------
# Parser — nftables
# ---------------------------------------------------------------------------

_NFT_RULESET_DROP = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
"""

_NFT_RULESET_ACCEPT = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
}
"""

_NFT_RULESET_MINIMAL = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
    }
}
"""


class TestNftParsers:
    def test_policy_drop(self):
        assert _nft_policy(_NFT_RULESET_DROP, "input") == "DROP"

    def test_policy_accept(self):
        assert _nft_policy(_NFT_RULESET_ACCEPT, "input") == "ACCEPT"

    def test_policy_forward_drop(self):
        assert _nft_policy(_NFT_RULESET_DROP, "forward") == "DROP"

    def test_policy_unknown_when_absent(self):
        assert _nft_policy("", "input") == "unknown"

    def test_has_loopback_true(self):
        assert _nft_has_loopback(_NFT_RULESET_DROP) is True

    def test_has_loopback_false(self):
        assert _nft_has_loopback(_NFT_RULESET_MINIMAL) is False

    def test_has_conntrack_true(self):
        assert _nft_has_conntrack(_NFT_RULESET_DROP) is True

    def test_has_conntrack_false(self):
        assert _nft_has_conntrack(_NFT_RULESET_MINIMAL) is False

    def test_has_conntrack_drop_action_is_false(self):
        """ct state established drop must not be mistaken for a valid conntrack rule."""
        rules = "ct state established,related drop\n"
        assert _nft_has_conntrack(rules) is False


# ---------------------------------------------------------------------------
# check_iptables_nftables — no backend
# ---------------------------------------------------------------------------

class TestNoBackend:
    def test_warn_when_no_backend(self):
        result = check_iptables_nftables(_snap(backend="none"), t=_t)
        assert "warn" in _levels(result)

    def test_deduction_3_when_no_backend(self):
        result = check_iptables_nftables(_snap(backend="none"), t=_t)
        assert _deduction_points(result) == 3

    def test_key_no_backend(self):
        result = check_iptables_nftables(_snap(backend="none"), t=_t)
        assert "firewall_iptables.no_backend" in _deduction_keys(result)


# ---------------------------------------------------------------------------
# check_iptables_nftables — INPUT policy
# ---------------------------------------------------------------------------

class TestInputPolicy:
    def test_alert_when_input_accept(self):
        result = check_iptables_nftables(_snap(input_policy="ACCEPT"), t=_t)
        assert "alert" in _levels(result)

    def test_deduction_3_when_input_accept(self):
        result = check_iptables_nftables(_snap(input_policy="ACCEPT"), t=_t)
        assert _deduction_points(result) == 3

    def test_ok_when_input_drop(self):
        result = check_iptables_nftables(_snap(input_policy="DROP"), t=_t)
        assert "ok" in _levels(result)

    def test_ok_when_input_reject(self):
        result = check_iptables_nftables(_snap(input_policy="REJECT"), t=_t)
        assert "ok" in _levels(result)

    def test_no_deduction_when_input_drop(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", forward_policy="DROP"), t=_t
        )
        assert _deduction_points(result) == 0

    def test_info_when_input_unknown(self):
        result = check_iptables_nftables(_snap(input_policy="unknown"), t=_t)
        assert "info" in _levels(result)

    def test_backend_info_always_present(self):
        result = check_iptables_nftables(_snap(), t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.backend_detected" in keys

    def test_input_accept_key(self):
        result = check_iptables_nftables(_snap(input_policy="ACCEPT"), t=_t)
        assert "firewall_iptables.input_accept" in _deduction_keys(result)


# ---------------------------------------------------------------------------
# check_iptables_nftables — loopback / conntrack sub-checks
# ---------------------------------------------------------------------------

class TestSubChecks:
    def test_warn_when_no_loopback(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", has_loopback_rule=False), t=_t
        )
        assert "warn" in _levels(result)

    def test_deduction_1_no_loopback(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", has_loopback_rule=False,
                  has_conntrack_rule=True, forward_policy="DROP"), t=_t
        )
        assert _deduction_points(result) == 1

    def test_warn_when_no_conntrack(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", has_conntrack_rule=False), t=_t
        )
        assert "warn" in _levels(result)

    def test_deduction_1_no_conntrack(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", has_loopback_rule=True,
                  has_conntrack_rule=False, forward_policy="DROP"), t=_t
        )
        assert _deduction_points(result) == 1

    def test_no_loopback_check_when_input_accept(self):
        """Sub-checks are skipped when INPUT=ACCEPT (policy itself is the problem)."""
        result = check_iptables_nftables(
            _snap(input_policy="ACCEPT", has_loopback_rule=False,
                  has_conntrack_rule=False), t=_t
        )
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.no_loopback" not in keys
        assert "firewall_iptables.no_conntrack" not in keys

    def test_loopback_key(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", has_loopback_rule=False), t=_t
        )
        assert "firewall_iptables.no_loopback" in _deduction_keys(result)

    def test_conntrack_key(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", has_conntrack_rule=False), t=_t
        )
        assert "firewall_iptables.no_conntrack" in _deduction_keys(result)


# ---------------------------------------------------------------------------
# check_iptables_nftables — FORWARD policy
# ---------------------------------------------------------------------------

class TestForwardPolicy:
    def test_warn_when_forward_accept(self):
        result = check_iptables_nftables(_snap(forward_policy="ACCEPT"), t=_t)
        assert "warn" in _levels(result)

    def test_deduction_1_forward_accept(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", forward_policy="ACCEPT"), t=_t
        )
        assert _deduction_points(result) == 1

    def test_no_warn_when_forward_drop(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", forward_policy="DROP"), t=_t
        )
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.forward_accept" not in keys

    def test_forward_accept_key(self):
        result = check_iptables_nftables(_snap(forward_policy="ACCEPT"), t=_t)
        assert "firewall_iptables.forward_accept" in _deduction_keys(result)

    def test_forward_unknown_emits_info(self):
        result = check_iptables_nftables(_snap(forward_policy="unknown"), t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.forward_unknown" in keys

    def test_forward_unknown_is_info_level(self):
        result = check_iptables_nftables(_snap(forward_policy="unknown"), t=_t)
        f = next(f for f in result.findings if f.key == "firewall_iptables.forward_unknown")
        assert f.level == FindingLevel.INFO

    def test_input_accept_and_forward_accept_both_flagged(self):
        """FORWARD check is unconditional — both findings coexist when both policies are ACCEPT."""
        result = check_iptables_nftables(
            _snap(input_policy="ACCEPT", forward_policy="ACCEPT"), t=_t
        )
        keys = _deduction_keys(result)
        assert "firewall_iptables.input_accept" in keys
        assert "firewall_iptables.forward_accept" in keys

    def test_ok_when_forward_drop(self):
        result = check_iptables_nftables(_snap(forward_policy="DROP"), t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.forward_ok" in keys

    def test_ok_when_forward_reject(self):
        result = check_iptables_nftables(_snap(forward_policy="REJECT"), t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.forward_ok" in keys

    def test_forward_ok_is_ok_level(self):
        result = check_iptables_nftables(_snap(forward_policy="DROP"), t=_t)
        f = next(f for f in result.findings if f.key == "firewall_iptables.forward_ok")
        assert f.level == FindingLevel.OK

    def test_forward_drop_no_deduction(self):
        result = check_iptables_nftables(
            _snap(input_policy="DROP", forward_policy="DROP"), t=_t
        )
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# check_iptables_nftables — nftables backend cmd variants
# ---------------------------------------------------------------------------

class TestNftablesCmd:
    def test_input_accept_cmd_nftables(self):
        result = check_iptables_nftables(
            _snap(backend="nftables", input_policy="ACCEPT"), t=_t
        )
        f = next(f for f in result.findings if f.key == "firewall_iptables.input_accept")
        assert (f.cmd or "").startswith("sudo nft ")

    def test_input_accept_cmd_iptables(self):
        result = check_iptables_nftables(
            _snap(backend="iptables", input_policy="ACCEPT"), t=_t
        )
        f = next(f for f in result.findings if f.key == "firewall_iptables.input_accept")
        assert (f.cmd or "").startswith("sudo iptables ")

    def test_no_loopback_cmd_nftables(self):
        result = check_iptables_nftables(
            _snap(backend="nftables", input_policy="DROP",
                  has_loopback_rule=False), t=_t
        )
        f = next(f for f in result.findings if f.key == "firewall_iptables.no_loopback")
        assert (f.cmd or "").startswith("sudo nft ")

    def test_forward_accept_cmd_nftables_uses_chain_not_add(self):
        """nft chain (not nft add chain) — idempotent on existing chains."""
        result = check_iptables_nftables(
            _snap(backend="nftables", forward_policy="ACCEPT"), t=_t
        )
        f = next(f for f in result.findings if f.key == "firewall_iptables.forward_accept")
        assert "nft add chain" not in (f.cmd or "")
        assert (f.cmd or "").startswith("sudo nft chain ")


# ---------------------------------------------------------------------------
# check_iptables_nftables — ufw_installed context message
# ---------------------------------------------------------------------------

class TestUfwInactiveContext:
    def test_context_info_when_ufw_installed(self):
        result = check_iptables_nftables(_snap(), ufw_installed=True, t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.ufw_inactive_context" in keys

    def test_no_context_info_when_ufw_not_installed(self):
        result = check_iptables_nftables(_snap(), ufw_installed=False, t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.ufw_inactive_context" not in keys

    def test_context_info_is_info_level(self):
        result = check_iptables_nftables(_snap(), ufw_installed=True, t=_t)
        f = next(f for f in result.findings if f.key == "firewall_iptables.ufw_inactive_context")
        assert f.level == FindingLevel.INFO

    def test_context_info_not_emitted_for_no_backend(self):
        result = check_iptables_nftables(_snap(backend="none"), ufw_installed=True, t=_t)
        keys = [f.key for f in result.findings]
        assert "firewall_iptables.ufw_inactive_context" not in keys
