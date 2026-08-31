"""
v0.15.1 — "no issues" was claimed about a ruleset that was never listed.

Found by the new cross-check angle rather than by re-running v0.15.0's sweeps.
`firewall_stack` and `iptables_nftables` both describe the firewall drivers, and
comparing what they said about the same machine showed one reporting a refused
query and the other reporting a clean stack.

`iptables -L` and `nft list ruleset` both need CAP_NET_ADMIN and write their
refusal to stderr, leaving stdout empty. `_run` discards the exit code, so:

    _has_user_nft_rules("")  ->  False
    -> nftables_active = False
    -> [OK] firewall_drivers.no_issues

An explicit "no issues" about a ruleset BOB never saw. `iptables_nftables` was
fixed for exactly this in v0.15.0; `firewall_stack` was examined in the same
cycle but only for its line parsing, so the question was never asked of it.

The discriminator is the one already established: a working `iptables -L` always
prints its chain headers, even with no rules loaded, so an installed binary plus
empty output is a refused query. `nft list ruleset` prints nothing for a
genuinely empty ruleset and cannot tell the two apart alone — but both commands
need the same capability, so iptables answers for both.
"""

from __future__ import annotations

import pytest

import bob.checks.firewall_stack as fs
from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack


def _keys(**kw) -> set[str]:
    base = dict(nftables_active=False, ip_forward=False)
    base.update(kw)
    return {f.key for f in check_firewall_stack(FirewallStackSnapshot(**base)).findings}


class TestARefusedQueryIsNotACleanStack:
    def test_it_does_not_claim_no_issues(self):
        keys = _keys(rules_readable=False)
        assert "firewall_drivers.rules_unreadable" in keys
        assert "firewall_drivers.no_issues" not in keys

    def test_it_does_not_claim_a_conflict_either(self):
        """Unknown is unknown — inventing a warning would be the same error in
        the other direction."""
        keys = _keys(rules_readable=False)
        assert "firewall_drivers.nftables_parallel" not in keys

    def test_it_carries_no_deduction(self):
        result = check_firewall_stack(
            FirewallStackSnapshot(nftables_active=False, ip_forward=False,
                                  rules_readable=False))
        assert result.deductions == []

    def test_a_readable_clean_stack_still_says_so(self):
        assert "firewall_drivers.no_issues" in _keys(rules_readable=True)

    def test_a_readable_conflict_is_still_reported(self):
        keys = _keys(rules_readable=True, nftables_active=True)
        assert "firewall_drivers.nftables_parallel" in keys
        assert "firewall_drivers.rules_unreadable" not in keys


class TestTheReadabilitySignal:
    @pytest.mark.parametrize("iptables_present,output,expected", [
        (True,  "",                                   False),
        (True,  "   \n",                              False),
        (True,  "Chain INPUT (policy ACCEPT)\n",      True),
        (True,  "Chain INPUT (policy DROP)\ntarget prot opt source destination\n", True),
        # No iptables binary at all: nothing to infer a refusal from, so the
        # collection is taken at face value rather than declared unreadable.
        (False, "",                                   True),
    ])
    def test_signal(self, monkeypatch, iptables_present, output, expected):
        monkeypatch.setattr(fs, "_command_exists",
                            lambda n: iptables_present if n == "iptables" else False)
        monkeypatch.setattr(fs, "_run", lambda *a, **k: output)
        monkeypatch.setattr(fs, "_read_ip_forward", lambda: False)
        assert FirewallStackSnapshot.from_system().rules_readable is expected


class TestAgreementWithIptablesNftables:
    """The cross-check that found this: two modules describing the same thing
    must not disagree about whether they could read it."""

    def test_both_report_a_refused_query_the_same_way(self, monkeypatch):
        import bob.checks.iptables_nftables as ipt
        monkeypatch.setattr(fs, "_command_exists", lambda n: n == "iptables")
        monkeypatch.setattr(fs, "_run", lambda *a, **k: "")
        monkeypatch.setattr(fs, "_read_ip_forward", lambda: False)
        monkeypatch.setattr(ipt, "_command_exists", lambda n: n == "iptables")
        monkeypatch.setattr(ipt, "_run", lambda *a, **k: "")

        stack = FirewallStackSnapshot.from_system()
        nft = ipt.IptablesNftSnapshot.from_system()
        assert stack.rules_readable is False
        assert nft.query_failed is True, \
            "the two firewall-driver checks disagree about whether the ruleset was readable"
