"""
v0.15.5 — nftables installed and refusing was read as "no firewall backend".

Item B of the diagnosed-not-fixed list, and the third instance of one pattern:
an absence of answer collapsed into an assertion.

`query_failed` already existed, added for exactly this problem on the iptables
side, but it consulted one binary:

    query_failed = _command_exists("iptables")

So a host running nftables with no iptables binary — increasingly ordinary —
had `nft` refuse, `query_failed` stay False, and the audit report
`firewall_iptables.no_backend`: three points, the largest single deduction in
the check, plus "sudo apt install iptables" on a machine whose firewall backend
is installed and running.

**The discriminator, established against nft itself** rather than assumed:

    unprivileged        rc=1, stdout empty, "Operation not permitted" on stderr
    empty ruleset (netns) rc=0, stdout empty

stdout cannot tell those apart — the module's own comment says so and stopped
there. The exit code can. This is deliberately the opposite of the choice
`unit_active_state` documents for systemctl, which exits non-zero to *report* an
inactive unit: there the exit code is not an answer, here it is the only one.
"""

from __future__ import annotations

import pytest

import bob.checks.iptables_nftables as ipt
from bob.checks._run import CommandResult
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables


def _deducted(result) -> set[str]:
    return {d.key for d in getattr(result, "deductions", [])}


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


@pytest.fixture
def tools(monkeypatch):
    """Declare which binaries exist and what nft answers."""
    def _apply(present, nft_rc=1, nft_out=""):
        monkeypatch.setattr(ipt, "_command_exists", lambda name: name in present)
        monkeypatch.setattr(
            ipt, "run_result",
            lambda *a, **k: CommandResult(nft_out, nft_rc == 0, ""),
        )
        monkeypatch.setattr(ipt, "_run", lambda *a, **k: "")
    return _apply


class TestNftRefusingIsNotAnAbsentBackend:

    def test_nft_alone_and_refusing_is_unknown(self, tools):
        """The reported case: nftables host, no iptables binary."""
        tools({"nft"}, nft_rc=1)
        snap = IptablesNftSnapshot.from_system()
        assert snap.query_failed is True
        assert snap.nft_no_input_filter is False

    def test_nft_alone_and_refusing_costs_nothing(self, tools):
        tools({"nft"}, nft_rc=1)
        result = check_iptables_nftables(IptablesNftSnapshot.from_system())
        assert "firewall_iptables.no_backend" not in _deducted(result)
        assert "firewall_iptables.ruleset_unreadable" in _keys(result)

    def test_a_genuinely_empty_ruleset_is_still_a_finding(self, tools):
        """
        nft answered. The backend is installed and nothing filters inbound
        traffic — the same exposure, a different cause, and a remedy that does
        not tell an nftables machine to install iptables.
        """
        tools({"nft"}, nft_rc=0, nft_out="")
        snap = IptablesNftSnapshot.from_system()
        assert snap.nft_no_input_filter is True
        result = check_iptables_nftables(snap)
        assert "firewall_iptables.nft_no_input_filter" in _deducted(result)
        assert "firewall_iptables.no_backend" not in _deducted(result)

    def test_the_remedy_names_the_backend_the_host_has(self, tools):
        tools({"nft"}, nft_rc=0, nft_out="")
        result = check_iptables_nftables(IptablesNftSnapshot.from_system())
        cmds = " ".join(f.cmd or "" for f in result.findings)
        assert "apt install iptables" not in cmds
        assert "nft" in cmds

    def test_ufw_present_gets_the_ufw_remedy(self, tools):
        tools({"nft"}, nft_rc=0, nft_out="")
        result = check_iptables_nftables(
            IptablesNftSnapshot.from_system(), ufw_installed=True
        )
        cmds = " ".join(f.cmd or "" for f in result.findings)
        assert "ufw enable" in cmds

    def test_no_backend_at_all_still_deducts(self, tools):
        """The polarity twin: neither binary present is a real absence."""
        tools(set(), nft_rc=1)
        snap = IptablesNftSnapshot.from_system()
        assert snap.query_failed is False
        assert "firewall_iptables.no_backend" in _deducted(
            check_iptables_nftables(snap)
        )

    def test_a_loaded_ruleset_is_still_parsed(self, tools):
        """nft answering with real rules must reach the nftables branch."""
        tools({"nft"}, nft_rc=0, nft_out=(
            "table inet filter {\n"
            "  chain input {\n"
            "    type filter hook input priority 0; policy drop;\n"
            '    iifname "lo" accept\n'
            "  }\n"
            "}\n"
        ))
        snap = IptablesNftSnapshot.from_system()
        assert snap.backend == "nftables"
        assert snap.nft_no_input_filter is False
        assert snap.has_loopback_rule is True
