"""nftables parity — a hardened nft host must not be penalised for iptables habits.

Backlog item 4, second tooth. The firewall domain was scored from the iptables
path; the nft path parsed the same four signals but not with the same reach,
so an nftables host could fail a check an equivalent iptables host passed.

The gap was in the loopback rule. nft has two spellings — ``iif`` matches the
interface by index, ``iifname`` by name — and it *preserves* whichever the
operator wrote rather than normalising to one, which was verified by loading
rulesets into a network namespace and reading back what `nft list ruleset`
prints. BOB matched ``iif`` only, and ``iifname "lo" accept`` is the form most
guides ship.

So a correctly hardened nft host was told it had no loopback rule and lost a
point for it. That is a false deduction, which is worse than a missed one: the
operator is told to add a rule that is already there, and the score says the
machine is weaker than it is.

The fixture below is genuine `nft list ruleset` output, not hand-written.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from bob.checks import iptables_nftables as M

# Verbatim output of `nft list ruleset` after loading a hardened ruleset.
GENUINE = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiifname "lo" accept
\t\tct state established,related accept
\t}

\tchain forward {
\t\ttype filter hook forward priority filter; policy drop;
\t}
}
"""


class TestTheLoopbackRuleIsRecognised:
    @pytest.mark.parametrize("rule", ['iif "lo" accept', 'iifname "lo" accept'])
    def test_both_spellings_count(self, rule):
        assert M._nft_has_loopback(rule) is True

    @pytest.mark.parametrize(
        "rule",
        ['iifname "eth0" accept',   # another interface
         'iif "eth0" accept',
         'oifname "lo" accept',     # output interface, not input
         'iifname "lo" drop'],      # matches lo, but does not accept
    )
    def test_the_polarity_twins_do_not(self, rule):
        """Without these, a parser that answered True on anything mentioning
        `lo` would pass every case above."""
        assert M._nft_has_loopback(rule) is False


class TestTheGenuineRulesetIsReadCorrectly:
    def test_all_four_signals(self):
        assert M._nft_policy(GENUINE, "input") == "DROP"
        assert M._nft_policy(GENUINE, "forward") == "DROP"
        assert M._nft_has_loopback(GENUINE) is True
        assert M._nft_has_conntrack(GENUINE) is True

    def test_a_hardened_nft_host_is_not_penalised(self):
        snap = M.IptablesNftSnapshot(
            backend="nftables",
            input_policy=M._nft_policy(GENUINE, "input"),
            forward_policy=M._nft_policy(GENUINE, "forward"),
            has_loopback_rule=M._nft_has_loopback(GENUINE),
            has_conntrack_rule=M._nft_has_conntrack(GENUINE),
        )
        result = M.check_iptables_nftables(snap)
        assert not result.deductions, (
            "a hardened nftables host lost points for rules it has: "
            f"{[d.reason for d in result.deductions]}"
        )

    def test_an_open_nft_host_still_is(self):
        """Polarity: parity must not become blanket forgiveness."""
        snap = M.IptablesNftSnapshot(
            backend="nftables", input_policy="ACCEPT", forward_policy="ACCEPT",
            has_loopback_rule=False, has_conntrack_rule=False,
        )
        assert M.check_iptables_nftables(snap).deductions


class TestAgainstNftItself:
    """nft is the authority on what it prints back."""

    @pytest.mark.skipif(shutil.which("nft") is None, reason="nft not installed")
    @pytest.mark.parametrize("written", ['iif "lo" accept', 'iifname "lo" accept',
                                         "meta iifname \"lo\" accept"])
    def test_nft_output_is_still_one_of_the_two_spellings(self, written, tmp_path):
        ruleset = tmp_path / "rs.nft"
        ruleset.write_text(
            "table inet t {\n chain input {\n"
            "  type filter hook input priority 0; policy drop;\n"
            f"  {written}\n }}\n}}\n"
        )
        proc = subprocess.run(
            ["unshare", "-Urn", "--map-root-user", "sh", "-c",
             f"nft -f {ruleset} && nft list ruleset"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            pytest.skip("no permission to create a network namespace here")
        assert M._nft_has_loopback(proc.stdout), (
            f"nft printed a form BOB does not read:\n{proc.stdout}"
        )
