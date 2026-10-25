"""v0.26.0 — a chain at policy accept that ends by rejecting everything filters.

Measured in a network namespace, a listener on 8097 and 8099, 8097 accepted:

* nft, ``policy accept`` and a last rule ``reject``: 8099 refused;
* iptables (iptables-nft), ``-P INPUT ACCEPT`` and a last ``-j REJECT``: the
  same.

BOB read the policy only: "no active firewall" and −3 for INPUT ACCEPT, in
0.25.1 and in 0.26.0, which also capped *Firewall & Network* at 3/10. The first
rule that takes every packet decides now; a rule with a match does not.

Found on the same bench: iptables-nft writes ``iifname "lo" counter packets 0
bytes 0 accept``, and the loopback pattern wanted ``accept`` right after
``"lo"`` — −1 for a loopback rule that was there.
"""

from bob.checks import iptables_nftables as ipt
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from tests.helpers import _keys, _t

# As `nft list ruleset` printed them in the namespace.
NFT_FINAL_REJECT = """table inet bobtest {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tct state established,related accept
\t\tiif "lo" accept
\t\ttcp dport 8097 accept
\t\treject
\t}
}
"""
IPTNFT_FINAL_REJECT = """table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname "lo" counter packets 0 bytes 0 accept
\t\ttcp dport 8097 counter packets 0 bytes 0 accept
\t\tcounter packets 0 bytes 0 reject
\t}
}
"""
TCP_ONLY = """table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tip protocol tcp counter packets 0 bytes 0 reject with tcp reset
\t}
}
"""
ACCEPT_FIRST = """table inet t {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\taccept
\t\treject
\t}
}
"""


class TestTheNftChain:
    def test_a_final_reject_filters(self):
        assert ipt._nft_policy(NFT_FINAL_REJECT, "input") == "REJECT"
        assert ipt._nft_policy_by_rule(NFT_FINAL_REJECT, "input")

    def test_iptables_nft_counters_do_not_hide_it(self):
        assert ipt._nft_policy(IPTNFT_FINAL_REJECT, "input") == "REJECT"
        assert ipt._nft_has_loopback(IPTNFT_FINAL_REJECT)

    def test_a_rule_with_a_match_leaves_the_rest_to_the_policy(self):
        # v0.27.0 — not "accept" any more: a reject for every TCP packet closes
        # every TCP listener, which "all incoming traffic is allowed" denied
        # (measured after the 0.27.0 review: a drop for one port at policy
        # accept closed it). Not established — no rule gives the verdict.
        assert ipt._nft_policy(TCP_ONLY, "input") == "PARTIAL"
        assert not ipt._nft_policy_by_rule(TCP_ONLY, "input")

    def test_an_accept_everything_rule_before_it_wins(self):
        assert ipt._nft_policy(ACCEPT_FIRST, "input") == "ACCEPT"

    def test_a_final_drop(self):
        assert ipt._nft_policy(NFT_FINAL_REJECT.replace("\t\treject\n", "\t\tdrop\n"), "input") == "DROP"


class TestTheIptablesChain:
    def test_a_final_reject_filters(self):
        rules = ("-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n"
                 "-A INPUT -p tcp -m tcp --dport 8097 -j ACCEPT\n"
                 "-A INPUT -j REJECT --reject-with icmp-port-unreachable\n")
        assert ipt._ipt_effective_input_policy(rules) == "REJECT"
        assert ipt._ipt_terminal_input(rules) == "REJECT"

    def test_the_first_terminal_rule_decides(self):
        assert ipt._ipt_effective_input_policy("-P INPUT DROP\n-A INPUT -j ACCEPT\n") == "ACCEPT"
        assert ipt._ipt_effective_input_policy("-P INPUT ACCEPT\n-A INPUT -j DROP\n-A INPUT -j ACCEPT\n") == "DROP"

    def test_a_rule_with_a_match_does_not(self):
        rules = "-P INPUT ACCEPT\n-A INPUT -p tcp -j REJECT --reject-with tcp-reset\n"
        assert ipt._ipt_effective_input_policy(rules) == "PARTIAL"     # v0.27.0, as above


class TestTheVerdict:
    def _snap(self, by_rule):
        return IptablesNftSnapshot(backend="nftables", input_policy="REJECT", forward_policy="DROP",
                                   has_loopback_rule=True, has_conntrack_rule=True,
                                   input_policy_by_rule=by_rule)

    def test_no_deduction_and_said_as_it_is(self):
        res = check_iptables_nftables(self._snap(True), t=_t, ssh_ports=[22])
        assert not res.deductions and "firewall_iptables.input_ok" in _keys(res)
        ok = next(f for f in res.findings if f.key == "firewall_iptables.input_ok")
        assert ok.message == "firewall_iptables.input_ok_final_rule"

    def test_a_policy_keeps_its_own_words(self):
        res = check_iptables_nftables(self._snap(False), t=_t, ssh_ports=[22])
        ok = next(f for f in res.findings if f.key == "firewall_iptables.input_ok")
        assert ok.message == "firewall_iptables.input_ok"


TWO_CHAINS_ACCEPT_FIRST = """table inet a {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\taccept
\t}
}
table inet b {
\tchain input {
\t\ttype filter hook input priority 10; policy accept;
\t\tct state established,related accept
\t\ttcp dport 8097 accept
\t\treject
\t}
}
"""


def test_an_accept_in_one_base_chain_does_not_skip_the_next():
    """After review, measured in a network namespace: chain a (priority 0)
    accepting everything and chain b (priority 10) ending in reject refused
    8099 in either order — an accept hands the packet to the next base chain,
    a reject ends it."""
    assert ipt._nft_policy(TWO_CHAINS_ACCEPT_FIRST, "input") == "REJECT"
    swapped = TWO_CHAINS_ACCEPT_FIRST.replace("priority filter;", "priority 20;")
    assert ipt._nft_policy(swapped, "input") == "REJECT"
