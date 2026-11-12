"""v0.34.0 — ICMP rules by type no longer make the port verdicts unknown.

An ICMP or ICMPv6 rule naming types cannot decide a TCP or UDP connection,
whatever its verdict; any other rule the walker did not know made the verdict
"not established". Except IPv6 neighbour discovery: refusing the nd-* types
breaks IPv6 reachability — those rules still leave the IPv6 verdict unknown,
and an IPv6 accept under a policy-drop chain that nowhere accepts neighbour
discovery is not established either. Measured on Fedora 44 (nftables 1.1.6),
a network namespace, a listener on 8099, a real connection as the oracle
(netnsbench/a20340):

| inet input chain                                         | oracle v4/v6     | 0.33.0 v4/v6     | 0.34.0 v4/v6 |
|----------------------------------------------------------|------------------|------------------|--------------|
| accept, icmpv6 type echo-request drop                    | open/open        | ACCEPT/UNKNOWN   | ACCEPT/ACCEPT |
| accept, icmpv6 type { nd-neighbor-solicit, -advert } drop | open/closed     | ACCEPT/UNKNOWN   | ACCEPT/UNKNOWN |
| accept, icmp type echo-request drop                      | open/open        | UNKNOWN/ACCEPT   | ACCEPT/ACCEPT |
| drop, icmpv6 echo-request accept, tcp dport 8099 accept  | open/closed, then open | ACCEPT/ACCEPT | ACCEPT/UNKNOWN |
| drop, nd types accepted, tcp dport 8099 accept           | open/open        | ACCEPT/ACCEPT    | ACCEPT/ACCEPT |
"""

from __future__ import annotations

import pytest

from bob.checks.iptables_nftables import _v4_view, nft_port_verdict, nft_port_verdict_v6

_CHAIN = "table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy %s;\n\t\ttcp dport 22 drop\n%s\t}\n}\n"


@pytest.mark.parametrize("policy, rules, v4, v6", [
    ("accept", "\t\ticmpv6 type echo-request drop\n", "ACCEPT", "ACCEPT"),
    ("accept", "\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } drop\n", "ACCEPT", "UNKNOWN"),
    ("accept", "\t\ticmp type echo-request drop\n", "ACCEPT", "ACCEPT"),
    ("drop", "\t\ticmpv6 type echo-request accept\n\t\ttcp dport 8099 accept\n", "ACCEPT", "UNKNOWN"),
    ("drop", "\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n\t\ttcp dport 8099 accept\n", "ACCEPT", "ACCEPT"),
    ("drop", "\t\tmeta l4proto ipv6-icmp accept\n\t\ttcp dport 8099 accept\n", "ACCEPT", "ACCEPT"),
], ids=["v6-echo-drop", "nd-drop", "v4-echo-drop", "no-nd-accept", "nd-accepted", "all-icmpv6-accepted"])
def test_as_measured(policy, rules, v4, v6):
    ruleset = _CHAIN % (policy, rules)
    assert nft_port_verdict(_v4_view(ruleset), 8099, "tcp")[0] == v4
    assert nft_port_verdict_v6(ruleset, 8099, "tcp")[0] == v6
