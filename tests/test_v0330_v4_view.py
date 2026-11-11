"""v0.33.0 — IPv6-only rules no longer leave the IPv4 port verdict unknown.

The IPv6 verdict has read the ruleset through _v6_view since 0.30.0 (IPv4-only
rules set aside). The IPv4 verdict had no such view: a single `meta nfproto
ipv6` rule in an inet input chain made it "not established". Measured on the
Linux Mint 22.3 test install (nftables 1.0.9), a network namespace, a listener
on 8099 over IPv4 and IPv6, a real connection as the oracle (netnsbench/a40330):

| inet input chain                                   | oracle v4 | 0.32.0 v4 | 0.33.0 v4 |
|----------------------------------------------------|-----------|-----------|-----------|
| policy accept, meta nfproto ipv6 tcp dport 8099 drop | open    | UNKNOWN   | ACCEPT    |
| policy drop, meta nfproto ipv6 tcp dport 8099 accept | closed  | UNKNOWN   | DROP      |
| policy drop, ip6 saddr fd77::/64 tcp dport 8099 accept | closed | UNKNOWN  | DROP      |
| policy drop, meta nfproto ipv4 tcp dport 8099 accept | open    | UNKNOWN   | ACCEPT    |
| policy accept, icmpv6 type echo-request drop          | open    | UNKNOWN   | ACCEPT    |
"""

from __future__ import annotations

import pytest

from bob.checks.iptables_nftables import _v4_view, nft_port_verdict

_CHAIN = """table inet f {
\tchain in {
\t\ttype filter hook input priority filter; policy %s;
\t\ttcp dport 22 drop
\t\t%s
\t}
}
"""


@pytest.mark.parametrize("policy, rule, want", [
    ("accept", "meta nfproto ipv6 tcp dport 8099 drop", ("ACCEPT", "default")),
    ("drop", "meta nfproto ipv6 tcp dport 8099 accept", ("DROP", "default")),
    ("drop", "ip6 saddr fd77::/64 tcp dport 8099 accept", ("DROP", "default")),
    ("drop", "meta nfproto ipv4 tcp dport 8099 accept", ("ACCEPT", "rule")),
    ("accept", "icmpv6 type echo-request drop", ("ACCEPT", "default")),
], ids=["v6-drop", "v6-accept", "ip6-saddr", "v4-only-accept", "icmpv6"])
def test_the_measured_cases(policy, rule, want):
    assert nft_port_verdict(_v4_view(_CHAIN % (policy, rule)), 8099, "tcp") == want


def test_ipv4_rules_stay_weighed():
    ruleset = _CHAIN % ("accept", "ip saddr 10.0.0.0/8 tcp dport 8099 drop")
    assert _v4_view(ruleset).splitlines() == ruleset.splitlines()


def test_the_snapshot_reads_through_the_view():
    from bob.checks.iptables_nftables import IptablesNftSnapshot
    snap = IptablesNftSnapshot(backend="nftables", input_policy="DROP", forward_policy="DROP",
                               has_loopback_rule=True, has_conntrack_rule=True,
                               raw_output=_CHAIN % ("drop", "meta nfproto ipv6 tcp dport 8099 accept"))
    assert snap.port_verdict(8099, "tcp")[0] == "DROP"
