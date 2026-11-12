"""v0.34.0 — IPv6 destination NAT in the IPv6 port verdict.

IPv4's verdict has followed destination NAT since 0.31.0; IPv6's ignored it.
Measured on Fedora 44 (nftables 1.1.6), a network namespace, a listener on
8099, a real connection as the oracle (netnsbench/b10340):

| ip6/inet nat prerouting                         | oracle v6 | 0.33.0 v6 | 0.34.0 v6  |
|-------------------------------------------------|-----------|-----------|------------|
| none                                            | open      | ACCEPT    | ACCEPT     |
| ip6: tcp dport 8099 redirect to :9999           | closed    | ACCEPT    | DROP (nat) |
| ip6: tcp dport 8080 redirect to :8099           | open      | ACCEPT    | ACCEPT     |
| inet: meta nfproto ipv6 tcp dport 8099 redirect | closed    | ACCEPT    | DROP (nat) |
| ip6: tcp dport 8099 dnat ip6 to [fd77::9]:8099  | closed    | ACCEPT    | UNKNOWN (not followed) |

IPv4 untouched in every case.
"""

from __future__ import annotations

import pytest

from bob.checks.iptables_nftables import IptablesNftSnapshot, _nft_nat_views

_FILTER = "table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 22 drop\n\t}\n}\n"


def _nat(family, rule):
    return (f"table {family} n {{\n\tchain p {{\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            f"\t\t{rule}\n\t}}\n}}\n")


def _snap(raw):
    return IptablesNftSnapshot(backend="nftables", input_policy="ACCEPT", forward_policy="ACCEPT",
                               has_loopback_rule=True, has_conntrack_rule=True, raw_output=raw,
                               nat_rules=_nft_nat_views(raw, "", "")[0], nat_rules6=_nft_nat_views(raw, "", "")[1])


@pytest.mark.parametrize("nat, v6", [
    ("", "ACCEPT"),
    (_nat("ip6", "tcp dport 8099 redirect to :9999"), "DROP"),
    (_nat("ip6", "tcp dport 8080 redirect to :8099"), "ACCEPT"),
    (_nat("inet", "meta nfproto ipv6 tcp dport 8099 redirect to :9999"), "DROP"),
    (_nat("ip6", "tcp dport 8099 dnat ip6 to [fd77::9]:8099"), "UNKNOWN"),
], ids=["none", "redirect-away", "redirect-here", "inet-nfproto", "dnat-not-followed"])
def test_as_measured(nat, v6):
    snap = _snap(_FILTER + nat)
    assert snap.port_verdict_v6(8099, "tcp")[0] == v6
    assert snap.port_verdict(8099, "tcp")[0] == "ACCEPT"


def test_an_ipv6_only_nat_rule_does_not_spoil_ipv4s():
    raw = _FILTER + _nat("inet", "meta nfproto ipv6 tcp dport 8099 redirect to :9999")
    v4, v6 = _nft_nat_views(raw, "", "")
    assert v4 == [] and v6 and v6[0]["to"] == 9999
