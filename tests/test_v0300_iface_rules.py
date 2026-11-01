"""v0.30.0 — the per-port verdict reads rules limited to an input interface.

0.28.0 wrote the limit: "a rule limited to an interface leaves a port not
established" — and, the bench showed, every other port of the chain too.
Measured in a network namespace (1 November 2026,
`~/.cache/bob-fieldtest/netnsbench/p7bench.sh`, listeners 8098 and 8099 on
0.0.0.0, the host's interface s0 and, in some cases, a second one s1):

| case | probe | 0.30.0 |
|---|---|---|
| I1 `iifname "s0" tcp dport 8099 drop`, s0 only | 8099 closed | 8099 refused |
| I2 `iifname "eth9" …`, absent | open | accepted |
| I3 drop on s0, s0 and s1 | 8099 closed on s0, open on s1 | not established |
| I4 `iifname { "s0", "s1" }` | closed on both | refused |
| I5 `iifname "s*"` | closed on both | refused |
| I6 policy drop, `iifname "s0" tcp dport 8098 accept`, s0 only | 8098 open | accepted by a rule |
| I7 the same, s0 and s1 | 8098 open on s0, closed on s1 | not established |
| I8 iptables `-i s0 … --dport 8099 -j DROP`, s0 only | closed | refused |
| I9 the same, s0 and s1 | closed on s0, open on s1 | not established |
| I10 `iifname != "s0"`, s0 only | open | accepted |

0.29.0 read both ports not established in all ten.
"""

from __future__ import annotations

import ipaddress

import pytest

from bob.checks import iptables_nftables as nf

A, D, U = ("ACCEPT", "rule"), ("DROP", "rule"), ("UNKNOWN", "")
AD, DD = ("ACCEPT", "default"), ("DROP", "default")


def _hosts(*ifaces):
    view = nf._HostView(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2"))
    view.ifaces = frozenset(ifaces)
    return view


ONE, TWO = _hosts("s0"), _hosts("s0", "s1")


def _nft(policy, *rules):
    return ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy " + policy + ";\n"
            + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n}\n")


PARTIAL = ("tcp dport 22 drop",)


@pytest.mark.parametrize("ruleset, hosts, v8098, v8099", [
    (_nft("accept", *PARTIAL, 'iifname "s0" tcp dport 8099 drop'), ONE, AD, D),
    (_nft("accept", *PARTIAL, 'iifname "eth9" tcp dport 8099 drop'), ONE, AD, AD),
    (_nft("accept", *PARTIAL, 'iifname "s0" tcp dport 8099 drop'), TWO, AD, U),
    (_nft("accept", *PARTIAL, 'iifname { "s0", "s1" } tcp dport 8099 drop'), TWO, AD, D),
    (_nft("accept", *PARTIAL, 'iifname "s*" tcp dport 8099 drop'), TWO, AD, D),
    (_nft("drop", 'iifname "s0" tcp dport 8098 accept'), ONE, A, DD),
    (_nft("drop", 'iifname "s0" tcp dport 8098 accept'), TWO, U, DD),
    (_nft("accept", *PARTIAL, 'iifname != "s0" tcp dport 8099 drop'), ONE, AD, AD),
    (_nft("accept", *PARTIAL, 'tcp dport 8099 iifname "s0" drop'), ONE, AD, D),
    (_nft("accept", *PARTIAL, 'iifname "s0" tcp dport 8099 drop'), frozenset(), AD, U),
], ids=["I1", "I2", "I3", "I4", "I5", "I6", "I7", "I10", "after-port", "interfaces-unread"])
def test_nftables(ruleset, hosts, v8098, v8099):
    assert (nf.nft_port_verdict(ruleset, 8098, "tcp", hosts),
            nf.nft_port_verdict(ruleset, 8099, "tcp", hosts)) == (v8098, v8099)


def _ipt(*rules):
    return "\n".join(["-P INPUT ACCEPT", "-P FORWARD DROP", "-P OUTPUT ACCEPT",
                      "-A INPUT -p tcp -m tcp --dport 22 -j DROP", *rules]) + "\n"


@pytest.mark.parametrize("rule, hosts, v8099", [
    ("-A INPUT -i s0 -p tcp -m tcp --dport 8099 -j DROP", ONE, D),
    ("-A INPUT -i s0 -p tcp -m tcp --dport 8099 -j DROP", TWO, U),
    ("-A INPUT ! -i s0 -p tcp -m tcp --dport 8099 -j DROP", ONE, AD),
    ("-A INPUT -i s+ -p tcp -m tcp --dport 8099 -j DROP", TWO, D),
], ids=["I8", "I9", "negated", "plus-wildcard"])
def test_iptables(rule, hosts, v8099):
    assert nf.ipt_port_verdict(_ipt(rule), 8098, "tcp", {}, hosts) == AD
    assert nf.ipt_port_verdict(_ipt(rule), 8099, "tcp", {}, hosts) == v8099


@pytest.mark.parametrize("spec, negated, hosts, cover", [
    ('"s0"', False, ONE, "all"), ('"eth9"', False, ONE, "none"), ('"s0"', False, TWO, "some"),
    ('{ "s0", "s1" }', False, TWO, "all"), ('"s*"', False, TWO, "all"), ('"s0"', True, ONE, "none"),
    ('"s0"', True, TWO, "some"), ("s+", False, TWO, "all"), ('"s0"', False, frozenset(), None),
])
def test_the_cover(spec, negated, hosts, cover):
    assert nf._iface_cover(spec, negated, hosts) == cover


def test_the_interfaces_read(monkeypatch):
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
           "2: s0    inet 10.77.0.2/24 brd 10.77.0.255 scope global s0\\       valid_lft forever\n"
           "2: s0    inet6 fd77::2/64 scope global \\       valid_lft forever\n"
           "3: s1    inet6 fe80::1/64 scope link \\       valid_lft forever\n")

    class R:
        ok, stdout, stderr, code = True, out, "", 0
    monkeypatch.setattr(nf, "run_result", lambda *a, **k: R())
    view = nf._host_addresses()
    assert view.ifaces == frozenset({"s0"})
    assert ipaddress.ip_address("10.77.0.2") in view
