"""v0.30.0 — each IPv6 listener says the verdict it meets; shown, not scored.

0.29.0 wrote the limit: "the per-port verdict is IPv4". Decided with the
maintainer (1 November 2026): the IPv6 verdict is given for information, and
the score keeps weighing IPv6 exposure in the IPv6 section, not port by port.
Measured in a network namespace (`~/.cache/bob-fieldtest/netnsbench/p7bbench.sh`,
listeners 8098 and 8099 on 10.77.0.2 and fd77::2), every IPv6 verdict matching
the probe, the IPv4 verdicts unchanged:

- 6A an inet drop for 8099: closed over IPv6 — refused;
- 6B a drop in an ip table, 6E `ip saddr … drop`: open over IPv6 — accepted;
- 6C an ip6 table, 6H an ip6 prerouting chain, 6I `meta nfproto ipv6 … drop`,
  6F ip6tables `--dport 8099 -j DROP`: closed — refused;
- 6D inet at policy drop accepting 8098: 8098 accepted by a rule, 8099 refused;
- 6G `iifname "s0" … drop`, s0 holding the IPv6 address: refused.
"""

from __future__ import annotations

import ipaddress

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf

A, D, U = ("ACCEPT", "rule"), ("DROP", "rule"), ("UNKNOWN", "")
AD, DD = ("ACCEPT", "default"), ("DROP", "default")


def _hosts():
    view = nf._HostView(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2", "::1", "fd77::2"))
    view.ifaces, view.ifaces6 = frozenset({"s0"}), frozenset({"s0"})
    return view


def _table(family, name, policy, *rules, hook="input"):
    return (f"table {family} {name} {{\n\tchain c {{\n\t\ttype filter hook {hook} priority filter; policy {policy};\n"
            + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n}\n")


INET = _table("inet", "f", "accept", "tcp dport 22 drop")


@pytest.mark.parametrize("ruleset, v8098, v8099", [
    (_table("inet", "f", "accept", "tcp dport 22 drop", "tcp dport 8099 drop"), AD, D),
    (INET + _table("ip", "v", "accept", "tcp dport 8099 drop"), AD, AD),
    (INET + _table("ip6", "w", "accept", "tcp dport 8099 drop"), AD, D),
    (_table("inet", "f", "drop", "tcp dport 8098 accept", "meta l4proto ipv6-icmp accept"), A, DD),
    (_table("inet", "f", "accept", "tcp dport 22 drop", "ip saddr 10.0.0.0/8 tcp dport 8099 drop"), AD, AD),
    (_table("inet", "f", "accept", "tcp dport 22 drop", 'iifname "s0" tcp dport 8099 drop'), AD, D),
    (INET + _table("ip6", "r", "accept", "tcp dport 8099 drop", hook="prerouting"), AD, D),
    (_table("inet", "f", "accept", "tcp dport 22 drop", "meta nfproto ipv6 tcp dport 8099 drop"), AD, D),
    (_table("inet", "f", "accept", "tcp dport 22 drop", "meta nfproto ipv4 tcp dport 8099 drop"), AD, AD),
    (_table("ip", "v", "accept", "tcp dport 8099 drop"), U, U),
], ids=["6A", "6B", "6C", "6D", "6E", "6G", "6H", "6I", "nfproto-ipv4", "no-ipv6-input-chain"])
def test_nftables(ruleset, v8098, v8099):
    assert (nf.nft_port_verdict_v6(ruleset, 8098, "tcp", _hosts()),
            nf.nft_port_verdict_v6(ruleset, 8099, "tcp", _hosts())) == (v8098, v8099)


def test_the_ipv4_verdict_is_untouched():
    ruleset = _table("inet", "f", "accept", "tcp dport 22 drop", "meta nfproto ipv6 tcp dport 8099 drop")
    assert nf.nft_port_verdict(ruleset, 8099, "tcp", _hosts()) == U


def test_ip6tables_through_the_snapshot():
    """6F."""
    s = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="DROP",
                               has_loopback_rule=False, has_conntrack_rule=False,
                               raw_output="-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j DROP\n",
                               other_tables={}, host_addresses=_hosts(),
                               raw_output6="-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n",
                               other_tables6={})
    assert (s.port_verdict_v6(8098, "tcp"), s.port_verdict_v6(8099, "tcp")) == (AD, D)
    s.raw_output6 = ""
    assert s.port_verdict_v6(8099, "tcp") == U


def test_ipv6_reads_the_ipv6_interfaces():
    view = _hosts()
    view.ifaces, view.ifaces6 = frozenset({"s1"}), frozenset({"s0"})
    ruleset = _table("inet", "f", "accept", "tcp dport 22 drop", 'iifname "s0" tcp dport 8099 drop')
    assert nf.nft_port_verdict_v6(ruleset, 8099, "tcp", view) == D


def test_the_ipv6_interfaces_read(monkeypatch):
    out = ("1: lo    inet6 ::1/128 scope host \\       valid_lft forever\n"
           "2: s0    inet6 fd77::2/64 scope global \\       valid_lft forever\n"
           "3: s1    inet 10.78.0.2/24 scope global s1\\       valid_lft forever\n")

    class R:
        def __init__(self, text):
            self.ok, self.stdout, self.stderr, self.code = True, text, "", 0
    links = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
    monkeypatch.setattr(nf, "run_result", lambda *a, **k: R(links if "link" in a else out))
    view = nf._host_addresses()
    assert (view.ifaces6, view.ifaces) == (frozenset({"s0"}), frozenset({"s1"}))


class TestThePortsSection:

    @staticmethod
    def _check(address, verdict6, verdict4=AD):
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        snap = PortsSnapshot(ports=[ListeningPort(port=8099, proto="tcp", address=address, raw_line="")],
                             ufw_rules="", ss_output="")
        return check_ports(snap, ufw_active=False, netfilter_partial=True,
                           t=lambda k, **kw: f"{k}[{kw['verdict']}]" if "verdict" in kw else k,
                           netfilter_port_verdict=lambda p, pr: verdict4,
                           netfilter_port_verdict6=lambda p, pr: verdict6)

    def test_an_ipv6_listener_says_its_verdict(self):
        res = self._check("::", D)
        f = next(f for f in res.findings if f.key == "ports.uncovered_netfilter_unweighed")
        assert f.message == "ports.uncovered_netfilter_weighed6[ports.netfilter_port.drop_rule]"
        assert f.detail == "ports.netfilter_port.detail6"

    def test_reached_by_default_over_ipv6_takes_no_point(self):
        res = self._check("::", AD)
        assert not res.deductions
        assert "ports.uncovered_netfilter_open" not in {f.key for f in res.findings}

    def test_an_ipv4_listener_keeps_the_ipv4_verdict(self):
        res = self._check("0.0.0.0", D, verdict4=AD)
        assert res.deductions and "ports.uncovered_netfilter_open" in {f.key for f in res.findings}

    def test_bound_to_one_ipv6_address(self):
        res = self._check("fd77::2", D)
        f = next(f for f in res.findings if f.key == "ports.uncovered_bound_address_netfilter_unweighed")
        assert f.message == "ports.uncovered_bound_address_netfilter_weighed6[ports.netfilter_port.drop_rule]"

    def test_the_runner_hands_it(self):
        import inspect
        from bob import runner
        assert "netfilter_port_verdict6=(_nf_snap.port_verdict_v6" in inspect.getsource(runner)


@pytest.mark.parametrize("lang, key, words", [
    ("en", "ports.uncovered_netfilter_weighed6", "over IPv6"),
    ("fr", "ports.uncovered_netfilter_weighed6", "en IPv6"),
    ("en", "ports.netfilter_port.detail6", "Shown for information: the score weighs IPv6 exposure in the IPv6 section"),
    ("fr", "ports.netfilter_port.detail6", "Donné à titre d'information : le score pèse l'exposition IPv6 dans la section IPv6"),
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key, port="8099/tcp", verdict="x", address="fd77::2")
    finally:
        i18n.init(lang="en")
