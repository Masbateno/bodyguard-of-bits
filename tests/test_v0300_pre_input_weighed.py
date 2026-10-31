"""v0.30.0 — the chains before input are weighed port by port.

Since 0.28.0 a refusal in a prerouting chain, or in the raw, mangle or
security table, left every port it might touch "not established", and since
0.29.0 a chain there at policy drop was named but its ports were not weighed.
Measured again in network namespaces (31 October 2026, `prebench-0300.txt`,
`secbench` F1–F3, `posturebench-0300.txt`, every verdict matching the probe):

- a drop for 8099 in a prerouting chain, raw PREROUTING, mangle INPUT or
  security INPUT closed 8099 — now refused;
- a prerouting chain at policy drop accepting 8098 only closed 8099 and left
  8098 open — now 8099 refused by default, 8098 accepted by a rule (opened
  on purpose: not scored, as a rule on input);
- a mark, or a drop for another port or another address, left 8099 open —
  still accepted;
- an ingress chain sees one device: a drop for 8099 there stays not
  established.

A full audit of the policy-drop case keeps its score (8, a ceiling), with each
port's verdict said instead of "not established" (`scorebench-p4.txt`).
"""

from __future__ import annotations

import ipaddress

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf

A, D, U = ("ACCEPT", "rule"), ("DROP", "rule"), ("UNKNOWN", "")
AD, DD = ("ACCEPT", "default"), ("DROP", "default")
HOSTS = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2"))

INPUT = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
         "\t\ttcp dport 22 drop\n\t}\n}\n")


def _pre(family, *rules, hook="prerouting", policy="accept", device=""):
    dev = f' device "{device}"' if device else ""
    return (f"table {family} r {{\n\tchain pre {{\n\t\ttype filter hook {hook}{dev} priority raw; policy {policy};\n"
            + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n}\n")


@pytest.mark.parametrize("extra, v8098, v8099", [
    (_pre("ip", "tcp dport 8099 drop"), AD, D),
    (_pre("inet", "tcp dport 8098 accept", policy="drop"), A, DD),
    (_pre("ip", "meta mark set 0x1"), AD, AD),
    (_pre("ip", "tcp dport 9000 drop"), AD, AD),
    (_pre("ip", 'ip daddr 172.17.0.2 iifname != "docker0" drop'), AD, AD),
    (_pre("ip", "ip daddr 10.77.0.2 tcp dport 8099 drop"), AD, D),
    (_pre("netdev", "tcp dport 8099 drop", hook="ingress", device="s0"), AD, U),
    (_pre("netdev", "", hook="ingress", policy="drop", device="s0"), U, U),
    (_pre("ip6", "tcp dport 8099 drop"), AD, AD),
    (_pre("ip", 'iifname "eth9" accept', policy="drop"), U, U),
    (_pre("netdev", "tcp dport 9000 drop", hook="ingress", device="s0"), AD, AD),
], ids=["P1-drop", "P3-policy-drop", "P4-mark", "P6-another-port", "P8-docker", "P9-this-host",
        "R2-ingress", "ingress-policy-drop", "ip6-is-not-ipv4", "an-accept-bob-cannot-weigh",
        "ingress-another-port"])
def test_nftables(extra, v8098, v8099):
    ruleset = INPUT + extra
    assert (nf.nft_port_verdict(ruleset, 8098, "tcp", HOSTS),
            nf.nft_port_verdict(ruleset, 8099, "tcp", HOSTS)) == (v8098, v8099)


def _ipt():
    return "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j DROP\n"


@pytest.mark.parametrize("tables, v8098, v8099", [
    ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}, AD, D),
    ({"raw": "-P PREROUTING DROP\n-A PREROUTING -p tcp -m tcp --dport 8098 -j ACCEPT\n"}, A, DD),
    ({"mangle": "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j MARK --set-xmark 0x1/0xffffffff\n"}, AD, AD),
    ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP\n"}, AD, AD),
    ({"security": "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n"}, AD, D),
    ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -i eth9 -j DROP\n"}, U, U),
], ids=["raw-drop", "raw-policy-drop", "mangle-mark", "docker", "security-drop", "a-refusal-bob-cannot-weigh"])
def test_iptables(tables, v8098, v8099):
    assert (nf.ipt_port_verdict(_ipt(), 8098, "tcp", tables, HOSTS),
            nf.ipt_port_verdict(_ipt(), 8099, "tcp", tables, HOSTS)) == (v8098, v8099)


def test_the_snapshot_weighs_nfts_own_chains_through_iptables():
    s = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="DROP",
                               has_loopback_rule=False, has_conntrack_rule=False, raw_output=_ipt(),
                               other_tables={}, host_addresses=HOSTS,
                               nft_pre_input=_pre("inet", "tcp dport 8098 accept", policy="drop"))
    assert (s.port_verdict(8098, "tcp"), s.port_verdict(8099, "tcp")) == (A, DD)


@pytest.mark.parametrize("lang, words", [
    ("en", "each IPv4 listening port is weighed against it in the ports section"),
    ("fr", "chaque port en écoute IPv4 est pesé face à elle dans la section des ports"),
])
def test_what_is_said(lang, words):
    i18n.init(lang)
    try:
        assert words in i18n.t("firewall_iptables.input_accept_default_drop", chains="inet r pre")
    finally:
        i18n.init(lang="en")


class TestTheInboundDefault:
    """The chains before input still decide the hook's default the 0.29.0 way:
    a chain at policy drop, or a rule that may refuse, makes it PARTIAL; a
    refusal aimed at another address (Docker's raw rule) does not."""

    @pytest.mark.parametrize("tables, policy", [
        ({"raw": "-P PREROUTING DROP\n"}, "PARTIAL"),
        ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP\n"}, "ACCEPT"),
        ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 9000 -j DROP\n"}, "PARTIAL"),
        ({}, "ACCEPT"),
    ], ids=["policy-drop", "docker", "a-drop", "nothing"])
    def test_iptables(self, tables, policy):
        assert nf._with_pre_input("ACCEPT", nf._ipt_refused_before_input(tables, None, None, HOSTS)) == policy


class TestTheIPv6SectionNamesTheChain:
    """v0.30.0 — measured in a network namespace (31 October 2026,
    `v6namebench.txt`): with an inet prerouting chain at policy drop, the IPv4
    section named it (0.29.0) and the IPv6 one did not. Now both do."""

    def _system(self, monkeypatch, nft="", ip6tables=None):
        class R:
            def __init__(self, ok, out):
                self.ok, self.stdout, self.stderr = ok, out, ""
        monkeypatch.setattr(nf, "_command_exists", lambda n: (n == "nft" and bool(nft)) or (n == "ip6tables" and ip6tables is not None))
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: R(True, nft))
        monkeypatch.setattr(nf, "_ipt_other_tables", lambda binary="iptables": ip6tables)

    def test_nft(self, monkeypatch):
        self._system(monkeypatch, nft=_pre("ip6", "tcp dport 8098 accept", policy="drop"))
        assert nf.read_default_drop_v6() == ["ip6 r pre"]

    def test_ip6tables(self, monkeypatch):
        self._system(monkeypatch, ip6tables={"raw": "-P PREROUTING DROP\n"})
        assert nf.read_default_drop_v6() == ["raw PREROUTING"]

    @pytest.mark.parametrize("chains, key", [(("inet r pre",), "ipv6.netfilter_v6_default_drop"),
                                             ((), "ipv6.netfilter_v6_unweighed")])
    def test_said(self, chains, key):
        from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False, ipv6_listeners=["8099/tcp"])
        res = check_ipv6(snap, ufw_active=False, netfilter_active=True, netfilter_v6_policy="PARTIAL",
                         netfilter_v6_drop_chains=chains, t=lambda k, **kw: k)
        assert [f.message for f in res.findings if f.key == "ipv6.netfilter_v6"] == [key]
        assert not res.deductions

    def test_the_runner_reads_and_hands_them(self):
        import inspect
        from bob import runner
        src = inspect.getsource(runner)
        assert '_v6_drop = tuple(read_default_drop_v6()) if _v6_policy == "PARTIAL" else ()' in src
        assert "netfilter_v6_drop_chains=_v6_drop)" in src

    @pytest.mark.parametrize("lang, words", [
        ("en", "is at policy drop (inet r pre): it refuses by default what it does not accept"),
        ("fr", "est en politique drop (inet r pre) : elle refuse par défaut ce qu'elle n'accepte pas"),
    ])
    def test_what_is_said(self, lang, words):
        i18n.init(lang)
        try:
            assert words in i18n.t("ipv6.netfilter_v6_default_drop", count=1, ports="8099/tcp", chains="inet r pre")
        finally:
            i18n.init(lang="en")
