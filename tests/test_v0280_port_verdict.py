"""v0.28.0 — each listener weighed against the rules for its port (lot 4).

0.27.0 wrote down the limit: "an accept for one port at policy drop is not
weighed (measured: 8099 accepted at policy drop was open and read 'denied by
default'), and which ports a refusing rule matches is not weighed either".
Measured in a network namespace (25 October 2026), listeners 8098 and 8099:

- policy accept + `tcp dport 8099 drop` (or `-p tcp --dport 8099 -j REJECT`,
  or a jump to a chain dropping 8099): 8098 open, 8099 closed;
- policy drop + `tcp dport 8099 accept` (also after loopback and
  established/related accepts): 8098 closed, 8099 open; `{ 8098, 8099 }`,
  `-m multiport --dports 8098,8099`: both open; `8090-8098`, `--dport
  8090:8098`: 8098 open, 8099 closed; `udp dport 8099 accept`: both closed;
- an accept for 8099 before a drop for it: open; an accept limited to another
  source: closed to this one — BOB does not weigh sources (not established).

The verdict is IPv4, and INFO only: no score moves.
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports


def _nft(policy, *rules, extra=""):
    body = "".join(f"\t\t{r}\n" for r in rules)
    return ("table inet f {\n\tchain in {\n"
            f"\t\ttype filter hook input priority filter; policy {policy};\n{body}\t}}\n{extra}}}\n")


def _ipt(policy, *rules):
    return "\n".join([f"-P INPUT {policy}", "-P FORWARD DROP", "-P OUTPUT ACCEPT", *rules]) + "\n"


A, D, U = ("ACCEPT", "rule"), ("DROP", "rule"), ("UNKNOWN", "")
AD, DD = ("ACCEPT", "default"), ("DROP", "default")

NFT_CASES = {
    "P1": (_nft("accept", "tcp dport 8099 drop"), AD, D),
    "P2": (_nft("drop", "tcp dport 8099 accept"), DD, A),
    "P3": (_nft("drop", "tcp dport { 8098, 8099 } accept"), A, A),
    "P4": (_nft("drop", "tcp dport 8090-8098 accept"), A, DD),
    "P5": (_nft("drop", "ct state established,related accept", 'iif "lo" accept', "tcp dport 8099 accept"), DD, A),
    "P6": (_nft("accept", "tcp dport 8099 accept", "tcp dport 8099 drop"), AD, A),
    "P7": (_nft("drop", "udp dport 8099 accept"), DD, DD),
    "P12": (_nft("drop", "ip saddr 10.77.0.99 tcp dport 8099 accept"), U, U),
    "P13": (_nft("accept", "jump x", extra="\n\tchain x {\n\t\ttcp dport 8099 drop\n\t}\n"), AD, D),
    "iptables-nft": (_nft("drop", 'iifname "lo" counter packets 3 bytes 180 accept',
                          "meta l4proto tcp tcp dport 8099 counter packets 0 bytes 0 accept"), DD, A),
    "comment": (_nft("drop", 'tcp dport 8099 accept comment "web"'), DD, A),
    "vmap": (_nft("accept", "tcp dport vmap { 8099 : drop }"), U, U),
    "goto-out": (_nft("drop", "goto x", extra="\n\tchain x {\n\t\ttcp dport 8098 accept\n\t}\n"), A, DD),
    "return": (_nft("drop", "jump x", "tcp dport 8099 accept",
                    extra="\n\tchain x {\n\t\treturn\n\t\ttcp dport 8099 drop\n\t}\n"), DD, A),
}

IPT_CASES = {
    "P8": (_ipt("DROP", "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT"), DD, A),
    "P9": (_ipt("ACCEPT", "-A INPUT -p tcp -m tcp --dport 8099 -j REJECT --reject-with tcp-reset"), AD, D),
    "P10": (_ipt("DROP", "-A INPUT -p tcp -m multiport --dports 8098,8099 -j ACCEPT"), A, A),
    "P11": (_ipt("DROP", "-A INPUT -p tcp -m tcp --dport 8090:8098 -j ACCEPT"), A, DD),
    "chain": (_ipt("ACCEPT", "-N X", "-A INPUT -j X", "-A X -p tcp -m tcp --dport 8099 -j DROP"), AD, D),
    "neutral": (_ipt("DROP", "-A INPUT -i lo -j ACCEPT",
                     "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                     "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT"), DD, A),
    "source": (_ipt("DROP", "-A INPUT -s 10.77.0.99/32 -p tcp -m tcp --dport 8099 -j ACCEPT"), U, U),
    "udp": (_ipt("DROP", "-A INPUT -p udp -m udp --dport 8099 -j ACCEPT"), DD, DD),
}


class TestTheMeasuredRulesets:

    @pytest.mark.parametrize("name", NFT_CASES)
    def test_nftables(self, name):
        ruleset, v8098, v8099 = NFT_CASES[name]
        assert (nf.nft_port_verdict(ruleset, 8098, "tcp"), nf.nft_port_verdict(ruleset, 8099, "tcp")) == (v8098, v8099)

    @pytest.mark.parametrize("name", IPT_CASES)
    def test_iptables_s(self, name):
        rules, v8098, v8099 = IPT_CASES[name]
        assert (nf.ipt_port_verdict(rules, 8098, "tcp", {}), nf.ipt_port_verdict(rules, 8099, "tcp", {})) == (v8098, v8099)

    def test_every_base_chain_must_accept(self):
        two = _nft("accept", "tcp dport 8099 accept") + _nft("accept", "tcp dport 8099 drop").replace("inet f", "inet g")
        assert nf.nft_port_verdict(two, 8099, "tcp") == D

    def test_an_ip6_chain_is_not_ipv4(self):
        assert nf.nft_port_verdict(_nft("drop").replace("inet f", "ip6 f"), 8099, "tcp") == U

    def test_the_snapshot_picks_its_backend(self):
        s = nf.IptablesNftSnapshot(backend="iptables", input_policy="DROP", forward_policy="DROP",
                                   has_loopback_rule=True, has_conntrack_rule=True,
                                   raw_output=IPT_CASES["P8"][0], other_tables={})
        assert s.port_verdict(8099, "tcp") == A
        s.backend = "none"
        assert s.port_verdict(8099, "tcp") == U


def _ports(*bindings):
    ports = [ListeningPort(port=p, proto="tcp", address=a, raw_line="", process="web") for p, a in bindings]
    return PortsSnapshot(ports=ports, ufw_rules="", ss_output="")


def _verdicts(table):
    return lambda port, proto: table.get(port, U)


def _messages(snap, lang="en", **kw):
    i18n.init(lang)
    try:
        res = check_ports(snap, ufw_active=False, t=i18n.t, **kw)
    finally:
        i18n.init("en")
    return [f.message for f in res.findings], res


class TestWhatIsSaid:

    @pytest.mark.parametrize("lang, verdict, words", [
        ("en", A, "for this port accepts it: reachable from the network"),
        ("en", DD, "refuses it by default and no rule accepts this port first: not reachable"),
        ("fr", D, "pour ce port le refuse : injoignable depuis le réseau"),
        ("fr", AD, "l'accepte par défaut et aucune règle ne refuse ce port : joignable"),
    ])
    def test_a_weighed_listener(self, lang, verdict, words):
        msgs, res = _messages(_ports((8099, "0.0.0.0")), lang, netfilter_active=True,
                              netfilter_port_verdict=_verdicts({8099: verdict}))
        assert any(words in m and "8099" in m for m in msgs), msgs
        assert not res.deductions

    def test_partial_too(self):
        msgs, _ = _messages(_ports((8099, "0.0.0.0")), netfilter_partial=True,
                            netfilter_port_verdict=_verdicts({8099: D}))
        assert any("for this port refuses it" in m for m in msgs)

    def test_not_established_keeps_the_old_text(self):
        msgs, _ = _messages(_ports((8099, "0.0.0.0")), netfilter_partial=True,
                            netfilter_port_verdict=_verdicts({}))
        assert any("whether this port is reachable is not established" in m for m in msgs)

    def test_an_ipv6_listener_is_not_given_the_ipv4_verdict(self):
        msgs, _ = _messages(_ports((8099, "::")), netfilter_active=True,
                            netfilter_port_verdict=_verdicts({8099: A}))
        assert not any("over IPv4" in m for m in msgs)

    def test_a_bound_address(self):
        msgs, _ = _messages(_ports((8099, "192.0.2.10")), netfilter_active=True,
                            netfilter_port_verdict=_verdicts({8099: DD}))
        assert any("bound to 192.0.2.10 only — over IPv4, the nftables/iptables ruleset refuses it" in m
                   for m in msgs), msgs

    def test_the_runner_hands_it(self):
        from bob import runner
        src = inspect.getsource(runner)
        assert "netfilter_port_verdict=(_nf_snap.port_verdict" in src


class TestTheServicesLine:

    def _line(self, verdict, lang="en", **kw):
        from bob.checks.services import Exposure, _check_port_exposure
        from bob.scoring import CheckResult
        from types import SimpleNamespace
        snap = SimpleNamespace(service=SimpleNamespace(id="ssh", is_high_or_critical=True), label="SSH",
                               local_sources={})
        i18n.init(lang)
        try:
            res = CheckResult()
            _check_port_exposure(snap, "22/tcp", Exposure.NO_RULE, res, "local", False, i18n.t,
                                 netfilter_active=True, netfilter_port_verdict=lambda p, pr: verdict, **kw)
        finally:
            i18n.init("en")
        return [f.message for f in res.findings]

    @pytest.mark.parametrize("lang, verdict, words", [
        ("en", A, "Port 22/tcp — over IPv4, a rule of the nftables/iptables ruleset for this port accepts it"),
        ("fr", DD, "Port 22/tcp — en IPv4, le jeu nftables/iptables le refuse par défaut"),
    ])
    def test_weighed(self, lang, verdict, words):
        assert any(words in m for m in self._line(verdict, lang)), self._line(verdict, lang)

    def test_not_established_keeps_the_old_text(self):
        assert any("reachable only if that ruleset permits this port" in m for m in self._line(U))

    def test_the_runner_gives_it_for_ipv4_listeners_only(self):
        from bob import runner
        src = inspect.getsource(runner)
        assert "netfilter_port_verdict=_v4_port_verdict," in src
        # the verdict function's own condition (a second function names the
        # same test for its interface scope)
        assert 'lp.proto == proto and ":" not in lp.address' in src


class TestSourcesAndInterfaces:
    """After review (round 1), measured in a network namespace (portbench
    P14-P19L, the client at 10.77.0.1): a drop limited to another source left
    8099 open — set aside, the port is reachable from every other source; a
    drop for all sources but one, and a drop limited to the client's interface,
    closed it — BOB leaves the port not established, never scored. In those two
    chains BOB also leaves 8098 not established: it stops at a rule it does not
    weigh, whichever port that rule names."""

    @pytest.mark.parametrize("rule, v8099", [
        ("ip saddr 10.77.0.99 tcp dport 8099 drop", AD),
        ("ip saddr != 10.77.0.99 tcp dport 8099 drop", U),
        ('iifname "s0" tcp dport 8099 drop', U),
    ], ids=["another-source", "all-but-one", "interface"])
    def test_nftables(self, rule, v8099):
        assert nf.nft_port_verdict(_nft("accept", rule), 8099, "tcp") == v8099

    @pytest.mark.parametrize("rule, v8099", [
        ("-A INPUT -s 10.77.0.99/32 -p tcp -m tcp --dport 8099 -j DROP", AD),
        ("-A INPUT ! -s 10.77.0.99/32 -p tcp -m tcp --dport 8099 -j DROP", U),
        ("-A INPUT -i s0 -p tcp -m tcp --dport 8099 -j DROP", U),
    ], ids=["another-source", "all-but-one", "interface"])
    def test_iptables_s(self, rule, v8099):
        assert nf.ipt_port_verdict(_ipt("ACCEPT", rule), 8099, "tcp", {}) == v8099

    def test_only_the_reachable_one_is_scored(self):
        for rule, scored in (("ip saddr 10.77.0.99 tcp dport 8099 drop", True),
                             ("ip saddr != 10.77.0.99 tcp dport 8099 drop", False),
                             ('iifname "s0" tcp dport 8099 drop', False)):
            ruleset = _nft("accept", rule)
            r = check_ports(_ports((8099, "0.0.0.0")), ufw_active=False, netfilter_partial=True,
                            netfilter_port_verdict=lambda p, pr, rs=ruleset: nf.nft_port_verdict(rs, p, pr),
                            t=lambda k, **kw: k)
            assert bool(r.deductions) is scored, rule


def _pre(family, table, chain, hook, rule, policy="accept", device=""):
    dev = f' device "{device}"' if device else ""
    return (f"table {family} {table} {{\n\tchain {chain} {{\n"
            f"\t\ttype filter hook {hook}{dev} priority raw; policy {policy};\n\t\t{rule}\n\t}}\n}}\n")


_INPUT = _nft("accept", "tcp dport 22 drop")


class TestRefusedBeforeInput:
    """Round 2 (29 October 2026) — measured in a network namespace, input at
    policy accept with a drop for 22: a drop for 8099 at prerouting (nft raw
    priority, `iptables -t raw`), at a netdev ingress hook, in mangle INPUT or
    security INPUT closed 8099, and BOB read "accepted by default" — scored on
    a closed port. Now not established. A drop for another port and a mark
    left 8099 open and keep "accepted by default"."""

    @pytest.mark.parametrize("extra, v8099", [
        ("", AD),
        (_pre("ip", "r", "pre", "prerouting", "tcp dport 8099 drop"), U),
        (_pre("netdev", "n", "ing", "ingress", "tcp dport 8099 drop", device="s0"), U),
        (_pre("ip", "r", "pre", "prerouting", "tcp dport 9000 drop"), AD),
        (_pre("ip", "r", "pre", "prerouting", "tcp dport 8099 meta mark set 0x00000001"), AD),
        (_pre("ip", "raw", "PREROUTING", "prerouting",
              "meta l4proto tcp tcp dport 8099 counter packets 0 bytes 0 drop"), U),
        (_pre("ip", "r", "pre", "prerouting", "tcp dport 9000 accept", policy="drop"), U),
        (_pre("ip6", "r", "pre", "prerouting", "tcp dport 8099 drop"), AD),
    ], ids=["R0-nothing", "R1-prerouting", "R2-ingress", "R3-another-port", "R4-mark",
            "R5-iptables-nft-raw", "prerouting-policy-drop", "ip6-is-not-ipv4"])
    def test_nftables(self, extra, v8099):
        assert nf.nft_port_verdict(_INPUT + extra, 8099, "tcp") == v8099

    @pytest.mark.parametrize("tables, v8099", [
        ({}, AD),
        ({"raw": "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}, U),
        ({"mangle": "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n"}, U),
        ({"mangle": "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 9000 -j DROP\n"}, AD),
        ({"security": "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n"}, U),
        ({"mangle": "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A OUTPUT -p tcp -m tcp --dport 8099 -j DROP\n"}, AD),
        ({"mangle": "-P PREROUTING DROP\n-P INPUT ACCEPT\n"}, U),
        (None, U),
    ], ids=["R10L-nothing", "R6L-raw", "R7L-mangle-input", "R8L-another-port", "R9L-security",
            "output-is-not-inbound", "policy-drop", "unread"])
    def test_iptables_s(self, tables, v8099):
        rules = _ipt("ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j DROP")
        assert nf.ipt_port_verdict(rules, 8099, "tcp", tables) == v8099

    def test_a_drop_does_not_become_unknown(self):
        ruleset = _nft("accept", "tcp dport 8099 drop") + _pre("ip", "r", "pre", "prerouting", "tcp dport 8099 drop")
        assert nf.nft_port_verdict(ruleset, 8099, "tcp") == D

    def test_the_snapshot_hands_its_tables(self):
        s = nf.IptablesNftSnapshot(backend="iptables", input_policy="ACCEPT", forward_policy="DROP",
                                   has_loopback_rule=False, has_conntrack_rule=False,
                                   raw_output=_ipt("ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j DROP"),
                                   other_tables={"raw": "-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"})
        assert s.port_verdict(8099, "tcp") == U
        s.other_tables = {}
        assert s.port_verdict(8099, "tcp") == AD

    def test_the_other_tables_are_read(self, monkeypatch):
        calls = []

        def fake(*args, **kw):
            calls.append(args)
            table = args[2]
            if table == "security":
                return _Res("", False, "can't initialize iptables table `security': Table does not exist")
            return _Res(f"-P INPUT ACCEPT\n# {table}\n", True, "")
        monkeypatch.setattr(nf, "run_result", fake)
        got = nf._ipt_other_tables()
        assert set(got) == {"raw", "mangle", "security"} and got["security"] == ""
        assert all(a[:2] == ("iptables", "-t") and a[3] == "-S" for a in calls)

        monkeypatch.setattr(nf, "run_result", lambda *a, **k: _Res("", False, "Permission denied"))
        assert nf._ipt_other_tables() is None

    def test_a_closed_port_is_not_scored(self):
        ruleset = _INPUT + _pre("ip", "r", "pre", "prerouting", "tcp dport 8099 drop")
        r = check_ports(_ports((8099, "0.0.0.0")), ufw_active=False, netfilter_partial=True,
                        netfilter_port_verdict=lambda p, pr: nf.nft_port_verdict(ruleset, p, pr),
                        t=lambda k, **kw: k)
        assert not r.deductions


class _Res:
    def __init__(self, stdout, ok, stderr):
        self.stdout, self.ok, self.stderr = stdout, ok, stderr


def test_from_system_reads_the_other_tables(monkeypatch):
    """The iptables backend (nft absent) carries the raw, mangle and security
    tables to the verdict."""
    monkeypatch.setattr(nf, "_command_exists", lambda name: name == "iptables")
    monkeypatch.setattr(nf, "_run", lambda *a, **k: _ipt("ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j DROP"))
    monkeypatch.setattr(nf, "_ipt_other_tables",
                        lambda: {"raw": "-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"})
    s = nf.IptablesNftSnapshot.from_system()
    assert s.backend == "iptables"
    assert s.port_verdict(8099, "tcp") == U
    assert s.port_verdict(8098, "tcp") == AD
