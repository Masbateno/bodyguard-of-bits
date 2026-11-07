"""v0.31.0 — the per-port verdict follows a destination NAT to the port it reaches.

0.30.0 wrote two limits: a redirect that sends a listener's port elsewhere was
not read (the port read accepted by default, −1, though nothing reached it),
and a refusal before a non-empty NAT prerouting chain stayed not established
whatever port the NAT rule named. Measured in a network namespace (2 November
2026, `~/.cache/bob-fieldtest/netnsbench/a1bench.sh`, `a1bench-fix.txt`;
listeners 8098 and 8099, a TCP probe on 7000, 8080, 8098 and 8099):

| case | probe 8099 | 0.30.0 | now |
|---|---|---|---|
| M1 `tcp dport 8099 redirect to :9999` | closed | accepted (−1) | refused, by the NAT |
| M2 a redirect for 7000 only, raw drop for 8099 | closed | not established | refused |
| M3 `tcp dport 8080 redirect to :8099`, raw drop for 8080 | open | accepted | accepted |
| M4 a dnat of 8080 to the host's address, port 8099 | open | accepted | accepted |
| M5 a dnat of 8099 to another host | closed | accepted (−1) | refused, by the NAT |
| M6 every tcp port redirected to 9999 | closed (8098 too) | accepted (−1) | refused, by the NAT |
| M7 a dnat of 8099 to the host's own address, same port | open | accepted | accepted |
| M8 `iifname "s0"` on the redirect (a condition) | closed | accepted (−1) | accepted (−1): not followed |
| M9 iptables `-t nat … REDIRECT --to-ports 9999` | closed | accepted (−1) | refused, by the NAT |
| M10 the same in a legacy nat table beside nft | closed | accepted (−1) | refused, by the NAT |
| M11 8080 → 8099 and 8099 → 9999 | open through 8080 | accepted | accepted |

Replayed against 0.30.0's NAT benches (`natbench`, `prio_legacy_bench`,
`legacybench`, `n12bench`): every verdict the same, but N12 (the redirect to
9999: refused, was accepted) and N13 (a redirect for 7000 only: refused, was
not established) — the probe found 8099 closed in both.
"""

from __future__ import annotations

import inspect
import ipaddress

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf

D, U, A, DD, DN = ("DROP", "rule"), ("UNKNOWN", ""), ("ACCEPT", "default"), ("DROP", "default"), ("DROP", "nat")
HOSTS = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2"))
INPUT = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
         "\t\ttcp dport 22 drop\n\t}\n}\n")


def _nat(*rules, family="ip", table="n"):
    return (f"table {family} {table} {{\n\tchain pre {{\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n}\n")


RAW_DROP_8099 = ("table ip r {\n\tchain c {\n\t\ttype filter hook prerouting priority raw; policy accept;\n"
                 "\t\ttcp dport 8099 drop\n\t}\n}\n")
RAW_DROP_8080 = RAW_DROP_8099.replace("8099", "8080")


def _snap(ruleset, nat_rules="read"):
    rules = nf._nft_nat_rules(ruleset) if nat_rules == "read" else nat_rules
    return nf.IptablesNftSnapshot(backend="nftables", input_policy="PARTIAL", forward_policy="ACCEPT",
                                  has_loopback_rule=False, has_conntrack_rule=False, raw_output=ruleset,
                                  host_addresses=HOSTS, nat_rules=rules)


class TestTheMeasuredCases:

    @pytest.mark.parametrize("ruleset, v8099", [
        (INPUT + _nat("tcp dport 8099 redirect to :9999"), DN),
        (INPUT + _nat("tcp dport 7000 redirect to :7001") + RAW_DROP_8099, D),
        (INPUT + _nat("tcp dport 8080 redirect to :8099") + RAW_DROP_8080, A),
        (INPUT + _nat("tcp dport 8080 dnat to 10.77.0.2:8099"), A),
        (INPUT + _nat("tcp dport 8099 dnat to 192.0.2.10:80"), DN),
        (INPUT + _nat("meta l4proto tcp redirect to :9999"), DN),
        (INPUT + _nat("tcp dport 8099 dnat to 10.77.0.2"), A),
        (INPUT + _nat('iifname "s0" tcp dport 8099 redirect to :9999'), A),
        (INPUT + _nat("tcp dport 8080 redirect to :8099", "tcp dport 8099 redirect to :9999"), A),
    ], ids=["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8-not-followed", "M11"])
    def test_nft(self, ruleset, v8099):
        assert _snap(ruleset).port_verdict(8099, "tcp") == v8099

    def test_a_redirect_from_another_port_keeps_0_30_0s_reading(self):
        """N1: a raw drop for 8099 and a redirect of 8080 to it — open
        through 8080, not established as in 0.30.0."""
        assert _snap(INPUT + _nat("tcp dport 8080 redirect to :8099") + RAW_DROP_8099).port_verdict(8099, "tcp") == U

    def test_rules_not_read_keep_0_30_0s_reading(self):
        rs = INPUT + _nat("tcp dport 7000 redirect to :7001") + RAW_DROP_8099
        assert _snap(rs, nat_rules=None).port_verdict(8099, "tcp") == U
        assert _snap(INPUT + _nat("tcp dport 8099 redirect to :9999"), nat_rules=None).port_verdict(8099, "tcp") == A

    def test_iptables(self):
        """M9: the iptables backend, its nat table read."""
        rules = nf._ipt_nat_rules("-P PREROUTING ACCEPT\n"
                                  "-A PREROUTING -p tcp -m tcp --dport 8099 -j REDIRECT --to-ports 9999\n")
        s = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="ACCEPT",
                                   has_loopback_rule=False, has_conntrack_rule=False,
                                   raw_output="-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j DROP\n",
                                   other_tables={}, host_addresses=HOSTS, nat_rules=rules)
        assert s.port_verdict(8099, "tcp") == DN
        assert s.port_verdict(8098, "tcp") == A

    def test_iptables_a_refusal_before_an_unrelated_nat(self):
        rules = nf._ipt_nat_rules("-A PREROUTING -p tcp -m tcp --dport 7000 -j REDIRECT --to-ports 7001\n")
        s = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="ACCEPT",
                                   has_loopback_rule=False, has_conntrack_rule=False,
                                   raw_output="-P INPUT ACCEPT\n", host_addresses=HOSTS, nat_rules=rules,
                                   other_tables={"raw": "-P PREROUTING ACCEPT\n"
                                                        "-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"},
                                   nat_prerouting=True)
        assert s.port_verdict(8099, "tcp") == D


class TestTheRulesRead:

    @pytest.mark.parametrize("text, rule", [
        ("tcp dport 8099 redirect to :9999", ("tcp", ((8099, 8099),), True, None, 9999)),
        ("tcp dport 8080 dnat to 10.77.0.2:8099", ("tcp", ((8080, 8080),), False, "10.77.0.2", 8099)),
        ("tcp dport 8080 dnat ip to 10.77.0.2:8099", ("tcp", ((8080, 8080),), False, "10.77.0.2", 8099)),
        ("meta l4proto tcp redirect to :9999", ("tcp", (), True, None, 9999)),
        ("tcp dport 8099 dnat to 10.77.0.2", ("tcp", ((8099, 8099),), False, "10.77.0.2", None)),
        ("tcp dport { 80, 443 } redirect to :8443", ("tcp", ((80, 80), (443, 443)), True, None, 8443)),
        ("tcp dport 8000-8010 redirect to :8099", ("tcp", ((8000, 8010),), True, None, 8099)),
        ("udp dport 53 redirect to :5353", ("udp", ((53, 53),), True, None, 5353)),
        ("tcp dport 8099 redirect", ("tcp", ((8099, 8099),), True, None, None)),
        ("ip protocol tcp tcp dport { 80, 443 } counter packets 0 bytes 0 redirect to :8443",
         ("tcp", ((80, 80), (443, 443)), True, None, 8443)),
    ])
    def test_nft(self, text, rule):
        got = nf._nft_nat_rules(_nat(text))
        assert [(r["proto"], r["ports"], r["redirect"], r["addr"], r["to"]) for r in got] == [rule]

    @pytest.mark.parametrize("text", [
        'iifname "s0" tcp dport 8099 redirect to :9999', "ip saddr 192.0.2.0/24 tcp dport 8099 redirect to :9999",
        "jump DOCKER", "fib daddr type local jump DOCKER", "tcp dport 8099 redirect to :9000-9010",
        "tcp dport 8099 dnat to 10.77.0.2:9000-9010", "tcp dport @ports redirect to :9999",
    ])
    def test_nft_not_followed(self, text):
        assert nf._nft_nat_rules(_nat(text)) is None

    def test_two_nft_chains_not_ordered(self):
        assert nf._nft_nat_rules(_nat("tcp dport 1 redirect to :2") + _nat("tcp dport 3 redirect to :4", table="m")) is None

    def test_postrouting_and_empty_chains_hold_none(self):
        post = _nat("oifname lo masquerade").replace("hook prerouting", "hook postrouting")
        assert nf._nft_nat_rules(post + _nat()) == []

    @pytest.mark.parametrize("line, rule", [
        ("-A PREROUTING -p tcp -m tcp --dport 8099 -j REDIRECT --to-ports 9999", ("tcp", ((8099, 8099),), True, 9999)),
        ("-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.77.0.2:8099",
         ("tcp", ((8080, 8080),), False, 8099)),
        ("-A PREROUTING -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8443",
         ("tcp", ((80, 80), (443, 443)), True, 8443)),
        ("-A PREROUTING -p tcp -m tcp --dport 8000:8010 -j REDIRECT --to-ports 8099", ("tcp", ((8000, 8010),), True, 8099)),
        ("-A PREROUTING -p tcp -m tcp --dport 8099 -j DNAT --to-destination 10.77.0.2", ("tcp", ((8099, 8099),), False, None)),
    ])
    def test_iptables(self, line, rule):
        got = nf._ipt_nat_rules("-P PREROUTING ACCEPT\n" + line + "\n")
        assert [(r["proto"], r["ports"], r["redirect"], r["to"]) for r in got] == [rule]

    @pytest.mark.parametrize("line", [
        "-A PREROUTING -i s0 -p tcp -m tcp --dport 8099 -j REDIRECT --to-ports 9999",
        "-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER",
        "-A PREROUTING ! -s 192.0.2.0/24 -p tcp -m tcp --dport 8099 -j REDIRECT --to-ports 9999",
    ])
    def test_iptables_not_followed(self, line):
        assert nf._ipt_nat_rules(line + "\n") is None

    def test_iptables_not_read(self):
        assert nf._ipt_nat_rules(None) is None


class TestTheEffect:

    @staticmethod
    def _rules(*rules):
        return nf._nft_nat_rules(_nat(*rules))

    @pytest.mark.parametrize("rules, effect", [
        (["tcp dport 8099 redirect to :9999"], "away"),
        (["tcp dport 7000 redirect to :7001"], "untouched"),
        (["tcp dport 8080 redirect to :8099"], "brought"),
        (["tcp dport 8099 dnat to 192.0.2.10:80"], "away"),
        (["tcp dport 8099 dnat to 192.0.2.10"], "away"),
        (["meta l4proto tcp redirect to :9999"], "away"),
        (["tcp dport 8099 dnat to 10.77.0.2"], "untouched"),
        (["tcp dport 8099 redirect"], "untouched"),
        (["udp dport 8099 redirect to :9999"], "untouched"),
        (["tcp dport 8000-8010 redirect to :8099"], "brought"),
        (["tcp dport 8099 redirect to :8099"], "untouched"),
        (["tcp dport 8099 redirect to :9999", "tcp dport 8099 redirect to :8099"], "away"),
        (["tcp dport 8099 redirect to :8099", "tcp dport 8099 redirect to :9999"], "untouched"),
    ], ids=["away", "another-port", "brought", "dnat-elsewhere", "dnat-elsewhere-same-port", "every-port", "dnat-own-same-port",
            "redirect-same-port", "another-protocol", "range-brought", "to-itself", "first-wins-away",
            "first-wins-kept"])
    def test_it(self, rules, effect):
        assert nf._nat_effect(8099, "tcp", self._rules(*rules), HOSTS) == effect

    def test_none_followed(self):
        assert nf._nat_effect(8099, "tcp", None, HOSTS) is None

    def test_a_dnat_needs_the_host_addresses(self):
        assert nf._nat_effect(8099, "tcp", self._rules("tcp dport 8099 dnat to 10.77.0.2:9999"), None) is None
        assert nf._nat_effect(8099, "tcp", self._rules("tcp dport 8099 redirect to :9999"), None) == "away"

    def test_a_dnat_to_loopback_is_not_followed(self):
        """With route_localnet on (kube-proxy sets it), a dnat to 127.0.0.1
        reaches a local listener: neither "away" nor "untouched" can be said."""
        assert nf._nat_effect(8099, "tcp", self._rules("tcp dport 8080 dnat to 127.0.0.1:8099"), HOSTS) is None
        assert nf._nat_effect(8099, "tcp", self._rules("tcp dport 8099 dnat to 127.0.0.1:9999"), HOSTS) is None


class TestTheSources:

    A = [{"proto": "tcp", "ports": ((8099, 8099),), "redirect": True, "addr": None, "to": 9999}]
    B = [{"proto": "tcp", "ports": ((7000, 7000),), "redirect": True, "addr": None, "to": 7001}]

    def test_one_source(self):
        assert nf._nat_rules_of([], self.A, []) == self.A

    def test_the_same_rules_shown_twice_count_once(self):
        """iptables-nft's nat table, in nft's ruleset and through iptables."""
        assert nf._nat_rules_of(self.A, list(self.A)) == self.A

    def test_two_sources_not_ordered(self):
        assert nf._nat_rules_of(self.A, self.B) is None

    def test_one_not_followed(self):
        assert nf._nat_rules_of(self.A, None) is None

    def test_none(self):
        assert nf._nat_rules_of([], []) == []

    def test_iptables_nft_seen_both_ways_is_one_source(self):
        nft = nf._nft_nat_rules(_nat("tcp dport 8099 counter packets 0 bytes 0 redirect to :9999",
                                     "ip protocol tcp tcp dport { 80, 443 } counter packets 0 bytes 0 redirect to :8443"))
        ipt = nf._ipt_nat_rules("-P PREROUTING ACCEPT\n"
                                "-A PREROUTING -p tcp -m tcp --dport 8099 -j REDIRECT --to-ports 9999\n"
                                "-A PREROUTING -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8443\n")
        assert nf._nat_rules_of(nft, ipt) == nft

    @pytest.mark.parametrize("res, text", [
        (("-P PREROUTING ACCEPT\n", True, ""), "-P PREROUTING ACCEPT\n"),
        (("", False, "iptables: Table does not exist (do you need to insmod?)"), ""),
        (("", False, "Permission denied (you must be root)"), None),
    ], ids=["read", "no-table", "refused"])
    def test_the_nat_table_text(self, monkeypatch, res, text):
        from bob.checks._run import CommandResult
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: CommandResult(stdout=res[0], ok=res[1], stderr=res[2]))
        assert nf._ipt_nat_text() == text

    @pytest.mark.parametrize("names, binary, text", [
        (FileNotFoundError, True, ""), (PermissionError, True, None), ("filter\n", True, ""),
        ("nat\nfilter\n", False, None), ("nat\nfilter\n", True, "-A PREROUTING x\n"),
    ], ids=["no-legacy", "list-unread", "no-nat", "no-binary", "nat-read"])
    def test_the_legacy_nat_text(self, monkeypatch, names, binary, text):
        import io

        def fake_open(path, *a, **k):
            if isinstance(names, type):
                raise names(path)
            return io.StringIO(names)
        monkeypatch.setattr(nf, "open", fake_open, raising=False)
        monkeypatch.setattr(nf, "_command_exists", lambda n: binary and n == "iptables-legacy")
        monkeypatch.setattr(nf, "_ipt_nat_text", lambda b="iptables": "-A PREROUTING x\n" if b == "iptables-legacy" else None)
        assert nf._legacy_nat_text() == text

    def test_read_with_the_ruleset(self):
        src = inspect.getsource(nf.IptablesNftSnapshot.from_system)
        assert "nat_rules=_nat_rules_of(_nft_nat_rules(raw), _ipt_nat_rules(_legacy_nat_text()))," in src
        assert "nat_rules=_nat_rules_of(_ipt_nat_rules(_ipt_nat_text())," in src
        assert "_nft_nat_rules(nft_raw) if nft_raw else []," in src


class TestWhatIsSaid:

    # Review of the 0.31.0 changelog (7 November 2026): "not reached on this
    # port from the network" read as "the port is closed". Measured on Kali in
    # namespaces (review-dnat.txt): a DNAT of 8099 to a backend that serves it
    # — the host's 8099 answered, from the backend; the host's own listener
    # was reached in none of the three NAT cases. The text names the listener.

    @pytest.mark.parametrize("lang, words", [
        ("en", "a NAT rule of the nftables/iptables ruleset sends this port's new connections elsewhere (another port or another host): this listener is not reached through it — whatever answers there instead is not weighed by this finding"),
        ("fr", "une règle NAT du jeu de règles nftables/iptables envoie ailleurs (un autre port ou une autre machine) les nouvelles connexions vers ce port : ce service n'y est pas atteint — ce qui y répond à sa place n'est pas évalué par ce constat"),
    ])
    def test_the_ports_line(self, lang, words):
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        snap = PortsSnapshot(ports=[ListeningPort(port=8099, proto="tcp", address="0.0.0.0", raw_line="", process="web")],
                             ufw_rules="", ss_output="")
        i18n.init(lang)
        try:
            res = check_ports(snap, ufw_active=False, t=i18n.t, netfilter_partial=True,
                              netfilter_port_verdict=lambda p, pr: DN)
        finally:
            i18n.init("en")
        assert any(words in f.message for f in res.findings)
        assert not res.deductions

    def test_the_services_line(self):
        from bob.checks.services import _port_weighed
        assert _port_weighed(lambda p, pr: DN, "8099/tcp") == "ports.netfilter_port.drop_nat"
