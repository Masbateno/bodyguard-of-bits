"""v0.30.0 — the per-port verdict reads named sets, verdict maps and destinations.

0.29.0 wrote the limit: a named set, a verdict map, and a rule written with a
destination before its port left a port not established — and, the bench
showed, every other port of the chain too. Measured in a network namespace
(31 October 2026, `~/.cache/bob-fieldtest/netnsbench/p3bench.sh`, listeners
8098 and 8099, input at policy accept with a drop for 22):

| case | probe | 0.29.0 | 0.30.0 |
|---|---|---|---|
| D1 `ip daddr <host's only address> tcp dport 8099 drop` | 8098 open, 8099 closed | both not established | 8098 accepted, 8099 refused |
| D2 `ip daddr <another address> tcp dport 8099 drop` | both open | both not established | both accepted |
| D3 two host addresses, the drop for one | 8099 closed on one, open on the other | both not established | 8098 accepted, 8099 not established |
| D4 two host addresses, the drop for both | 8099 closed | both not established | 8098 accepted, 8099 refused |
| S1 `tcp dport @blk drop`, blk = { 8099 } | 8099 closed | both not established | 8098 accepted, 8099 refused |
| S2 the same, blk empty | both open | both not established | both accepted |
| V1 `tcp dport vmap { 8099 : drop }` | 8099 closed | both not established | 8098 accepted, 8099 refused |
| V2 `tcp dport vmap @vm`, vm = { 8099 : drop } | 8099 closed | both not established | 8098 accepted, 8099 refused |
| I1 `-d <host's only address> … --dport 8099 -j DROP` | 8099 closed | both not established | 8098 accepted, 8099 refused |
| I2 `-d <another address> … --dport 8099 -j DROP` | both open | both not established | both accepted |
"""

from __future__ import annotations

import ipaddress

import pytest

from bob.checks import iptables_nftables as nf

A, D, U = ("ACCEPT", "rule"), ("DROP", "rule"), ("UNKNOWN", "")
AD = ("ACCEPT", "default")

ONE = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2", "fd77::2"))
TWO = ONE | {ipaddress.ip_address("10.77.0.3")}


def _nft(*rules, sets=""):
    body = "".join(f"\t\t{r}\n" for r in ("tcp dport 22 drop", *rules))
    return ("table inet f {\n" + sets
            + "\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
            + body + "\t}\n}\n")


def _ipt(*rules):
    return "\n".join(["-P INPUT ACCEPT", "-P FORWARD DROP", "-P OUTPUT ACCEPT",
                      "-A INPUT -p tcp -m tcp --dport 22 -j DROP", *rules]) + "\n"


SET_BLK = "\tset blk {\n\t\ttype inet_service\n\t\telements = { 8099 }\n\t}\n\n"
SET_EMPTY = "\tset blk {\n\t\ttype inet_service\n\t}\n\n"
MAP_VM = "\tmap vm {\n\t\ttype inet_service : verdict\n\t\telements = { 8099 : drop }\n\t}\n\n"

MEASURED = {
    "D1": (_nft("ip daddr 10.77.0.2 tcp dport 8099 drop"), ONE, AD, D),
    "D2": (_nft("ip daddr 10.77.0.9 tcp dport 8099 drop"), ONE, AD, AD),
    "D3": (_nft("ip daddr 10.77.0.2 tcp dport 8099 drop"), TWO, AD, U),
    "D4": (_nft("ip daddr { 10.77.0.2, 10.77.0.3 } tcp dport 8099 drop"), TWO, AD, D),
    "D-after-port": (_nft("tcp dport 8099 ip daddr 10.77.0.2 drop"), ONE, AD, D),
    "S1": (_nft("tcp dport @blk drop", sets=SET_BLK), ONE, AD, D),
    "S2": (_nft("tcp dport @blk drop", sets=SET_EMPTY), ONE, AD, AD),
    "V1": (_nft("tcp dport vmap { 8099 : drop }"), ONE, AD, D),
    "V2": (_nft("tcp dport vmap @vm", sets=MAP_VM), ONE, AD, D),
}


@pytest.mark.parametrize("name", MEASURED)
def test_the_measured_nft_cases(name):
    ruleset, hosts, v8098, v8099 = MEASURED[name]
    assert (nf.nft_port_verdict(ruleset, 8098, "tcp", hosts),
            nf.nft_port_verdict(ruleset, 8099, "tcp", hosts)) == (v8098, v8099)


@pytest.mark.parametrize("rule, v8099", [("-A INPUT -d 10.77.0.2/32 -p tcp -m tcp --dport 8099 -j DROP", D),
                                         ("-A INPUT -d 10.77.0.9/32 -p tcp -m tcp --dport 8099 -j DROP", AD)],
                         ids=["I1", "I2"])
def test_the_measured_iptables_cases(rule, v8099):
    assert nf.ipt_port_verdict(_ipt(rule), 8098, "tcp", {}, ONE) == AD
    assert nf.ipt_port_verdict(_ipt(rule), 8099, "tcp", {}, ONE) == v8099


class TestWhatStaysNotEstablished:

    def test_the_hosts_addresses_not_read(self):
        ruleset = _nft("ip daddr 10.77.0.2 tcp dport 8099 drop")
        assert nf.nft_port_verdict(ruleset, 8099, "tcp", None) == U
        assert nf.nft_port_verdict(ruleset, 8098, "tcp", None) == AD

    def test_a_negated_destination(self):
        assert nf.nft_port_verdict(_nft("ip daddr != 10.77.0.9 tcp dport 8099 drop"), 8099, "tcp", ONE) == U

    @pytest.mark.parametrize("flags", ["flags dynamic", "flags timeout", "flags dynamic,timeout"])
    def test_a_set_updated_at_run_time(self, flags):
        sets = f"\tset blk {{\n\t\ttype inet_service\n\t\t{flags}\n\t\telements = {{ 8099 }}\n\t}}\n\n"
        assert nf.nft_port_verdict(_nft("tcp dport @blk drop", sets=sets), 8099, "tcp", ONE) == U

    def test_a_set_bob_cannot_find(self):
        assert nf.nft_port_verdict(_nft("tcp dport @nowhere drop"), 8099, "tcp", ONE) == U

    def test_a_set_not_keyed_by_port(self):
        sets = "\tset blk {\n\t\ttype ipv4_addr\n\t\telements = { 10.77.0.9 }\n\t}\n\n"
        assert nf.nft_port_verdict(_nft("ip saddr @blk tcp dport 8099 drop", sets=sets), 8099, "tcp", ONE) == U

    def test_a_map_verdict_that_jumps(self):
        assert nf.nft_port_verdict(_nft("tcp dport vmap { 8099 : jump x }"), 8099, "tcp", ONE) == U


class TestTheSets:

    def test_elements_over_several_lines(self):
        ruleset = ("table inet f {\n\tset blk {\n\t\ttype inet_service\n\t\tflags interval\n"
                   "\t\telements = { 22, 80,\n\t\t\t     8090-8099 }\n\t}\n}\n")
        s = nf._nft_sets(ruleset)[("inet", "f", "blk")]
        assert s["elements"] == "22, 80, 8090-8099" and s["flags"] == "interval"
        assert nf.nft_port_verdict(_nft("tcp dport @blk drop", sets=ruleset.split("{\n", 1)[1].rsplit("}", 1)[0]),
                                   8095, "tcp", ONE) == D

    def test_a_map(self):
        s = nf._nft_sets("table inet f {\n" + MAP_VM + "}\n")[("inet", "f", "vm")]
        assert (s["kind"], s["type"], s["elements"]) == ("map", "inet_service : verdict", "8099 : drop")

    def test_another_tables_set_is_not_this_ones(self):
        other = "table inet g {\n" + SET_BLK + "}\n"
        assert nf.nft_port_verdict(other + _nft("tcp dport @blk drop"), 8099, "tcp", ONE) == U


@pytest.mark.parametrize("spec, hosts, cover", [
    ("10.77.0.2", ONE, "all"), ("10.77.0.0/24", ONE, "all"), ("10.77.0.9", ONE, "none"),
    ("10.77.0.2", TWO, "some"), ("{ 10.77.0.2, 10.77.0.3 }", TWO, "all"),
    ("10.77.0.2", None, None), ("fd77::2", ONE, None), ("not-an-address", ONE, None),
    ("127.0.0.1", ONE, "none"),
])
def test_the_cover(spec, hosts, cover):
    assert nf._daddr_cover(spec, hosts) == cover


def _localnet(value):
    view = nf._HostView(ONE)
    view.localnet = value
    return view


class TestRouteLocalnet:
    """Measured in a network namespace (2 November 2026,
    `~/.cache/bob-fieldtest/netnsbench/localnetbench.txt`): with
    `route_localnet` 1, a client sending to 127.0.0.1 over the wire reached a
    listener on 0.0.0.0 — and one bound to 127.0.0.1 alone; past
    `ip daddr 10.77.0.2 tcp dport 8099 drop` 8099 stayed reachable that way,
    and BOB read it refused. At 0 the wire reached nothing at 127.0.0.1."""

    @pytest.mark.parametrize("spec, cover", [
        ("10.77.0.2", "some"), ("{ 10.77.0.2, 127.0.0.1 }", "some"), ("127.0.0.1", "some"),
        ("{ 10.77.0.2, 127.0.0.0/8 }", "all"), ("0.0.0.0/0", "all"), ("10.77.0.9", "none"),
    ])
    @pytest.mark.parametrize("value", [True, None], ids=["on", "not-read"])
    def test_the_cover(self, spec, cover, value):
        assert nf._daddr_cover(spec, _localnet(value)) == cover

    def test_off_the_wire_reaches_no_loopback(self):
        assert nf._daddr_cover("10.77.0.2", _localnet(False)) == "all"
        assert nf._daddr_cover("127.0.0.1", _localnet(False)) == "none"

    @pytest.mark.parametrize("values, found", [
        ({"all": "0", "default": "1", "lo": "1", "s0": "0"}, False),
        ({"all": "1", "s0": "0"}, True),
        ({"all": "0", "s0": "1"}, True),
        ({"all": "0", "s0": None}, None),
    ], ids=["off", "all-on", "one-on", "one-unread"])
    def test_the_switch_read(self, monkeypatch, values, found):
        import io
        monkeypatch.setattr(nf.os, "listdir", lambda path: list(values))

        def fake_open(path, *a, **k):
            name = path.split("/")[-2]
            if values.get(name) is None:
                raise PermissionError(path)
            return io.StringIO(values[name] + "\n")
        monkeypatch.setattr(nf, "open", fake_open, raising=False)
        assert nf._route_localnet() is found

    def test_the_conf_not_listed(self, monkeypatch):
        def refused(path):
            raise PermissionError(path)
        monkeypatch.setattr(nf.os, "listdir", refused)
        assert nf._route_localnet() is None

    def test_read_with_the_addresses(self, monkeypatch):
        class R:
            ok, stdout, stderr, code = True, "2: s0    inet 10.77.0.2/24 scope global s0\n", "", 0
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: R())
        monkeypatch.setattr(nf, "_route_localnet", lambda: True)
        assert nf._host_addresses().localnet is True


@pytest.mark.parametrize("lang, words", [
    ("en", "a named port set, a verdict map keyed by port"),
    ("fr", "un set de ports nommé, une verdict map par port"),
])
def test_the_port_detail_says_it(lang, words):
    from bob import i18n
    i18n.init(lang)
    try:
        assert words in i18n.t("ports.netfilter_port.detail")
    finally:
        i18n.init(lang="en")
