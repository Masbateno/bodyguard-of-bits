"""v0.29.0 — the inbound default (IPv4 posture, IPv6 default) reads the chains before input.

0.28.0 weighed refusals before the input hook port by port, but the hook's
default verdict still read input alone. Measured in a network namespace (31
October 2026, `~/.cache/bob-fieldtest/netnsbench/posturebench.sh`), input at
policy accept, listeners 8098 and 8099 over IPv4 and IPv6:

- a drop for 8099 in an nft `ip` prerouting chain (raw priority), a netdev
  ingress chain, an `inet` prerouting chain at policy drop, or `iptables -t
  raw|mangle|security`, closed 8099 over IPv4 — BOB said "INPUT ACCEPT, no
  rule refuses it" (−3); likewise with no nft input chain at all;
- over IPv6, ingress, the inet prerouting chain, an `ip6` prerouting drop and
  `ip6tables -t raw` closed it — BOB said IPv6 inbound accepted by default;
- a mark, an `ip6` chain for IPv4, an `ip` chain for IPv6, and a drop aimed
  at an address that is not the host's (`ip daddr 172.17.0.2 iifname !=
  "docker0" drop`, Docker's own raw rule, measured with Docker 29) left both
  open — and for the last one 0.28.0 made every port of the host not
  established (`-d 172.17.0.2/32 ! -i docker0 -j DROP`, port 22 included).
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf

HOSTS = "1: lo    inet 127.0.0.1/8 scope host lo\n" \
        "2: s0    inet 10.77.0.2/24 brd 10.77.0.255 scope global s0\n" \
        "2: s0    inet6 fd77::2/64 scope global \n"

INPUT = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n")


def _pre(family, rule, hook="prerouting", policy="accept", device=""):
    dev = f' device "{device}"' if device else ""
    return (f"table {family} r {{\n\tchain pre {{\n"
            f"\t\ttype filter hook {hook}{dev} priority raw; policy {policy};\n"
            + (f"\t\t{rule}\n" if rule else "") + "\t}\n}\n")


class _Res:
    def __init__(self, stdout, ok=True, stderr=""):
        self.stdout, self.ok, self.stderr = stdout, ok, stderr


def _system(monkeypatch, *, nft=None, ipt=None, ip6t=None, tables=None, tables6=None, ip=HOSTS):
    """Commands as the host answers them: nft's ruleset, `iptables -S`,
    `ip6tables -S`, `iptables -t T -S` (a dict, or None: refused), `ip -o addr`."""
    present = {n for n, v in (("nft", nft), ("iptables", ipt), ("ip6tables", ip6t)) if v is not None}
    monkeypatch.setattr(nf, "_command_exists", lambda name: name in present)
    monkeypatch.setattr(nf, "_run", lambda *a, **k: {"iptables": ipt, "ip6tables": ip6t}.get(a[0]) or "")

    def run_result(*a, **k):
        if a[:2] == ("nft", "list"):
            return _Res(nft or "")
        if a[0] == "ip":
            return _Res(ip or "", ok=ip is not None)
        if a[1:2] == ("-t",):
            got = tables if a[0] == "iptables" else tables6
            if got is None:
                return _Res("", ok=False, stderr="Permission denied")
            return _Res(got.get(a[2], ""))
        raise AssertionError(a)
    monkeypatch.setattr(nf, "run_result", run_result)


def _ipt(policy="ACCEPT", *rules):
    return "\n".join([f"-P INPUT {policy}", "-P FORWARD DROP", "-P OUTPUT ACCEPT", *rules]) + "\n"


class TestTheIPv4Default:

    @pytest.mark.parametrize("extra, policy", [
        ("", "ACCEPT"),
        (_pre("ip", "tcp dport 8099 drop"), "PARTIAL"),
        (_pre("netdev", "tcp dport 8099 drop", hook="ingress", device="s0"), "PARTIAL"),
        (_pre("inet", "tcp dport 8098 accept", policy="drop"), "PARTIAL"),
        (_pre("ip", "tcp dport 8099 meta mark set 0x00000001"), "ACCEPT"),
        (_pre("ip6", "tcp dport 8099 drop"), "ACCEPT"),
        (_pre("ip", "tcp dport 9000 drop"), "PARTIAL"),
        (_pre("ip", 'ip daddr 172.17.0.2 iifname != "docker0" counter packets 0 bytes 0 drop'), "ACCEPT"),
        (_pre("ip", "ip daddr 10.77.0.2 tcp dport 8099 drop"), "PARTIAL"),
    ], ids=["P0-nothing", "P1-prerouting", "P2-ingress", "P3-policy-drop", "P4-mark", "P5-ip6-is-not-ipv4",
            "P6-another-port", "P8-not-this-host", "P9-this-host"])
    def test_nftables(self, monkeypatch, extra, policy):
        _system(monkeypatch, nft=INPUT + extra)
        assert nf.IptablesNftSnapshot.from_system().input_policy == policy

    def test_addresses_not_read_count_the_refusal(self, monkeypatch):
        _system(monkeypatch, nft=INPUT + _pre("ip", 'ip daddr 172.17.0.2 iifname != "docker0" drop'), ip=None)
        assert nf.IptablesNftSnapshot.from_system().input_policy == "PARTIAL"

    def test_a_restrictive_input_stays_as_it_is(self, monkeypatch):
        _system(monkeypatch, nft=INPUT.replace("policy accept", "policy drop") + _pre("ip", "tcp dport 8099 drop"))
        assert nf.IptablesNftSnapshot.from_system().input_policy == "DROP"

    @pytest.mark.parametrize("tables, policy", [
        ({}, "ACCEPT"),
        ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}, "PARTIAL"),
        ({"mangle": "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n"}, "PARTIAL"),
        ({"security": "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n"}, "PARTIAL"),
        ({"mangle": "-P PREROUTING ACCEPT\n-A PREROUTING -p tcp --dport 8099 -j MARK --set-xmark 0x1/0xffffffff\n"},
         "ACCEPT"),
        ({"raw": "-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP\n"}, "ACCEPT"),
        ({"raw": "-A PREROUTING -d 10.77.0.2/32 -p tcp -m tcp --dport 8099 -j DROP\n"}, "PARTIAL"),
        (None, "unknown"),
    ], ids=["L0-nothing", "L1-raw", "L2-mangle-input", "L3-security", "mark", "L6-docker", "L7-this-host",
            "unread"])
    def test_iptables_s(self, monkeypatch, tables, policy):
        _system(monkeypatch, ipt=_ipt(), tables=tables)
        assert nf.IptablesNftSnapshot.from_system().input_policy == policy

    def test_nft_without_an_input_hook_still_refuses_first(self, monkeypatch):
        """P7: nft answers with a prerouting drop and no input chain; BOB
        reads the host through `iptables -S`."""
        _system(monkeypatch, nft=_pre("ip", "tcp dport 8099 drop"), ipt=_ipt(), tables={})
        s = nf.IptablesNftSnapshot.from_system()
        assert (s.backend, s.input_policy) == ("iptables", "PARTIAL")
        assert s.port_verdict(8099, "tcp") == ("UNKNOWN", "")
        assert s.port_verdict(8098, "tcp") == ("ACCEPT", "default")


class TestThePortVerdicts:
    """Docker's raw rule no longer makes every port not established."""

    def test_iptables(self, monkeypatch):
        _system(monkeypatch, ipt=_ipt("ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j DROP"),
                tables={"raw": "-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP\n"})
        s = nf.IptablesNftSnapshot.from_system()
        assert [s.port_verdict(p, "tcp")[0] for p in (22, 8098, 8099)] == ["DROP", "ACCEPT", "ACCEPT"]

    def test_nftables(self, monkeypatch):
        _system(monkeypatch, nft=INPUT + _pre("ip", 'ip daddr 172.17.0.2 iifname != "docker0" drop'))
        s = nf.IptablesNftSnapshot.from_system()
        assert s.port_verdict(8099, "tcp") == ("ACCEPT", "default")

    def test_without_the_addresses_it_is_not_established(self):
        rules = _ipt("ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j DROP")
        tables = {"raw": "-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP\n"}
        assert nf.ipt_port_verdict(rules, 8099, "tcp", tables) == ("UNKNOWN", "")


class TestTheIPv6Default:

    @pytest.mark.parametrize("extra, policy", [
        ("", "ACCEPT"),
        (_pre("ip", "tcp dport 8099 drop"), "ACCEPT"),
        (_pre("netdev", "tcp dport 8099 drop", hook="ingress", device="s0"), "PARTIAL"),
        (_pre("inet", "tcp dport 8098 accept", policy="drop"), "PARTIAL"),
        (_pre("ip6", "tcp dport 8099 drop"), "PARTIAL"),
        (_pre("ip6", "ip6 daddr fd99::5 drop"), "ACCEPT"),
    ], ids=["P0-nothing", "P1-ip-is-not-ipv6", "P2-ingress", "P3-policy-drop", "P5-ip6", "not-this-host"])
    def test_nftables(self, monkeypatch, extra, policy):
        _system(monkeypatch, nft=INPUT + extra)
        assert nf.read_input_policy_v6() == policy

    def test_no_ipv6_input_chain(self):
        assert nf.nft_input_policy_v6(_pre("ip6", "tcp dport 8099 drop")) == "PARTIAL"
        assert nf.nft_input_policy_v6(_pre("ip6", "meta mark set 0x1")) is None

    @pytest.mark.parametrize("tables6, policy", [
        ({}, "ACCEPT"),
        ({"raw": "-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}, "PARTIAL"),
        ({"mangle": "-A PREROUTING -p tcp -m tcp --dport 8099 -j MARK --set-xmark 0x1/0xffffffff\n"}, "ACCEPT"),
        (None, "unknown"),
    ], ids=["nothing", "L4-raw", "L5-mark", "unread"])
    def test_ip6tables_s(self, monkeypatch, tables6, policy):
        _system(monkeypatch, ip6t=_ipt(), tables6=tables6)
        assert nf.read_input_policy_v6() == policy

    def test_ip6tables_reads_its_own_tables(self, monkeypatch):
        calls = []
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: calls.append(a) or _Res(""))
        nf._ipt_other_tables("ip6tables")
        assert {a[0] for a in calls} == {"ip6tables"}


class TestTheHostAddresses:

    def test_read_from_ip(self, monkeypatch):
        import ipaddress
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: _Res(HOSTS))
        assert nf._host_addresses() == {ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2", "fd77::2")}

    def test_not_read(self, monkeypatch):
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: _Res("", ok=False))
        assert nf._host_addresses() is None
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: _Res(""))
        assert nf._host_addresses() is None

    @pytest.mark.parametrize("text, nft, elsewhere", [
        ('ip daddr 172.17.0.2 iifname != "docker0" drop', True, True),
        ("ip daddr { 172.17.0.2, 172.17.0.3 } drop", True, True),
        ("ip daddr { 172.17.0.2, 10.77.0.2 } drop", True, False),
        ("ip daddr != 172.17.0.2 drop", True, False),
        ("ip daddr @containers drop", True, False),
        ("tcp dport 8099 drop", True, False),
        ("-A PREROUTING -d 172.17.0.0/16 ! -i docker0 -j DROP", False, True),
        ("-A PREROUTING -d 10.0.0.0/8 -j DROP", False, False),
        ("-A PREROUTING ! -d 172.17.0.2/32 -j DROP", False, False),
    ])
    def test_aimed_elsewhere(self, text, nft, elsewhere):
        import ipaddress
        hosts = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2", "fd77::2"))
        assert nf._aimed_elsewhere(text, hosts, nft=nft) is elsewhere
        assert nf._aimed_elsewhere(text, None, nft=nft) is False


@pytest.mark.parametrize("lang, key, words", [
    # Review of the 0.29.0 changelog: mangle and security INPUT run on the
    # input hook (after filter's INPUT for security), not before it.
    ("en", "firewall_iptables.input_accept_unweighed", "on the input hook, filter's INPUT or the mangle or security table's, or before it"),
    ("fr", "firewall_iptables.input_accept_unweighed", "au hook input, INPUT de filter ou celle de la table mangle ou security, ou avant lui"),
    ("en", "firewall_iptables.input_accept_unweighed_detail", "or on it in another table (mangle or security INPUT, even after filter's INPUT accepted the port)"),
    ("fr", "firewall_iptables.input_accept_unweighed_detail", "ou sur lui dans une autre table (INPUT de mangle ou de security, même après qu'INPUT de filter a accepté le port)"),
    ("en", "firewall_iptables.input_accept_unweighed_detail", "The default named here is the input hook's"),
    ("fr", "firewall_iptables.input_accept_unweighed_detail", "Le défaut nommé ici est celui du hook input"),
    ("en", "firewall_iptables.input_accept_unweighed_detail", "except one aimed at addresses that are not this host's"),
    ("fr", "firewall_iptables.input_accept_unweighed_detail", "sauf s'il vise des adresses qui ne sont pas celles de l'hôte"),
    ("en", "firewall_iptables.input_accept", "addresses that are not this host's"),
    ("fr", "firewall_iptables.input_accept", "d'adresses qui ne sont pas celles de l'hôte"),
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key)
    finally:
        i18n.init(lang="en")


class TestAChainAtPolicyDropIsNamed:
    """v0.29.0, review of the changelog — a chain on the way in at policy
    drop refuses by default what it does not accept. Measured in a network
    namespace (31 October 2026): an inet prerouting chain at policy drop
    accepting 8098 only closed 8099 while the input hook accepted by default.
    BOB said "accepts inbound by default, refuses some of it"; it now names
    the input policy, and the chain at policy drop. No points move."""

    @pytest.mark.parametrize("ruleset, chains", [
        (INPUT + _pre("inet", "tcp dport 8098 accept", policy="drop"), ["inet r pre"]),
        (INPUT + _pre("netdev", "", hook="ingress", policy="drop", device="s0"), ["netdev r pre"]),
        (INPUT + _pre("ip", "tcp dport 8099 drop"), []),
        (INPUT + _pre("ip6", "", policy="drop"), []),
    ], ids=["prerouting-drop", "ingress-drop", "a-rule-is-not-a-policy", "ip6-is-not-ipv4"])
    def test_nftables(self, ruleset, chains):
        assert nf._nft_default_drop_before_input(ruleset) == chains

    @pytest.mark.parametrize("tables, chains", [
        ({"raw": "-P PREROUTING DROP\n-P OUTPUT ACCEPT\n"}, ["raw PREROUTING"]),
        ({"mangle": "-P PREROUTING ACCEPT\n-P INPUT DROP\n"}, ["mangle INPUT"]),
        ({"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}, []),
        ({}, []),
        (None, []),
    ], ids=["raw-prerouting", "mangle-input", "a-rule-is-not-a-policy", "nothing", "unread"])
    def test_iptables(self, tables, chains):
        assert nf._ipt_default_drop_before_input(tables) == chains

    def _snap(self, chains):
        return nf.IptablesNftSnapshot(backend="nftables", input_policy="PARTIAL", forward_policy="DROP",
                                      has_loopback_rule=True, has_conntrack_rule=True, raw_output=INPUT,
                                      default_drop_before_input=chains)

    def test_said_by_name_without_points(self):
        res = nf.check_iptables_nftables(self._snap(["inet r pre"]), t=lambda k, **kw: f"{k}|{kw}")
        f = next(f for f in res.findings if f.key == "firewall_iptables.input_accept_unweighed")
        assert f.message.startswith("firewall_iptables.input_accept_default_drop|")
        assert "inet r pre" in f.message
        assert not res.deductions

    def test_otherwise_the_refusals_are_said(self):
        res = nf.check_iptables_nftables(self._snap([]), t=lambda k, **kw: k)
        f = next(f for f in res.findings if f.key == "firewall_iptables.input_accept_unweighed")
        assert f.message == "firewall_iptables.input_accept_unweighed"

    def test_read_from_nft(self, monkeypatch):
        ruleset = INPUT + _pre("inet", "tcp dport 8098 accept", policy="drop")
        monkeypatch.setattr(nf, "_command_exists", lambda name: name == "nft")
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: type(
            "R", (), {"ok": True, "stdout": ruleset if a[:1] == ("nft",) else HOSTS, "stderr": ""})())
        s = nf.IptablesNftSnapshot.from_system()
        assert (s.backend, s.input_policy, s.default_drop_before_input) == ("nftables", "PARTIAL", ["inet r pre"])

    def test_read_from_iptables(self, monkeypatch):
        monkeypatch.setattr(nf, "_command_exists", lambda name: name == "iptables")
        monkeypatch.setattr(nf, "_run", lambda *a, **k: "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n")
        monkeypatch.setattr(nf, "_host_addresses", lambda: None)
        monkeypatch.setattr(nf, "_ipt_other_tables", lambda *a: {"raw": "-P PREROUTING DROP\n"})
        s = nf.IptablesNftSnapshot.from_system()
        assert (s.backend, s.input_policy, s.default_drop_before_input) == ("iptables", "PARTIAL", ["raw PREROUTING"])

    @pytest.mark.parametrize("lang, words", [
        ("en", "is at policy drop (inet r pre): it refuses by default what it does not accept"),
        ("fr", "est en politique drop (inet r pre) : elle refuse par défaut ce qu'elle n'accepte pas"),
    ])
    def test_what_is_said(self, lang, words):
        i18n.init(lang)
        try:
            assert words in i18n.t("firewall_iptables.input_accept_default_drop", chains="inet r pre")
        finally:
            i18n.init(lang="en")
