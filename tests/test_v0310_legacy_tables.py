"""v0.31.0 — the legacy (x_tables) filter, raw, mangle and security tables beside nft.

0.30.0 wrote the limit: beside nft, a legacy ruleset was read for its NAT
table only. A packet passes both nft's chains and the legacy ones, so a
refusal in either closes the port. Measured in a network namespace (2
November 2026, `~/.cache/bob-fieldtest/netnsbench/a2bench.sh`,
`a2bench-fix.txt`, nft input accepting all but 22, listeners 8098 and 8099):

| case | probe 8099 | before | now |
|---|---|---|---|
| L2 legacy filter INPUT drops 8099 | closed | accepted (−1) | refused |
| L4 legacy filter INPUT at policy drop, accepts 8098 | closed | accepted (−1) | refused by default |
| L5 legacy raw PREROUTING drops 8099 | closed | accepted (−1) | refused |
| L6 legacy mangle INPUT drops 8099 | closed | accepted (−1) | refused |
| L7 legacy security INPUT drops 8099 | closed | accepted (−1) | refused |
| L9 legacy raw PREROUTING at policy drop, accepts 8098 | closed | accepted (−1) | refused by default |
| L3 nft drops 8099, legacy filter INPUT accepts it | closed | refused | refused |
| L0 legacy tables loaded and empty | open | accepted | accepted |

The posture too (`a2posture.sh`, `a2audit.sh`, full audits, nft input at
policy accept with no rule): a legacy drop for 8099, or legacy filter INPUT at
policy drop, read "INPUT ACCEPT — no rule refuses it" (−3) and "firewall
inactive" (the domain capped at 3/10), score 5; now the input policy is
accept with refusals on the way in, the legacy chain at policy drop named,
score ≤ 7 both.
"""

from __future__ import annotations

import inspect
import io
import ipaddress

import pytest

from bob.checks import iptables_nftables as nf
from bob.checks._run import CommandResult

D, U, A, AR, DD = ("DROP", "rule"), ("UNKNOWN", ""), ("ACCEPT", "default"), ("ACCEPT", "rule"), ("DROP", "default")
HOSTS = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2"))
NFT = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
       "\t\ttcp dport 22 drop\n\t}\n}\n")
FILTER = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
RAW = "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n"
MANGLE = "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"
SECURITY = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
EMPTY = {"filter": FILTER, "raw": RAW, "mangle": MANGLE, "security": SECURITY}
DROP_8099 = "-p tcp -m tcp --dport 8099 -j DROP\n"


def _snap(legacy, ruleset=NFT, nat_rules=None):
    return nf.IptablesNftSnapshot(backend="nftables", input_policy="PARTIAL", forward_policy="ACCEPT",
                                  has_loopback_rule=False, has_conntrack_rule=False, raw_output=ruleset,
                                  host_addresses=HOSTS, legacy_tables=legacy, nat_rules=nat_rules)


def _with(**tables):
    return {**EMPTY, **tables}


class TestTheMeasuredCases:

    @pytest.mark.parametrize("legacy, v8099", [
        (_with(filter=FILTER + "-A INPUT " + DROP_8099), D),
        (_with(filter=FILTER.replace("-P INPUT ACCEPT", "-P INPUT DROP") + "-A INPUT -p tcp -m tcp --dport 8098 -j ACCEPT\n"), DD),
        (_with(raw=RAW + "-A PREROUTING " + DROP_8099), D),
        (_with(mangle=MANGLE + "-A INPUT " + DROP_8099), D),
        (_with(security=SECURITY + "-A INPUT " + DROP_8099), D),
        (_with(raw=RAW.replace("-P PREROUTING ACCEPT", "-P PREROUTING DROP") + "-A PREROUTING -p tcp -m tcp --dport 8098 -j ACCEPT\n"), DD),
        # Eighth review of the changelog, measured on Kali (a2policy.txt): a
        # mangle or security chain at policy DROP closed 8099; 0.30.0 read it
        # accepted.
        (_with(mangle=MANGLE.replace("-P PREROUTING ACCEPT", "-P PREROUTING DROP") + "-A PREROUTING -p tcp -m tcp --dport 8098 -j ACCEPT\n"), DD),
        (_with(mangle=MANGLE.replace("-P INPUT ACCEPT", "-P INPUT DROP") + "-A INPUT -p tcp -m tcp --dport 8098 -j ACCEPT\n"), DD),
        (_with(security=SECURITY.replace("-P INPUT ACCEPT", "-P INPUT DROP") + "-A INPUT -p tcp -m tcp --dport 8098 -j ACCEPT\n"), DD),
        (EMPTY, A),
    ], ids=["L2", "L4", "L5", "L6", "L7", "L9", "M1", "M2", "M3", "L0"])
    def test_it(self, legacy, v8099):
        assert _snap(legacy).port_verdict(8099, "tcp") == v8099

    def test_a_legacy_accept_does_not_open_what_nft_drops(self):
        """L3."""
        ruleset = NFT.replace("tcp dport 22 drop", "tcp dport 22 drop\n\t\ttcp dport 8099 drop")
        assert _snap(_with(filter=FILTER + "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n"), ruleset).port_verdict(8099, "tcp") == D

    def test_a_legacy_accept_by_rule_is_opened_on_purpose(self):
        """L4's 8098: accepted by the legacy rule, no points."""
        legacy = _with(filter=FILTER.replace("-P INPUT ACCEPT", "-P INPUT DROP") + "-A INPUT -p tcp -m tcp --dport 8098 -j ACCEPT\n")
        assert _snap(legacy).port_verdict(8098, "tcp") == AR

    def test_tables_not_read(self):
        assert _snap(None).port_verdict(8099, "tcp") == U
        dropped = NFT.replace("tcp dport 22 drop", "tcp dport 8099 drop")
        assert _snap(None, dropped).port_verdict(8099, "tcp") == D

    def test_none_held_changes_nothing(self):
        assert _snap({}).port_verdict(8099, "tcp") == A

    def test_a_legacy_refusal_before_a_nat_that_brings_another_port(self):
        """Legacy raw PREROUTING runs before the NAT point, as iptables' own."""
        nat = ("table ip n {\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
               "\t\ttcp dport 8080 redirect to :8099\n\t}\n}\n")
        legacy = _with(raw=RAW + "-A PREROUTING " + DROP_8099)
        assert _snap(legacy, NFT + nat, nf._nft_nat_rules(NFT + nat)).port_verdict(8099, "tcp") == U

    def test_a_legacy_refusal_before_an_unrelated_nat(self):
        nat = ("table ip n {\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
               "\t\ttcp dport 7000 redirect to :7001\n\t}\n}\n")
        legacy = _with(raw=RAW + "-A PREROUTING " + DROP_8099)
        assert _snap(legacy, NFT + nat, nf._nft_nat_rules(NFT + nat)).port_verdict(8099, "tcp") == D


class TestTheTablesRead:

    @staticmethod
    def _patch(monkeypatch, names, binary=True, answers=None):
        def fake_open(path, *a, **k):
            if isinstance(names, type):
                raise names(path)
            return io.StringIO(names)
        monkeypatch.setattr(nf, "open", fake_open, raising=False)
        monkeypatch.setattr(nf, "_command_exists", lambda n: binary and n == "iptables-legacy")
        answers = answers or {}
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: answers.get(a[2], CommandResult(stdout="-P X ACCEPT\n", ok=True)))

    def test_no_legacy(self, monkeypatch):
        self._patch(monkeypatch, FileNotFoundError)
        assert nf._legacy_tables() == {}

    def test_list_not_read(self, monkeypatch):
        self._patch(monkeypatch, PermissionError)
        assert nf._legacy_tables() is None

    def test_nat_alone(self, monkeypatch):
        self._patch(monkeypatch, "nat\n")
        assert nf._legacy_tables() == {}

    def test_no_tool(self, monkeypatch):
        self._patch(monkeypatch, "filter\nraw\n", binary=False)
        assert nf._legacy_tables() is None

    def test_read(self, monkeypatch):
        self._patch(monkeypatch, "nat\nsecurity\nmangle\nraw\nfilter\n")
        assert set(nf._legacy_tables()) == {"filter", "raw", "mangle", "security"}

    def test_one_refused(self, monkeypatch):
        self._patch(monkeypatch, "filter\nraw\n", answers={"raw": CommandResult(stdout="", ok=False, stderr="denied")})
        assert nf._legacy_tables() is None

    def test_read_with_the_ruleset(self):
        src = inspect.getsource(nf.IptablesNftSnapshot.from_system)
        assert "legacy = _legacy_tables()" in src
        assert "raw, _nft_all_chains(raw), None, None, hosts=hosts), _legacy_refused(legacy, hosts)))," in src
        assert "legacy_tables=legacy," in src
        assert "default_drop_before_input=_nft_default_drop_before_input(raw) + _legacy_default_drop(legacy)," in src


class TestThePosture:

    @pytest.mark.parametrize("legacy, refused", [
        (None, None), (EMPTY, False),
        (_with(filter=FILTER + "-A INPUT " + DROP_8099), True),
        (_with(filter=FILTER.replace("-P INPUT ACCEPT", "-P INPUT DROP")), True),
        (_with(raw=RAW + "-A PREROUTING " + DROP_8099), True),
        (_with(mangle=MANGLE + "-A INPUT " + DROP_8099), True),
    ], ids=["not-read", "empty", "filter-drop", "filter-policy-drop", "raw-drop", "mangle-input-drop"])
    def test_refused(self, legacy, refused):
        assert nf._legacy_refused(legacy) is refused

    @pytest.mark.parametrize("legacy, named", [
        (EMPTY, []), (None, []), ({}, []),
        (_with(filter=FILTER.replace("-P INPUT ACCEPT", "-P INPUT DROP")), ["legacy filter INPUT"]),
        (_with(raw=RAW.replace("-P PREROUTING ACCEPT", "-P PREROUTING DROP")), ["legacy raw PREROUTING"]),
        (_with(mangle=MANGLE.replace("-P PREROUTING ACCEPT", "-P PREROUTING DROP")), ["legacy mangle PREROUTING"]),
        (_with(mangle=MANGLE.replace("-P INPUT ACCEPT", "-P INPUT DROP")), ["legacy mangle INPUT"]),
        (_with(security=SECURITY.replace("-P INPUT ACCEPT", "-P INPUT DROP")), ["legacy security INPUT"]),
    ], ids=["empty", "not-read", "none", "filter", "raw", "mangle-prerouting", "mangle-input", "security"])
    def test_named(self, legacy, named):
        assert nf._legacy_default_drop(legacy) == named

    @pytest.mark.parametrize("first, second, either", [
        (True, None, True), (None, True, True), (False, False, False), (False, None, None), (None, False, None),
    ])
    def test_either(self, first, second, either):
        assert nf._either(first, second) is either

    @pytest.mark.parametrize("refused, policy", [(True, "PARTIAL"), (None, "unknown"), (False, "ACCEPT")])
    def test_the_input_policy(self, refused, policy):
        assert nf._with_pre_input("ACCEPT", nf._either(False, refused)) == policy
