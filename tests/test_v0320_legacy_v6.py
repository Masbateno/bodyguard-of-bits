"""v0.32.0 — the legacy IPv6 tables beside nft meet the shown v6 port verdict.

0.31.0 weighed the legacy (x_tables) filter, raw, mangle and security tables
in the IPv4 port verdict, and wrote the limit: IPv6 unchanged. A packet passes
both nft's chains and the legacy v6 ones, so a legacy refusal closed a port
the shown v6 verdict called reachable. Measured on Ubuntu Server 26.04 in a
network namespace (11 November 2026,
~/.cache/bob-fieldtest/netnsbench/b3bench.sh): a legacy drop for 8099
(ip6tables-legacy, by rule and by policy) closed it over IPv6 while 0.31.4
showed ACCEPT; a legacy accept did not reopen what nft dropped; with the
tables loaded and ip6tables-legacy unreadable, the verdict is UNKNOWN, as the
IPv4 one has been since 0.31.0.
"""

from __future__ import annotations

import ipaddress

import pytest

from bob.checks import iptables_nftables as nf
from bob.checks._run import CommandResult

D, U, A, DD = ("DROP", "rule"), ("UNKNOWN", ""), ("ACCEPT", "default"), ("DROP", "default")
HOSTS = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2", "fd77::2"))
NFT = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
       "\t\ttcp dport 22 drop\n\t}\n}\n")
NFT_DROP_8099_V6 = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
                    "\t\tmeta nfproto ipv6 tcp dport 8099 drop\n\t}\n}\n")
FILTER = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
RAW = "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n"
MANGLE = "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"
SECURITY = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
EMPTY6 = {"filter": FILTER, "raw": RAW, "mangle": MANGLE, "security": SECURITY}
DROP_8099 = "-p tcp -m tcp --dport 8099 -j DROP\n"


def _snap(legacy6, ruleset=NFT, legacy4=None):
    return nf.IptablesNftSnapshot(backend="nftables", input_policy="PARTIAL", forward_policy="ACCEPT",
                                  has_loopback_rule=False, has_conntrack_rule=False, raw_output=ruleset,
                                  host_addresses=HOSTS, legacy_tables=legacy4 if legacy4 is not None else {},
                                  legacy_tables6=legacy6)


def _with(**tables):
    return {**EMPTY6, **tables}


class TestTheMeasuredCases:

    @pytest.mark.parametrize("legacy6, v8099", [
        (_with(filter=FILTER + "-A INPUT " + DROP_8099), D),
        (_with(filter=FILTER.replace("-P INPUT ACCEPT", "-P INPUT DROP")
               + "-A INPUT -p tcp -m tcp --dport 8098 -j ACCEPT\n"), DD),
        (_with(raw=RAW + "-A PREROUTING " + DROP_8099), D),
        (_with(mangle=MANGLE + "-A INPUT " + DROP_8099), D),
        (EMPTY6, A),
        (None, U),
    ], ids=["W1-filter-drop", "W2-policy-drop", "W6-raw-drop", "mangle-drop", "W0-loaded-empty", "W4-unreadable"])
    def test_the_v6_verdict_meets_them(self, legacy6, v8099):
        assert _snap(legacy6).port_verdict_v6(8099, "tcp") == v8099

    def test_a_legacy_accept_does_not_open_what_nft_drops(self):
        legacy6 = _with(filter=FILTER + "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n")
        assert _snap(legacy6, ruleset=NFT_DROP_8099_V6).port_verdict_v6(8099, "tcp")[0] == "DROP"

    def test_the_families_stay_apart(self):
        """A v6-only refusal does not close the v4 verdict, nor a v4 one the v6."""
        drop6 = _with(filter=FILTER + "-A INPUT " + DROP_8099)
        assert _snap(drop6).port_verdict(8099, "tcp") == A
        drop4 = _with(filter=FILTER + "-A INPUT " + DROP_8099)
        # the v4 tables never feed the v6 verdict:
        assert _snap(EMPTY6, legacy4=drop4).port_verdict_v6(8099, "tcp") == A


def test_from_system_reads_the_v6_tables(monkeypatch):
    seen = []

    def fake_legacy(v6=False):
        seen.append(v6)
        return {"filter": FILTER} if v6 else {}
    monkeypatch.setattr(nf, "_legacy_tables", fake_legacy)
    monkeypatch.setattr(nf, "_command_exists", lambda n: n == "nft")
    monkeypatch.setattr(nf, "run_result", lambda *a, **k: CommandResult(
        "table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n", True))
    monkeypatch.setattr(nf, "_host_addresses", lambda: HOSTS)
    monkeypatch.setattr(nf, "_legacy_nat_rewrites", lambda v6=False: False)
    monkeypatch.setattr(nf, "_legacy_nat_text", lambda v6=False: "")
    snap = nf.IptablesNftSnapshot.from_system()
    assert snap.legacy_tables6 == {"filter": FILTER} and True in seen
