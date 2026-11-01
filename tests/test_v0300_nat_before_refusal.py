"""v0.30.0, review of the changelog — a refusal before NAT does not close the port.

0.30.0 began weighing the chains before the input hook port by port: a drop
for 8099 in a prerouting chain, raw or mangle PREROUTING read "refused". A
redirect in the nat table's prerouting runs after those chains (dstnat,
priority −100; raw −300, mangle −150) and sends a packet aimed at another port
to the listener. Measured in a network namespace (1 November 2026,
`~/.cache/bob-fieldtest/netnsbench/natbench.sh`, `natbench-fix.txt`, nat
prerouting `tcp dport 8080 redirect to :8099`, a TCP probe on 8080, 8098 and
8099):

| case | probe | 08a1644 | now |
|---|---|---|---|
| N0 raw-priority drop for 8099, no redirect | 8099 closed | refused | refused |
| N1 the same drop, the redirect | 8099 closed, open through 8080 | refused | not established |
| N2 a mangle-priority drop, the redirect | the same | refused | not established |
| N3 a drop at priority 0 (after dstnat), the redirect | closed both ways | refused | refused |
| N4 an input drop, the redirect | closed both ways | refused | refused |
| N5 iptables raw PREROUTING drop, `-j REDIRECT` | open through 8080 | refused | not established |
| N6 mangle PREROUTING drop, the redirect | open through 8080 | refused | not established |
| N7 mangle INPUT drop, the redirect | closed both ways | refused | refused |
| N8 filter INPUT drop, the redirect | closed both ways | refused | refused |
| N9 raw-priority chain at policy drop accepting 8080 and 8098, the redirect | open through 8080 | refused by default | not established |
| N10 iptables raw PREROUTING at policy DROP, the same | open through 8080 | refused by default | not established |
| N11 a nat table with postrouting only (masquerade), raw drop | 8099 closed | refused | refused |

0.29.0 read each of N1–N10 not established, as now (`natbench.txt`).
"""

from __future__ import annotations

import ipaddress
import inspect

import pytest

from bob.checks import iptables_nftables as nf

D, U, DD, AD = ("DROP", "rule"), ("UNKNOWN", ""), ("DROP", "default"), ("ACCEPT", "default")
HOSTS = frozenset(ipaddress.ip_address(a) for a in ("127.0.0.1", "10.77.0.2"))

INPUT = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
         "\t\ttcp dport 22 drop\n\t}\n}\n")


def _chain(family, table, hook, priority, policy, *rules, kind="filter"):
    return (f"table {family} {table} {{\n\tchain c {{\n\t\ttype {kind} hook {hook} priority {priority}; "
            f"policy {policy};\n" + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n}\n")


REDIRECT = _chain("ip", "n", "prerouting", "dstnat", "accept", "tcp dport 8080 redirect to :8099", kind="nat")
DROP_8099 = ("tcp dport 8099 drop",)


class TestNftables:

    @pytest.mark.parametrize("ruleset, v8099", [
        (INPUT + _chain("ip", "r", "prerouting", "raw", "accept", *DROP_8099), D),
        (INPUT + REDIRECT + _chain("ip", "r", "prerouting", "raw", "accept", *DROP_8099), U),
        (INPUT + REDIRECT + _chain("ip", "r", "prerouting", "mangle", "accept", *DROP_8099), U),
        (INPUT + REDIRECT + _chain("ip", "r", "prerouting", "filter", "accept", *DROP_8099), D),
        (INPUT.replace("dport 22 drop", "dport 22 drop\n\t\ttcp dport 8099 drop") + REDIRECT, D),
        (INPUT + REDIRECT + _chain("ip", "r", "prerouting", "raw", "drop", "tcp dport { 8080, 8098 } accept"), U),
        (INPUT + _chain("ip", "n", "postrouting", "srcnat", "accept", "oifname lo masquerade", kind="nat")
               + _chain("ip", "r", "prerouting", "raw", "accept", *DROP_8099), D),
    ], ids=["N0", "N1", "N2", "N3", "N4", "N9", "N11"])
    def test_measured(self, ruleset, v8099):
        assert nf.nft_port_verdict(ruleset, 8099, "tcp", HOSTS) == v8099

    def test_without_the_redirect_the_policy_drop_still_refuses(self):
        rs = INPUT + _chain("ip", "r", "prerouting", "raw", "drop", "tcp dport { 8080, 8098 } accept")
        assert nf.nft_port_verdict(rs, 8099, "tcp", HOSTS) == DD

    def test_an_empty_nat_prerouting_chain_rewrites_nothing(self):
        rs = (INPUT + _chain("ip", "n", "prerouting", "dstnat", "accept", kind="nat")
              + _chain("ip", "r", "prerouting", "raw", "accept", *DROP_8099))
        assert nf.nft_port_verdict(rs, 8099, "tcp", HOSTS) == D

    def test_the_same_priority_is_not_after(self):
        """Two base chains of one priority run in an order nft does not promise."""
        rs = INPUT + REDIRECT + _chain("ip", "r", "prerouting", "dstnat", "accept", *DROP_8099)
        assert nf.nft_port_verdict(rs, 8099, "tcp", HOSTS) == U

    def test_a_nat_chain_of_a_priority_bob_cannot_read_comes_after_all(self):
        rs = (INPUT + REDIRECT.replace("priority dstnat", "priority weird")
              + _chain("ip", "r", "prerouting", "filter", "accept", *DROP_8099))
        assert nf.nft_port_verdict(rs, 8099, "tcp", HOSTS) == U

    def test_an_ipv4_redirect_does_not_touch_ipv6(self):
        rs = INPUT + REDIRECT + _chain("ip6", "r", "prerouting", "raw", "accept", *DROP_8099)
        assert nf.nft_port_verdict_v6(rs, 8099, "tcp", HOSTS) == D

    def test_an_ipv6_redirect_does(self):
        rs = (INPUT + REDIRECT.replace("table ip n", "table ip6 n")
              + _chain("ip6", "r", "prerouting", "raw", "accept", *DROP_8099))
        assert nf.nft_port_verdict_v6(rs, 8099, "tcp", HOSTS) == U

    @pytest.mark.parametrize("text, prio", [
        ("type filter hook prerouting priority raw; policy accept;", -300),
        ("type filter hook prerouting priority mangle - 5; policy accept;", -155),
        ("type nat hook prerouting priority dstnat + 10; policy accept;", -90),
        ("type filter hook input priority -10; policy accept;", -10),
        ("type filter hook input priority 0; policy accept;", 0),
        ("type filter hook input priority weird; policy accept;", None),
    ])
    def test_the_priority(self, text, prio):
        assert nf._nft_priority(text) == prio


def _ipt():
    return "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j DROP\n"


RAW_DROP = {"raw": "-P PREROUTING ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}
MANGLE_PRE = {"mangle": "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A PREROUTING -p tcp -m tcp --dport 8099 -j DROP\n"}
MANGLE_IN = {"mangle": "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n"}
RAW_POLICY = {"raw": "-P PREROUTING DROP\n-A PREROUTING -p tcp -m multiport --dports 8080,8098 -j ACCEPT\n"}


class TestIptables:

    @pytest.mark.parametrize("rules, tables, nat, v8099", [
        (_ipt(), RAW_DROP, False, D),
        (_ipt(), RAW_DROP, True, U),
        (_ipt(), MANGLE_PRE, True, U),
        (_ipt(), MANGLE_IN, True, D),
        (_ipt() + "-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n", RAW_DROP, True, D),
        (_ipt(), RAW_POLICY, True, U),
        (_ipt(), RAW_POLICY, False, DD),
    ], ids=["N0", "N5", "N6", "N7", "N8", "N10", "N10-without-nat"])
    def test_measured(self, rules, tables, nat, v8099):
        assert nf.ipt_port_verdict(rules, 8099, "tcp", tables, HOSTS, nat) == v8099

    @pytest.mark.parametrize("res, rewrites", [
        (("-P PREROUTING ACCEPT\n-A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-ports 8099\n", True, ""), True),
        (("-P PREROUTING ACCEPT\n", True, ""), False),
        (("", False, "iptables v1.8.11 (legacy): can't initialize iptables table `nat': Table does not exist"),
         False),
        (("", False, "Permission denied (you must be root)"), True),
    ], ids=["a-rule", "empty", "no-table", "refused"])
    def test_the_nat_table_read(self, monkeypatch, res, rewrites):
        from bob.checks._run import CommandResult
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: CommandResult(stdout=res[0], ok=res[1], stderr=res[2]))
        assert nf._ipt_nat_rewrites() is rewrites

    def test_the_snapshot_hands_it_down(self):
        snap = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="DROP",
                                      has_loopback_rule=False, has_conntrack_rule=False, raw_output=_ipt(),
                                      other_tables=RAW_DROP)
        assert snap.port_verdict(8099, "tcp") == D
        snap.nat_prerouting = True
        assert snap.port_verdict(8099, "tcp") == U

    def test_nft_own_redirect_counts_for_iptables_too(self):
        snap = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="DROP",
                                      has_loopback_rule=False, has_conntrack_rule=False, raw_output=_ipt(),
                                      other_tables=RAW_DROP, nft_pre_input=REDIRECT)
        assert snap.port_verdict(8099, "tcp") == U

    def test_iptables_nat_counts_for_nft_own_chains(self):
        snap = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="DROP",
                                      has_loopback_rule=False, has_conntrack_rule=False, raw_output=_ipt(),
                                      other_tables={}, nft_pre_input=_chain("ip", "r", "prerouting", "raw",
                                                                            "accept", *DROP_8099))
        assert snap.port_verdict(8099, "tcp") == D
        snap.nat_prerouting = True
        assert snap.port_verdict(8099, "tcp") == U

    def test_read_with_the_ruleset(self):
        src = inspect.getsource(nf.IptablesNftSnapshot.from_system)
        assert "nat_prerouting=_ipt_nat_rewrites()," in src
        assert 'nat_prerouting6=_ipt_nat_rewrites("ip6tables")' in src

    def test_ipv6_reads_its_own(self):
        rules6 = _ipt()
        snap = nf.IptablesNftSnapshot(backend="iptables", input_policy="PARTIAL", forward_policy="DROP",
                                      has_loopback_rule=False, has_conntrack_rule=False, raw_output=_ipt(),
                                      raw_output6=rules6, other_tables6=RAW_DROP, nat_prerouting=True,
                                      host_addresses=frozenset({ipaddress.ip_address("fd77::2")}))
        assert snap.port_verdict_v6(8099, "tcp") == D
        snap.nat_prerouting6 = True
        assert snap.port_verdict_v6(8099, "tcp") == U
