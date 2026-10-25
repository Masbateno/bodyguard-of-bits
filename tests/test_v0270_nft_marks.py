"""v0.27.0 — a mark set by native nftables feeds the mark rule BOB weighs.

0.26.0 followed MARK, CONNMARK, HMARK and TPROXY in `iptables -t raw|mangle|nat
-S`, and wrote down the limit: `meta mark set` in a native nftables table was
not read. Measured in a network namespace (24 October 2026), INPUT at DROP with
`-m mark --mark 0x20000/0x20000 -j ACCEPT`: an inet prerouting chain setting the
mark on 8099 — `meta mark set mark or 0x20000`, `meta mark set 0x20000`, or
`ct mark set 0x20000` then `meta mark set ct mark` — opened 8099, and BOB said
"conditional" (INFO). Marking 8098 with 0x40000 left 8099 closed. nft prints
the OR back as `meta mark set meta mark | 0x00020000`.
"""

from __future__ import annotations

import inspect

import pytest

from bob.checks import firewall_stack as fs

ACCEPT_MARK = "-A INPUT -m mark --mark 0x20000/0x20000 -j ACCEPT"


def _pre(*rules, hook="prerouting", priority="mangle", family="inet", table="m", chain="pre"):
    body = "".join(f"\t\t{r}\n" for r in rules)
    return (f"table {family} {table} {{\n\tchain {chain} {{\n"
            f"\t\ttype filter hook {hook} priority {priority}; policy accept;\n{body}\t}}\n}}\n")


M1 = _pre("tcp dport 8099 meta mark set meta mark | 0x00020000")
M2 = _pre("tcp dport 8099 meta mark set 0x00020000")
M3 = _pre("tcp dport 8099 ct mark set 0x00020000", "meta mark set ct mark")
M4 = _pre("tcp dport 8098 meta mark set 0x00040000")
M5 = _pre("meta mark set jhash ip saddr mod 4 offset 131072")


def _reachable(ruleset):
    extra = fs._nft_mark_setters(ruleset)
    setters = fs._mark_setters("", "", "", extra=extra)
    return fs._mark_reachable(ACCEPT_MARK, setters)


class TestTheMeasuredCases:

    @pytest.mark.parametrize("ruleset", [M1, M2, M3])
    def test_the_mark_set_on_8099_opens_the_accept(self, ruleset):
        assert _reachable(ruleset)

    def test_another_mark_on_another_port_does_not(self):
        assert not _reachable(M4)

    def test_a_mark_bob_cannot_follow_is_not_called_conditional(self):
        assert _reachable(M5)


class TestTheTranslation:

    @pytest.mark.parametrize("rule, op", [
        ("tcp dport 8099 meta mark set meta mark | 0x00020000", "-j MARK --set-xmark 0x20000/0x20000"),
        ("meta mark set mark or 0x20000", "-j MARK --set-xmark 0x20000/0x20000"),
        ("meta mark set meta mark & 0xfffdffff", "-j MARK --set-xmark 0x0/0x20000"),
        ("tcp dport 8099 meta mark set 0x00020000", "-j MARK --set-xmark 0x20000/0xffffffff"),
        ("tcp dport 8099 ct mark set 0x00020000", "-j CONNMARK --set-xmark 0x20000/0xffffffff"),
        ("ct mark set ct mark | 0x00000010", "-j CONNMARK --set-xmark 0x10/0x10"),
        ("meta mark set ct mark", "-j CONNMARK --restore-mark"),
        ("ct mark set meta mark", "-j CONNMARK --save-mark"),
        ("meta mark set jhash ip saddr mod 4 offset 131072", fs._MARK_UNKNOWN),
        ("tcp dport 22 accept", None),
    ])
    def test_each_statement(self, rule, op):
        assert fs._nft_mark_statement(rule) == op


class TestWhichChains:

    def test_input_before_the_filter_counts(self):
        assert fs._nft_mark_setters(_pre("meta mark set 0x00020000", hook="input", priority="mangle"))["INPUT"]

    def test_input_at_the_filters_priority_is_not_established(self):
        assert fs._nft_mark_setters(_pre("meta mark set 0x00020000", hook="input", priority="filter"))["INPUT"] \
            == [fs._MARK_UNKNOWN]

    def test_input_after_the_filter_does_not_count(self):
        out = fs._nft_mark_setters(_pre("meta mark set 0x00020000", hook="input", priority="10"))
        assert out == {"PREROUTING": [], "INPUT": []}

    def test_a_table_iptables_nft_keeps_is_read_through_iptables(self):
        ruleset = _pre("meta mark set 0x00020000", family="ip", table="mangle", chain="PREROUTING")
        assert fs._nft_mark_setters(ruleset) == {"PREROUTING": [], "INPUT": []}

    def test_two_tables_one_after_the_other(self):
        assert len(fs._nft_mark_setters(M2 + M4)["PREROUTING"]) == 2


def test_the_snapshot_reads_them():
    src = inspect.getsource(fs.FirewallStackSnapshot.from_system)
    assert "extra=_nft_mark_setters(nft_out)" in src
