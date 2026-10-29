"""v0.28.0 — a native nft mark set in a chain reached by jump or goto counts.

0.27.0 read `meta mark set` in prerouting chains (and input ones before the
filter) and wrote down the limit: a jump from such a chain to a regular chain
was not followed. Measured in a network namespace (25 October 2026), INPUT at
DROP with `-m mark --mark 0x20000/0x20000 -j ACCEPT`: a mark on 8099 set in a
chain reached from prerouting by `jump`, `goto`, two jumps or a vmap jump
opened 8099, and BOB said "conditional" (INFO, nothing deducted). The same
chain never jumped to, or jumped to from an output chain only, left 8099
closed. Measured the same day: a named set declared before the prerouting
chain made the reader close the table on the set's `}`, so the chain was never
read either (8099 open, "conditional"). The rulesets below are nft's own
printed form (`nft list ruleset`).
"""

from __future__ import annotations

import pytest

from bob.checks import firewall_stack as fs

ACCEPT_MARK = "-A INPUT -m mark --mark 0x20000/0x20000 -j ACCEPT"
HEAD = ("table inet m {\n\tchain pre {\n"
        "\t\ttype filter hook prerouting priority mangle; policy accept;\n")


def _table(pre_rules, *chains, head=HEAD):
    body = "".join(f"\t\t{r}\n" for r in pre_rules)
    out = head + body + "\t}\n"
    for name, rules in chains:
        out += f"\n\tchain {name} {{\n" + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n"
    return out + "}\n"


MK = ("mk", ["tcp dport 8099 meta mark set 0x00020000"])
J1 = _table(["jump mk"], MK)
J2 = _table(["goto mk"], MK)
J3 = _table(["jump mk"], ("mk", ["tcp dport 8099 jump mk2"]),
            ("mk2", ["meta mark set meta mark | 0x00020000"]))
J4 = _table(["tcp dport vmap { 8099 : jump mk }"], ("mk", ["meta mark set 0x00020000"]))
J5 = _table([], ("mk", ["meta mark set 0x00020000"]))
J6 = ("table inet m {\n\tchain pre {\n"
      "\t\ttype filter hook prerouting priority mangle; policy accept;\n\t}\n\n"
      "\tchain out {\n\t\ttype filter hook output priority mangle; policy accept;\n"
      "\t\tjump mk\n\t}\n\n\tchain mk {\n\t\tmeta mark set 0x00020000\n\t}\n}\n")
K1 = ("table inet m {\n\tset s {\n\t\ttype ipv4_addr\n\t\telements = { 10.99.0.9 }\n\t}\n\n"
      "\tchain pre {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"
      "\t\ttcp dport 8099 meta mark set 0x00020000\n\t}\n}\n")
#: nft refuses a loop at load time; the reader must not hang on one anyway.
LOOP = _table(["jump mk"], ("mk", ["jump mk2"]), ("mk2", ["jump mk", "meta mark set 0x00020000"]))


def _verdict(ruleset):
    setters = fs._mark_setters("", "", "", extra=fs._nft_mark_setters(ruleset))
    snap = fs.FirewallStackSnapshot(input_raw_accepts=[ACCEPT_MARK], input_rules=[ACCEPT_MARK],
                                    mark_setters=setters, rules_readable=True)
    result = fs.check_firewall_stack(snap, ufw_active=True)
    keys = {f.key for f in result.findings if f.key.startswith("firewall_drivers.iptables")}
    points = sum(d.points for d in result.deductions if d.key == "firewall_drivers.iptables_bypass")
    return keys, points


class TestTheMeasuredCases:

    @pytest.mark.parametrize("ruleset", [J1, J2, J3, J4, K1], ids=["jump", "goto", "two-jumps", "vmap", "set-first"])
    def test_a_mark_that_opened_8099_is_a_bypass(self, ruleset):
        assert _verdict(ruleset) == ({"firewall_drivers.iptables_bypass"}, 2)

    @pytest.mark.parametrize("ruleset", [J5, J6], ids=["never-jumped", "output-only"])
    def test_a_mark_that_left_it_closed_stays_conditional(self, ruleset):
        assert _verdict(ruleset) == ({"firewall_drivers.iptables_accept_conditional"}, 0)


class TestTheReader:

    def test_the_jumped_chain_is_read_in_place(self):
        out = fs._nft_mark_setters(_table(["meta mark set 0x00000001", "jump mk", "meta mark set 0x00000003"],
                                          ("mk", ["meta mark set 0x00000002"])))
        assert [op.split()[3] for op in out["PREROUTING"]] == ["0x1/0xffffffff", "0x2/0xffffffff", "0x3/0xffffffff"]

    def test_a_loop_ends(self):
        assert fs._nft_mark_setters(LOOP)["PREROUTING"]

    def test_a_chain_of_another_table_is_not_followed(self):
        other = "table inet o {\n\tchain mk {\n\t\tmeta mark set 0x00020000\n\t}\n}\n"
        assert fs._nft_mark_setters(_table(["jump mk"]) + other) == {"PREROUTING": [], "INPUT": []}
