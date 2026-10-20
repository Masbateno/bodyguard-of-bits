"""v0.26.0 — a raw INPUT ACCEPT rule is judged by what it can let in.

Measured on Ubuntu Server 26.04 with k3s 1.36: with ufw installed and off,
kube-router's `-m mark --mark 0x20000/0x20000 -j ACCEPT` cost 2 points as a "raw
ACCEPT rule bypassing UFW", on top of the 3 the iptables/nftables section takes
for the same INPUT chain.

Measured in a network namespace with ufw 0.36 active (default deny), from a
second namespace: a raw `-p tcp --dport 8099 -j ACCEPT` ahead of UFW's chains
opened 8099; a `-m mark` rule opened nothing; and `iptables -L INPUT -n`, which
BOB read, printed `-i lo -j ACCEPT` exactly as an accept-all. The rules are now
read with `iptables -S`.
"""

import pytest

from bob.checks import firewall_stack as fs
from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
from tests.helpers import _keys, _t

# As `iptables -S INPUT` printed them in the namespace bench and on k3s.
LOOPBACK = "-A INPUT -i lo -j ACCEPT"
MARK = ('-A INPUT -m comment --comment "KUBE-ROUTER rule to explicitly ACCEPT traffic that comply to '
        'network policies" -m mark --mark 0x20000/0x20000 -j ACCEPT')
MARK_BARE = "-A INPUT -m mark --mark 0x20000/0x20000 -j ACCEPT"
STATE = "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
PORT = "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT"
ALL = "-A INPUT -j ACCEPT"


def test_what_each_rule_can_let_in():
    assert fs._accept_reach(LOOPBACK) == "loopback"
    assert fs._accept_reach(MARK) == "conditional"
    assert fs._accept_reach(MARK_BARE) == "conditional"
    assert fs._accept_reach(STATE) == "conditional"
    assert fs._accept_reach(PORT) == "admits"
    assert fs._accept_reach(ALL) == "admits"
    assert fs._accept_reach("-A INPUT -m state --state NEW,ESTABLISHED -j ACCEPT") == "admits"


def test_the_s_form_is_parsed():
    out = "\n".join(["-P INPUT DROP", LOOPBACK, MARK_BARE, "-A INPUT -j ufw-before-input", PORT])
    assert fs._parse_raw_accepts_s(out) == [LOOPBACK, MARK_BARE, PORT]


def _snap(*rules):
    return FirewallStackSnapshot(input_raw_accepts=list(rules))


def test_with_ufw_off_nothing_is_a_bypass():
    result = check_firewall_stack(_snap(MARK, PORT, ALL), t=_t, ufw_active=False)
    assert "firewall_drivers.iptables_bypass" not in _keys(result)
    assert not [d for d in result.deductions if d.key == "firewall_drivers.iptables_bypass"]


def test_with_ufw_on_only_what_admits_is_deducted():
    result = check_firewall_stack(_snap(LOOPBACK, MARK, PORT), t=_t, ufw_active=True)
    bypass = [d for d in result.deductions if d.key == "firewall_drivers.iptables_bypass"]
    assert len(bypass) == 1 and bypass[0].points == 2
    assert _keys(result).count("firewall_drivers.iptables_accept_conditional") == 1


def test_the_runner_hands_the_ufw_state():
    import inspect
    import bob.runner as runner
    assert "check_firewall_stack(stack_snapshot, t=t, ufw_active=fw_status.active)" in inspect.getsource(runner)


def test_collection_reads_the_s_form(monkeypatch):
    calls = []
    def fake_run(*args, **kw):
        calls.append(args)
        if args[:2] == ("iptables", "-S"):
            return "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"
        if args[:2] == ("iptables", "-L"):
            return "Chain INPUT (policy DROP)\ntarget prot opt source destination\nACCEPT 0 -- 0.0.0.0/0 0.0.0.0/0\n"
        return ""
    monkeypatch.setattr(fs, "_run", fake_run)
    monkeypatch.setattr(fs, "_command_exists", lambda name: name == "iptables")
    snap = FirewallStackSnapshot.from_system()
    assert snap.input_raw_accepts == ["-A INPUT -i lo -j ACCEPT"]


class TestAMarkSetBeforehand:
    """v0.26.0, after review — measured with ufw 0.36 active in a network
    namespace: `-t mangle -A PREROUTING -p tcp --dport 8099 -j MARK --set-xmark
    0x20000/0x20000` plus `-A INPUT -m mark --mark 0x20000/0x20000 -j ACCEPT`
    opened 8099; without the mangle rule it stayed closed. BOB said INFO both
    times."""

    MANGLE = "-A PREROUTING -p tcp -m tcp --dport 8099 -j MARK --set-xmark 0x20000/0x20000"
    KUBE_PROXY = "-A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000"

    def test_a_mark_set_on_new_packets_admits(self):
        assert fs._accept_reach(MARK_BARE, [self.MANGLE]) == "admits"

    def test_another_mark_does_not(self):
        assert fs._accept_reach(MARK_BARE, [self.KUBE_PROXY]) == "conditional"

    def test_a_match_on_an_unset_bit_takes_every_new_packet(self):
        assert fs._accept_reach("-A INPUT -m mark --mark 0x0/0x4000 -j ACCEPT") == "admits"

    INPUT_MARK = "-A INPUT -p tcp -m tcp --dport 8099 -j MARK --set-xmark 0x20000/0x20000"

    @pytest.mark.parametrize("rules, deducted", [
        ([INPUT_MARK, MARK_BARE], True),     # measured: 8099 open
        ([MARK_BARE, INPUT_MARK], False),    # measured: 8099 closed
    ])
    def test_a_mark_set_in_input_counts_only_above_the_rule(self, rules, deducted):
        snap = FirewallStackSnapshot(input_raw_accepts=[MARK_BARE], input_rules=list(rules))
        result = check_firewall_stack(snap, t=_t, ufw_active=True)
        assert bool([d for d in result.deductions if d.key == "firewall_drivers.iptables_bypass"]) is deducted

    FILTER_SET = "-A BOBF -p tcp -m tcp --dport 8099 -j MARK --set-xmark 0x20000/0x20000"

    @pytest.mark.parametrize("filter_s, deducted", [
        # Measured (ufw 0.36 active): jumped above the mark rule, 8099 open.
        ("-N BOBF\n-A INPUT -j BOBF\n" + MARK_BARE + "\n" + FILTER_SET + "\n", True),
        # Nested one chain deeper, above: open.
        ("-N BOBA\n-N BOBF\n-A INPUT -j BOBA\n" + MARK_BARE + "\n-A BOBA -j BOBF\n"
         + FILTER_SET + "\n", True),
        # Jumped below the mark rule: closed.
        ("-N BOBF\n" + MARK_BARE + "\n-A INPUT -j BOBF\n" + FILTER_SET + "\n", False),
    ])
    def test_a_mark_set_in_a_user_chain_jumped_from_input(self, filter_s, deducted, monkeypatch):
        outputs = {("iptables", "-S", "INPUT"): "-P INPUT DROP\n" + "\n".join(
                       ln for ln in filter_s.splitlines() if ln.startswith("-A INPUT")) + "\n",
                   ("iptables", "-S"): "-P INPUT DROP\n" + filter_s}
        monkeypatch.setattr(fs, "_run", lambda *a, **k: outputs.get(a, ""))
        monkeypatch.setattr(fs, "_command_exists", lambda c: c == "iptables")
        snap = FirewallStackSnapshot.from_system()
        result = check_firewall_stack(snap, t=_t, ufw_active=True)
        assert bool([d for d in result.deductions if d.key == "firewall_drivers.iptables_bypass"]) is deducted

    def test_a_chain_that_jumps_back_does_not_loop(self):
        assert fs._input_path("-N A\n-A INPUT -j A\n-A A -j INPUT\n") == ["-A INPUT -j A", "-A A -j INPUT"]

    @pytest.mark.parametrize("table", ["raw", "nat"])
    def test_raw_and_nat_set_marks_too(self, table, monkeypatch):
        # Measured: a MARK in raw or nat PREROUTING opened 8099 like mangle.
        outputs = {("iptables", "-S", "INPUT"): "-P INPUT DROP\n" + MARK_BARE + "\n",
                   ("iptables", "-t", table, "-S"): "-P PREROUTING ACCEPT\n" + self.MANGLE + "\n"}
        monkeypatch.setattr(fs, "_run", lambda *a, **k: outputs.get(a, ""))
        monkeypatch.setattr(fs, "_command_exists", lambda c: c == "iptables")
        assert FirewallStackSnapshot.from_system().mark_setters == [self.MANGLE]

    def test_the_setters_are_collected_from_the_tables(self, monkeypatch):
        outputs = {("iptables", "-S", "INPUT"): "-P INPUT DROP\n" + MARK_BARE + "\n",
                   ("iptables", "-t", "mangle", "-S"): "-P PREROUTING ACCEPT\n" + self.MANGLE + "\n"}
        monkeypatch.setattr(fs, "_run", lambda *a, **k: outputs.get(a, ""))
        monkeypatch.setattr(fs, "_command_exists", lambda c: c == "iptables")
        snap = FirewallStackSnapshot.from_system()
        assert snap.mark_setters == [self.MANGLE]

    def test_deducted_like_a_port_rule(self):
        snap = FirewallStackSnapshot(input_raw_accepts=[MARK_BARE], mark_setters=[self.MANGLE])
        result = check_firewall_stack(snap, t=_t, ufw_active=True)
        assert [d.points for d in result.deductions if d.key == "firewall_drivers.iptables_bypass"] == [2]



class TestTheInboundPathOnly:
    """After review, measured with ufw 0.36 active (network namespace): a MARK
    in mangle OUTPUT or POSTROUTING left 8099 closed; in a user chain jumped
    from mangle PREROUTING it opened 8099, jumped from OUTPUT only it did not;
    CONNMARK --set-xmark then --restore-mark in mangle PREROUTING opened it."""

    SET = "-j MARK --set-xmark 0x20000/0x20000"

    def test_outbound_chains_do_not_count(self):
        out = ("-P OUTPUT ACCEPT\n-A OUTPUT -p tcp -m tcp --sport 8099 " + self.SET +
               "\n-A POSTROUTING -p tcp " + self.SET + "\n")
        assert fs._mark_setters(out) == []

    def test_a_user_chain_reached_from_prerouting_counts(self):
        out = ("-N BOBMARK\n-A PREROUTING -j BOBMARK\n"
               "-A BOBMARK -p tcp -m tcp --dport 8099 " + self.SET + "\n")
        assert fs._mark_setters(out) == ["-A BOBMARK -p tcp -m tcp --dport 8099 " + self.SET]

    def test_the_same_chain_reached_from_output_only_does_not(self):
        out = ("-N BOBMARK\n-A OUTPUT -j BOBMARK\n"
               "-A BOBMARK -p tcp -m tcp --dport 8099 " + self.SET + "\n")
        assert fs._mark_setters(out) == []

    def test_connmark_rules_are_collected_in_order(self):
        rule = "-A PREROUTING -p tcp -m tcp --dport 8099 -j CONNMARK --set-xmark 0x20000/0x20000"
        restore = "-A PREROUTING -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"
        assert fs._mark_setters(rule + "\n" + restore + "\n") == [rule, restore]


class TestAConnectionMark:
    """After review, measured with ufw 0.36 active, mark rule on 0x20000/0x20000:
    CONNMARK --set-xmark alone, restored with masks 0x10000, or restored before
    it is set left 8099 closed; set then restored (full masks) opened it."""

    SET = "-A PREROUTING -p tcp -m tcp --dport 8099 -j CONNMARK --set-xmark 0x20000/0x20000"
    RESTORE = "-A PREROUTING -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"
    RESTORE_OTHER_BITS = "-A PREROUTING -j CONNMARK --restore-mark --nfmask 0x10000 --ctmask 0x10000"

    @pytest.mark.parametrize("setters, admits", [
        ([SET], False),
        ([SET, RESTORE_OTHER_BITS], False),
        ([RESTORE, SET], False),
        ([SET, RESTORE], True),
    ])
    def test_measured(self, setters, admits):
        assert (fs._accept_reach(MARK_BARE, setters) == "admits") is admits



class TestOtherMarkTargets:
    """After review, measured with ufw 0.36 active: `-j HMARK --hmark-tuple src
    --hmark-mod 1 --hmark-offset 0x20000` in mangle PREROUTING opened 8099
    through the mark rule, which BOB called conditional; `--or-mark`,
    `--xor-mark` and `--and-mark` are printed by `iptables -S` as
    `--set-xmark` and were already followed."""

    HMARK = ("-A PREROUTING -p tcp -m tcp --dport 8099 -j HMARK --hmark-src-prefix 32 "
             "--hmark-rnd 0x00000001 --hmark-mod 1 --hmark-offset 131072")

    def test_hmark_is_followed(self):
        assert fs._mark_setters(self.HMARK + "\n") == [self.HMARK]
        assert fs._accept_reach(MARK_BARE, [self.HMARK]) == "admits"

    def test_an_hmark_range_that_misses_the_bits(self):
        other = self.HMARK.replace("--hmark-offset 131072", "--hmark-offset 0x100")
        assert fs._accept_reach(MARK_BARE, [other]) == "conditional"

    def test_a_wide_hmark_is_not_called_conditional(self):
        wide = self.HMARK.replace("--hmark-mod 1", "--hmark-mod 65536").replace("--hmark-offset 131072", "--hmark-offset 0x100")
        assert fs._accept_reach(MARK_BARE, [wide]) == "admits"

    def test_tproxy_mark(self):
        rule = "-A PREROUTING -p tcp -m tcp --dport 8099 -j TPROXY --on-port 3129 --on-ip 0.0.0.0 --tproxy-mark 0x20000/0x20000"
        assert fs._mark_setters(rule + "\n") == [rule]
        assert fs._accept_reach(MARK_BARE, [rule]) == "admits"

    def test_or_mark_as_printed(self):
        assert fs._accept_reach(MARK_BARE, ["-A PREROUTING -p tcp -m tcp --dport 8099 -j MARK --set-xmark 0x20000/0x20000"]) == "admits"
