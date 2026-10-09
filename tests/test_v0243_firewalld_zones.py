"""v0.24.3 — firewalld is judged by the zones that hold the host's interfaces.

0.24.2 alerted a firewalld default zone whose target is ACCEPT. It judged the
**default** zone only, which is wrong in both directions (measured on Fedora 44,
enp3s0, from another machine):

- enp3s0 bound to ``trusted`` under a filtering default zone: every port
  answered (9090 included) — and BOB said OK (a false OK);
- the default zone set to ACCEPT while enp3s0 is bound elsewhere: the default
  zone filters nothing on this host — and BOB would deduct 3 (a false alert).

Target ACCEPT is not, on its own, an open zone either: firewalld's ``libvirt``
and ``nm-shared`` zones pair it with ``rule priority="32767" reject``. With
enp3s0 in nm-shared, port 22 (listed) answered and 9090 did not.

Zones bound only by *sources* restrict themselves to those addresses (an
"allow from that network"), and zones holding only virtual interfaces (docker0,
virbr0) carry container or VM traffic: neither is the host's inbound default.
"""

from __future__ import annotations

import pathlib

import pytest

from bob.checks import _firewalld as fwd_mod
from bob.checks._firewalld import FirewalldStatus, ZoneBinding, zone_policy
from bob.checks.firewall import FirewallStatus, _firewalld_close_cmd, check_firewall
from tests.helpers import _keys, _t

_NM_SHARED_RICH = ('rule priority="32767" reject',)


def _ufw_off():
    return FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _status(default_zone, default_target, bindings):
    return FirewalldStatus(active=True, default_zone=default_zone, target=default_target,
                           services=["ssh"], bindings=list(bindings))


def _bind(name, target, ifaces=("enp3s0",), physical=None, rich=()):
    return ZoneBinding(name=name, interfaces=tuple(ifaces),
                       physical=tuple(ifaces) if physical is None else tuple(physical),
                       target=target, rich_rules=tuple(rich))


class TestZonePolicy:
    def test_accept_alone_is_open(self):
        assert zone_policy("ACCEPT", []) == "allow"

    def test_accept_with_a_catch_all_reject_is_closed(self):
        """firewalld's own libvirt / nm-shared shape."""
        assert zone_policy("ACCEPT", list(_NM_SHARED_RICH)) == "reject"

    def test_a_catch_all_accept_opens_a_filtering_zone(self):
        assert zone_policy("default", ['rule priority="100" accept']) == "allow"

    def test_a_qualified_rule_is_not_catch_all(self):
        assert zone_policy("ACCEPT", ['rule family="ipv4" source address="10.0.0.0/8" reject']) == "allow"

    def test_the_lowest_priority_number_decides(self):
        rules = ['rule priority="32767" reject', 'rule priority="-10" accept']
        assert zone_policy("default", rules) == "allow"

    def test_opposite_rules_at_one_priority_are_unknown(self):
        """firewalld leaves the order of equal-priority rules undefined."""
        assert zone_policy("ACCEPT", ['rule priority="5" reject', 'rule priority="5" accept']) == "unknown"

    def test_a_family_limited_rule_is_not_catch_all(self):
        """It covers one family only; the zone stays open for the other —
        BOB keeps the open verdict rather than guess."""
        assert zone_policy("ACCEPT", ['rule family="ipv4" priority="32767" reject']) == "allow"


class TestWhichZoneIsJudged:
    def test_an_interface_in_trusted_is_alerted_under_a_filtering_default(self):
        """The false OK: 0.24.2 read FedoraServer (default) and said OK."""
        st = _status("FedoraServer", "default",
                     [_bind("trusted", "ACCEPT"), ZoneBinding(name="FedoraServer", target="default")])
        assert st.incoming_policy == "allow"
        assert "firewall.firewalld_policy_open" in _keys(check_firewall(_ufw_off(), firewalld=st, t=_t))

    def test_an_open_default_zone_holding_nothing_is_not_alerted(self):
        """The false alert: the default zone governs no interface here."""
        st = _status("trusted", "ACCEPT", [_bind("public", "default")])
        assert st.incoming_policy == "reject"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_policy_open" not in _keys(result)
        assert not result.deductions

    def test_nm_shared_on_the_interface_is_not_alerted(self):
        st = _status("FedoraServer", "default", [_bind("nm-shared", "ACCEPT", rich=_NM_SHARED_RICH)])
        assert "firewall.firewalld_policy_open" not in _keys(check_firewall(_ufw_off(), firewalld=st, t=_t))

    def test_a_virtual_interface_zone_is_not_judged(self):
        st = _status("FedoraServer", "default",
                     [_bind("docker", "ACCEPT", ifaces=("docker0",), physical=()),
                      _bind("FedoraServer", "default")])
        assert st.incoming_policy == "reject"

    def test_without_bindings_the_default_zone_still_decides(self):
        """No active-zone listing read: the 0.24.2 behaviour, unchanged."""
        assert _status("FedoraServer", "ACCEPT", []).incoming_policy == "allow"
        assert _status("FedoraServer", "default", []).incoming_policy == "reject"


class TestTheFixFollowsTheBinding:
    def test_trusted_bound_to_an_interface_moves_the_interface(self):
        cmd = _firewalld_close_cmd("trusted", ("enp3s0",), is_default=False)
        assert "--permanent --zone=public --change-interface=enp3s0" in cmd
        assert "--set-default-zone" not in cmd
        assert cmd.endswith("sudo firewall-cmd --reload")

    def test_trusted_as_default_moves_the_default(self):
        cmd = _firewalld_close_cmd("trusted", ("enp3s0",), is_default=True)
        assert cmd.endswith("sudo firewall-cmd --set-default-zone=public")
        assert "--change-interface" not in cmd

    @pytest.mark.parametrize("is_default", [True, False])
    def test_ssh_is_allowed_in_public_before_anything_moves(self, is_default):
        """public ships with ssh, but nothing guarantees it still has it here."""
        cmd = _firewalld_close_cmd("trusted", ("enp3s0",), is_default=is_default)
        keep = cmd.index("--zone=public --add-service=ssh")
        move = cmd.find("--change-interface") if not is_default else cmd.index("--set-default-zone")
        assert keep < move

    def test_an_interface_name_is_quoted(self):
        assert "--change-interface='e n'" in _firewalld_close_cmd("trusted", ("e n",), is_default=False)

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_rendered_message_names_the_interface(self, lang):
        from bob import i18n
        st = _status("FedoraServer", "default", [_bind("trusted", "ACCEPT")])
        i18n.init(lang)
        try:
            result = check_firewall(_ufw_off(), firewalld=st, t=i18n.t)
        finally:
            i18n.init(lang="en")
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert "'trusted'" in finding.message and "enp3s0" in finding.message
        assert finding.template_vars == {"zone": "trusted", "interfaces": "enp3s0"}
        assert "--change-interface=enp3s0" in finding.cmd


class TestPhysicalBacking:
    """A bridge, bond or VLAN over a NIC is the host's uplink (measured: br0
    carries the default route on a Mint desktop and has no device link)."""

    @staticmethod
    def _sysfs(monkeypatch, devices, lowers):
        monkeypatch.setattr(fwd_mod, "path_exists",
                            lambda p: p.name == "device" and p.parent.name in devices)
        monkeypatch.setattr(fwd_mod.os, "listdir",
                            lambda p: [f"lower_{x}" for x in lowers.get(pathlib.Path(p).name, [])]
                            + ["mtu", "operstate"])

    @pytest.mark.parametrize("iface", ["br0", "bond0", "enp3s0.99"])
    def test_a_logical_interface_over_a_nic_is_backed(self, monkeypatch, iface):
        self._sysfs(monkeypatch, {"enp10s0", "enp3s0"},
                    {"br0": ["enp10s0"], "bond0": ["enp3s0"], "enp3s0.99": ["enp3s0"]})
        assert fwd_mod._physically_backed(iface)

    @pytest.mark.parametrize("iface", ["docker0", "virbr0"])
    def test_container_and_vm_bridges_are_not(self, monkeypatch, iface):
        self._sysfs(monkeypatch, {"enp10s0"}, {"docker0": ["veth1a2b"], "virbr0": []})
        assert not fwd_mod._physically_backed(iface)


class TestReadingTheZones:
    def test_active_zones_are_parsed_as_measured(self):
        text = "nm-shared\n  interfaces: enp3s0\nFedoraServer (default)\n"
        assert fwd_mod._parse_active_zones(text) == {"nm-shared": ["enp3s0"], "FedoraServer": []}

    def test_bindings_read_target_rules_and_physicality(self, monkeypatch):
        class _R:
            def __init__(self, out):
                self.ok, self.stdout = True, out
        outputs = {
            ("firewall-cmd", "--get-active-zones"): "nm-shared\n  interfaces: enp3s0 docker0\nFedoraServer (default)\n",
            ("firewall-cmd", "--zone=nm-shared", "--list-all"):
                "nm-shared (active)\n  target: ACCEPT\n  rich rules: \n\trule priority=\"32767\" reject\n",
        }
        monkeypatch.setattr(fwd_mod, "run_result", lambda *a, **k: _R(outputs[a]))
        monkeypatch.setattr(fwd_mod, "path_exists", lambda p: p.parts[-2] == "enp3s0")
        [b] = fwd_mod._read_bindings()
        assert (b.name, b.target, b.physical) == ("nm-shared", "ACCEPT", ("enp3s0",))
        assert b.rich_rules == ('rule priority="32767" reject',)
        assert b.policy == "reject"


class TestHostPolicies:
    """firewalld policies sit beside zones. Measured on Fedora 44: a policy
    ANY → HOST with target ACCEPT (priority -100 or 100) made 8080 reachable
    through FedoraServer (target default) — and 0.24.3's first draft said
    "reject". The shipped ``allow-host-ipv6`` (CONTINUE + ICMPv6 rules) decides
    nothing and hands the packet back to the zone."""

    @staticmethod
    def _st(*policies):
        from bob.checks._firewalld import HostPolicy
        return FirewalldStatus(active=True, default_zone="FedoraServer", target="default",
                               bindings=[_bind("FedoraServer", "default")],
                               host_policies=[HostPolicy(*p) for p in policies])

    def test_an_accept_policy_into_host_is_open(self):
        st = self._st(("bobtest", ("ANY",), "ACCEPT", ()))
        assert st.incoming_policy == "allow"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert finding.cmd == ("sudo firewall-cmd --permanent --zone=FedoraServer --add-service=ssh && "
                               "sudo firewall-cmd --permanent --policy=bobtest "
                               "--set-target=CONTINUE && sudo firewall-cmd --reload")

    def test_allow_host_ipv6_as_shipped_decides_nothing(self):
        rich = ('rule family="ipv6" icmp-type name="neighbour-advertisement" accept',)
        st = self._st(("allow-host-ipv6", ("ANY",), "CONTINUE", rich))
        assert st.host_policies[0].policy == "continue"
        assert st.incoming_policy == "reject"

    def test_a_policy_from_an_unjudged_zone_is_ignored(self):
        """libvirt-routed → HOST concerns VM traffic, not the host's uplink."""
        st = self._st(("vm-in", ("libvirt-routed",), "ACCEPT", ()))
        assert st.incoming_policy == "reject"

    def test_active_policies_are_parsed_as_measured(self):
        text = ("allow-host-ipv6\n  ingress-zones: ANY\n  egress-zones: HOST\n"
                "bobtest\n  ingress-zones: ANY\n  egress-zones: HOST\n")
        parsed = fwd_mod._parse_active_policies(text)
        assert parsed["bobtest"] == {"ingress-zones": ["ANY"], "egress-zones": ["HOST"]}


# ---------------------------------------------------------------------------
# The order firewalld applies, measured on Fedora 44
# (FedoraServer holds enp3s0, 8080 listening and unlisted, probed from the LAN)
# ---------------------------------------------------------------------------

def _pol(name, target, priority, rich=(), ingress=("ANY",)):
    from bob.checks._firewalld import HostPolicy
    return HostPolicy(name=name, ingress=tuple(ingress), target=target,
                      rich_rules=tuple(rich), priority=priority)


def _with(zone_target, *policies, zone_rich=()):
    return FirewalldStatus(active=True, default_zone="FedoraServer", target=zone_target,
                           bindings=[_bind("FedoraServer", zone_target, rich=zone_rich)],
                           host_policies=list(policies))


class TestPolicyOrder:
    """Negative-priority policies, then the zone's rules, then positive-priority
    policies, then the zone's target: the first that decides settles it."""

    def test_m2_a_negative_drop_beats_a_positive_accept(self):
        """8080 refused (and SSH cut — measured the hard way)."""
        st = _with("default", _pol("bt1", "DROP", -100), _pol("bt2", "ACCEPT", 100))
        assert st.incoming_policy == "deny"
        assert "firewall.firewalld_policy_open" not in _keys(check_firewall(_ufw_off(), firewalld=st, t=_t))

    def test_m3_a_negative_accept_beats_a_positive_drop(self):
        st = _with("default", _pol("bt1", "ACCEPT", -100), _pol("bt2", "DROP", 100))
        assert st.incoming_policy == "allow"
        assert st.open_verdict[1].holder.name == "bt1"

    def test_m4a_a_positive_accept_beats_the_zone_target(self):
        """Under %%REJECT%%, a policy ACCEPT at +100 opened 8080."""
        assert _with("%%REJECT%%", _pol("bt1", "ACCEPT", 100)).incoming_policy == "allow"

    def test_m4d_a_positive_drop_beats_an_accepting_zone_target(self):
        """Zone ACCEPT + policy DROP at +100: 8080 refused. The draft alerted."""
        st = _with("ACCEPT", _pol("bt1", "DROP", 100))
        assert st.incoming_policy == "deny"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_policy_open" not in _keys(result)
        assert not result.deductions

    def test_m4e_a_zone_catch_all_reject_beats_a_positive_accept(self):
        """The nm-shared shape + policy ACCEPT at +100: 8080 refused."""
        st = _with("ACCEPT", _pol("bt1", "ACCEPT", 100), zone_rich=_NM_SHARED_RICH)
        assert st.incoming_policy == "reject"

    def test_a_negative_accept_beats_a_zone_catch_all_reject(self):
        st = _with("ACCEPT", _pol("bt1", "ACCEPT", -100), zone_rich=_NM_SHARED_RICH)
        assert st.incoming_policy == "allow"

    @pytest.mark.parametrize("rule, verdict", [
        ('rule priority="32767" reject', "reject"),
        ('rule priority="32767" drop', "deny"),
    ])
    def test_m1_a_policy_catch_all_beats_its_own_accept_target(self, rule, verdict):
        """Measured: policy ACCEPT + its own ``rule reject`` → 8080 refused."""
        st = _with("default", _pol("bt1", "ACCEPT", -100, rich=(rule,)))
        assert st.incoming_policy == verdict

    def test_continue_passes_to_the_next(self):
        st = _with("default", _pol("allow-host-ipv6", "CONTINUE", -15000),
                   _pol("bt1", "ACCEPT", 100))
        assert st.incoming_policy == "allow"

    def test_policies_disagreeing_at_one_priority_are_unknown(self):
        st = _with("default", _pol("a", "ACCEPT", 5), _pol("b", "DROP", 5))
        assert st.incoming_policy == "unknown"

    def test_a_deciding_policy_of_unread_priority_is_unknown(self):
        assert _with("default", _pol("a", "DROP", None)).incoming_policy == "unknown"

    def test_a_continuing_policy_of_unread_priority_changes_nothing(self):
        assert _with("default", _pol("a", "CONTINUE", None)).incoming_policy == "reject"


class TestCatchAllIsSemantic:
    """M5, Fedora 44: each qualified accept below opened 8080 through
    FedoraServer (target default); the service-limited one did not."""

    @pytest.mark.parametrize("rule", [
        'rule priority="100" log prefix="bobt" level="info" accept',
        'rule priority="100" accept limit value="10/m"',
        'rule priority="100" audit accept',
        'rule priority="100" log prefix="a b" level="info" limit value="1/m" accept',
    ])
    def test_log_audit_and_limit_do_not_select_packets(self, rule):
        assert zone_policy("default", [rule]) == "allow"

    @pytest.mark.parametrize("rule", [
        'rule priority="100" service name="http" accept',
        'rule priority="100" source address="10.0.0.0/8" accept',
        'rule priority="100" protocol value="icmp" accept',
        'rule priority="100" port port="8080" protocol="tcp" accept',
        'rule priority="100" masquerade',
    ])
    def test_a_selector_makes_it_partial(self, rule):
        assert zone_policy("default", [rule]) == "reject"

    def test_a_logged_reject_is_still_catch_all(self):
        assert zone_policy("ACCEPT", ['rule priority="32767" log prefix="r" level="info" reject']) == "reject"

    def test_a_rate_limited_reject_decides_nothing(self):
        """Past its rate it lets packets through to the target."""
        assert zone_policy("ACCEPT", ['rule priority="1" reject limit value="5/m"']) == "allow"

    def test_mark_decides_nothing(self):
        assert zone_policy("default", ['rule priority="1" mark set="0x1"']) == "reject"

    def test_a_word_bob_does_not_know_is_unknown(self):
        assert zone_policy("default", ['rule priority="1" frobnicate accept']) == "unknown"


class TestTheFixFollowsTheCause:
    def test_a_zone_rule_is_removed_with_ssh_kept_first(self):
        rule = 'rule priority="100" log prefix="bobt" level="info" accept'
        st = _with("default", zone_rich=(rule,))
        finding = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                       if f.key == "firewall.firewalld_policy_open")
        assert finding.cmd == (
            "sudo firewall-cmd --permanent --zone=FedoraServer --add-service=ssh && "
            "sudo firewall-cmd --permanent --zone=FedoraServer --remove-rich-rule="
            "'rule priority=\"100\" log prefix=\"bobt\" level=\"info\" accept' && "
            "sudo firewall-cmd --reload")
        assert "--set-target" not in finding.cmd

    def test_a_policy_rule_is_removed_from_the_policy(self):
        """R2, Fedora 44: the policy rule opened 8080; this fix closed it, SSH kept.
        firewalld refuses an element-less rule without a non-zero priority."""
        st = _with("default", _pol("bt1", "CONTINUE", -100, rich=('rule priority="10" audit accept',)))
        finding = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                       if f.key == "firewall.firewalld_policy_open")
        assert """--policy=bt1 --remove-rich-rule='rule priority="10" audit accept'""" in finding.cmd
        assert finding.cmd.index("--add-service=ssh") < finding.cmd.index("--remove-rich-rule")
        assert "--set-target" not in finding.cmd

    def test_a_policy_target_fix_keeps_ssh_in_the_zone_first(self):
        st = _with("default", _pol("bt1", "ACCEPT", 100))
        finding = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                       if f.key == "firewall.firewalld_policy_open")
        assert finding.cmd.index("--zone=FedoraServer --add-service=ssh") \
            < finding.cmd.index("--policy=bt1 --set-target=CONTINUE")

    @pytest.mark.parametrize("lang", ["en", "fr"])
    @pytest.mark.parametrize("cause, key, needles", [
        ("zone-rule", "firewall.firewalld_policy_open_zone_rule", ("'FedoraServer'",)),
        ("policy-rule", "firewall.firewalld_policy_open_policy_rule", ("'bt1'", "'FedoraServer'")),
        ("policy-target", "firewall.firewalld_policy_open_host_policy", ("'bt1'", "'FedoraServer'")),
    ])
    def test_the_message_names_the_cause(self, lang, cause, key, needles):
        from bob import i18n
        st = {
            "zone-rule": lambda: _with("default", zone_rich=('rule priority="10" audit accept',)),
            "policy-rule": lambda: _with("default", _pol("bt1", "CONTINUE", 1, rich=('rule priority="10" accept',))),
            "policy-target": lambda: _with("default", _pol("bt1", "ACCEPT", 1)),
        }[cause]()
        i18n.init(lang)
        try:
            finding = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=i18n.t).findings
                           if f.key == "firewall.firewalld_policy_open")
            expected = i18n.t(key, **finding.template_vars)
        finally:
            i18n.init(lang="en")
        assert finding.message == expected
        assert all(n in finding.message for n in needles), finding.message
        assert "{" not in finding.message


class TestUnreadIsNotNone:
    def test_unread_zones_withhold_every_verdict(self):
        st = FirewalldStatus(active=True, default_zone="trusted", target="ACCEPT", zones_read=False)
        assert st.incoming_policy == "unknown"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_policy_open" not in _keys(result)
        assert not result.deductions

    @staticmethod
    def _runner(monkeypatch, results):
        from bob.checks._run import CommandResult
        monkeypatch.setattr(fwd_mod, "run_result", lambda *a, **k: results[a] if a in results
                            else CommandResult("", False, "", 1))

    def test_a_failed_zone_listing_is_none_not_empty(self, monkeypatch):
        self._runner(monkeypatch, {})
        assert fwd_mod._read_bindings() is None

    def test_a_firewalld_without_policies_has_none(self, monkeypatch):
        """Measured on 2.4.0: an unknown option exits 2, "unrecognized arguments"."""
        from bob.checks._run import CommandResult
        self._runner(monkeypatch, {("firewall-cmd", "--get-active-policies"): CommandResult(
            "", False, "firewall-cmd: error: unrecognized arguments: --get-active-policies", 2)})
        assert fwd_mod._read_host_policies() == []

    def test_a_refused_policy_listing_is_unread(self, monkeypatch):
        self._runner(monkeypatch, {})
        assert fwd_mod._read_host_policies() is None

    def test_the_priority_is_read_as_listed(self, monkeypatch):
        from bob.checks._run import CommandResult
        self._runner(monkeypatch, {
            ("firewall-cmd", "--get-active-policies"):
                CommandResult("p1\n  ingress-zones: ANY\n  egress-zones: HOST\n"
                              "p2\n  ingress-zones: ANY\n  egress-zones: HOST\n", True, "", 0),
            ("firewall-cmd", "--policy=p1", "--list-all"):
                CommandResult("p1 (active)\n  priority: -15000\n  target: CONTINUE\n", True, "", 0),
            ("firewall-cmd", "--policy=p2", "--list-all"):
                CommandResult("p2 (active)\n  target: ACCEPT\n", True, "", 0),
        })
        p1, p2 = fwd_mod._read_host_policies()
        assert (p1.priority, p2.priority) == (-15000, None)

    def test_from_system_marks_an_unread_listing(self, monkeypatch):
        monkeypatch.setattr(fwd_mod, "_command_exists", lambda c: True)
        monkeypatch.setattr(fwd_mod, "_read_bindings", lambda: None)
        monkeypatch.setattr(fwd_mod, "_read_host_policies", lambda: [])
        from bob.checks._run import CommandResult
        monkeypatch.setattr(fwd_mod, "run_result", lambda *a, **k: CommandResult(
            "running" if a[-1] == "--state" else "", True, "", 0))
        assert FirewalldStatus.from_system().zones_read is False


class TestTopologies:
    """Stacked logical interfaces resolve to the NIC."""

    def test_a_vlan_over_a_bond_over_a_nic_is_backed(self, monkeypatch):
        TestPhysicalBacking._sysfs(monkeypatch, {"enp3s0"},
                                   {"bond0.10": ["bond0"], "bond0": ["enp3s0"]})
        assert fwd_mod._physically_backed("bond0.10")

    def test_a_bridge_with_a_nic_among_veths_is_backed(self, monkeypatch):
        TestPhysicalBacking._sysfs(monkeypatch, {"enp3s0"},
                                   {"br0": ["veth1", "enp3s0", "veth2"]})
        assert fwd_mod._physically_backed("br0")

    def test_a_bridge_over_two_nics_is_backed(self, monkeypatch):
        TestPhysicalBacking._sysfs(monkeypatch, {"enp3s0", "enp4s0"}, {"br0": ["enp3s0", "enp4s0"]})
        assert fwd_mod._physically_backed("br0")

    def test_a_bridge_of_veths_only_is_not(self, monkeypatch):
        TestPhysicalBacking._sysfs(monkeypatch, {"enp3s0"}, {"br0": ["veth1", "veth2"]})
        assert not fwd_mod._physically_backed("br0")


# ---------------------------------------------------------------------------
# Sources, several causes at once, unread listings
# ---------------------------------------------------------------------------

class TestSourceBoundZones:
    """Measured on Fedora 44 (enp3s0 in FedoraServer, 8080 unlisted): a zone
    bound to a source takes precedence over the interface's zone for it —
    192.168.1.10/32 in trusted opened 8080 to 192.168.1.10, 192.168.1.250/32
    did not; 0.0.0.0/0 in trusted opened it to every IPv4 client while BOB
    said "reject"."""

    @staticmethod
    def _st(sources, target="ACCEPT", rich=()):
        return FirewalldStatus(active=True, default_zone="FedoraServer", target="default",
                               bindings=[_bind("FedoraServer", "default"),
                                         ZoneBinding(name="trusted", target=target,
                                                     rich_rules=tuple(rich), sources=tuple(sources))])

    def test_the_sources_line_is_parsed_as_measured(self):
        text = "FedoraServer (default)\n  interfaces: enp3s0\ntrusted\n  sources: 0.0.0.0/0\n"
        assert fwd_mod._parse_active_sources(text) == {"trusted": ["0.0.0.0/0"]}

    def test_a_whole_family_source_is_judged_and_alerted(self):
        st = self._st(["0.0.0.0/0"])
        assert st.incoming_policy == "allow"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert finding.template_vars == {"zone": "trusted", "sources": "0.0.0.0/0"}
        assert finding.cmd == ("sudo firewall-cmd --permanent --zone=FedoraServer --add-service=ssh && "
                               "sudo firewall-cmd --permanent --zone=trusted --remove-source=0.0.0.0/0 && "
                               "sudo firewall-cmd --reload")
        assert [d.points for d in result.deductions] == [3]

    def test_a_narrow_source_is_shown_not_scored(self):
        st = self._st(["192.168.1.10/32"])
        assert st.incoming_policy == "reject"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_source_zone_open" in _keys(result)
        assert "firewall.firewalld_policy_open" not in _keys(result)
        assert not result.deductions

    def test_a_filtering_source_zone_is_not_shown(self):
        result = check_firewall(_ufw_off(), firewalld=self._st(["10.0.0.0/8"], target="default"), t=_t)
        assert "firewall.firewalld_source_zone_open" not in _keys(result)

    def test_a_source_only_zone_is_read(self, monkeypatch):
        from bob.checks._run import CommandResult
        outputs = {
            ("firewall-cmd", "--get-active-zones"):
                "FedoraServer (default)\n  interfaces: enp3s0\ntrusted\n  sources: 192.168.1.10/32\n",
            ("firewall-cmd", "--zone=FedoraServer", "--list-all"): "FedoraServer (active)\n  target: default\n",
            ("firewall-cmd", "--zone=trusted", "--list-all"): "trusted (active)\n  target: ACCEPT\n",
        }
        monkeypatch.setattr(fwd_mod, "run_result", lambda *a, **k: CommandResult(outputs[a], True, "", 0))
        monkeypatch.setattr(fwd_mod, "path_exists", lambda p: p.parts[-2] == "enp3s0")
        trusted = next(b for b in fwd_mod._read_bindings() if b.name == "trusted")
        assert (trusted.sources, trusted.target, trusted.physical) == (("192.168.1.10/32",), "ACCEPT", ())


class TestSeveralCausesAtOnce:
    """Measured on Fedora 44: zone ACCEPT + ``rule priority="100" accept``, and
    policy ACCEPT + ``rule priority="10" accept`` — removing the rule alone left
    8080 open both times. The fix now undoes every cause in turn."""

    def test_a_zone_with_target_and_rule_loses_both(self):
        st = _with("ACCEPT", zone_rich=('rule priority="100" accept',))
        cmd = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                   if f.key == "firewall.firewalld_policy_open").cmd
        assert cmd.index("--remove-rich-rule=") < cmd.index("--set-target=default")

    def test_a_policy_with_target_and_rule_loses_both(self):
        st = _with("default", _pol("bt1", "ACCEPT", -100, rich=('rule priority="10" accept',)))
        cmd = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                   if f.key == "firewall.firewalld_policy_open").cmd
        assert "--policy=bt1 --remove-rich-rule=" in cmd and "--policy=bt1 --set-target=CONTINUE" in cmd

    def test_an_open_policy_and_an_open_zone_are_both_closed(self):
        st = _with("ACCEPT", _pol("bt1", "ACCEPT", -100))
        cmd = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                   if f.key == "firewall.firewalld_policy_open").cmd
        assert "--policy=bt1 --set-target=CONTINUE" in cmd
        assert "--zone=FedoraServer --set-target=default" in cmd

    def test_one_cause_still_gives_one_fix(self):
        st = _with("default", _pol("bt1", "ACCEPT", 100))
        cmd = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                   if f.key == "firewall.firewalld_policy_open").cmd
        assert cmd.count("--reload") == 1


class TestUnreadIsSaid:
    def test_unread_listings_are_said_and_count_as_unverified(self):
        from bob.visibility import is_visibility_key
        st = FirewalldStatus(active=True, default_zone="trusted", target="ACCEPT", zones_read=False)
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_zones_unread" in _keys(result)
        assert is_visibility_key("firewall.firewalld_zones_unread")

    def test_read_listings_say_nothing_of_it(self):
        result = check_firewall(_ufw_off(), firewalld=_with("default"), t=_t)
        assert "firewall.firewalld_zones_unread" not in _keys(result)


# ---------------------------------------------------------------------------
# Ingress priority, prefixes that add up to a whole family
# ---------------------------------------------------------------------------

def _src_status(sources, src_prio=0, iface_prio=0, target="ACCEPT"):
    return FirewalldStatus(active=True, default_zone="FedoraServer", target="default",
                           bindings=[ZoneBinding(name="FedoraServer", interfaces=("enp3s0",),
                                                 physical=("enp3s0",), target="default",
                                                 ingress_priority=iface_prio),
                                     ZoneBinding(name="trusted", target=target,
                                                 sources=tuple(sources), ingress_priority=src_prio)])


class TestIngressPriority:
    """Measured on Fedora 44, 0.0.0.0/0 in trusted, enp3s0 in FedoraServer:
    trusted +100 / FedoraServer -100 → 8080 refused; +100 / 0 → refused;
    -100 / +100 → reachable; 0 / 0 → reachable."""

    @pytest.mark.parametrize("src, iface, judged", [
        (100, -100, False), (100, 0, False), (-100, 100, True), (0, 0, True),
    ])
    def test_the_source_zone_counts_only_when_it_classifies_first(self, src, iface, judged):
        st = _src_status(["0.0.0.0/0"], src, iface)
        assert (st.incoming_policy == "allow") is judged
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert ("firewall.firewalld_policy_open" in _keys(result)) is judged

    def test_a_narrow_source_classified_after_the_interface_is_not_shown(self):
        result = check_firewall(_ufw_off(), firewalld=_src_status(["192.168.1.10/32"], 100, 0), t=_t)
        assert "firewall.firewalld_source_zone_open" not in _keys(result)

    def test_the_ingress_priority_is_read_as_listed(self, monkeypatch):
        from bob.checks._run import CommandResult
        outputs = {
            ("firewall-cmd", "--get-active-zones"): "trusted\n  sources: 0.0.0.0/0\n",
            ("firewall-cmd", "--zone=trusted", "--list-all"):
                "trusted (active)\n  target: ACCEPT\n  ingress-priority: 100\n  egress-priority: 0\n",
        }
        monkeypatch.setattr(fwd_mod, "run_result", lambda *a, **k: CommandResult(outputs[a], True, "", 0))
        [b] = fwd_mod._read_bindings()
        assert b.ingress_priority == 100

    def test_no_ingress_line_is_the_historic_order(self, monkeypatch):
        from bob.checks._run import CommandResult
        outputs = {
            ("firewall-cmd", "--get-active-zones"): "trusted\n  sources: 0.0.0.0/0\n",
            ("firewall-cmd", "--zone=trusted", "--list-all"): "trusted (active)\n  target: ACCEPT\n",
        }
        monkeypatch.setattr(fwd_mod, "run_result", lambda *a, **k: CommandResult(outputs[a], True, "", 0))
        [b] = fwd_mod._read_bindings()
        assert b.ingress_priority == 0


class TestPrefixesAddUp:
    """Measured on Fedora 44: 0.0.0.0/1 + 128.0.0.0/1 in trusted opened 8080 to
    every IPv4 client while BOB said reject; 128.0.0.0/1 alone opened it to
    192.168.1.10, 0.0.0.0/1 alone did not."""

    @pytest.mark.parametrize("sources", [
        ["0.0.0.0/1", "128.0.0.0/1"],
        ["::/1", "8000::/1"],
        ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"],
    ])
    def test_halves_that_cover_a_family_are_judged(self, sources):
        st = _src_status(sources)
        assert set(st.bindings[1].all_sources) == set(sources)
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert all(f"--remove-source={s}" in finding.cmd for s in sources)

    def test_one_half_is_narrow(self):
        st = _src_status(["128.0.0.0/1"])
        assert st.bindings[1].all_sources == ()
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_source_zone_open" in _keys(result)
        assert not result.deductions

    def test_mac_and_ipset_sources_never_add_up(self):
        st = _src_status(["aa:bb:cc:dd:ee:ff", "ipset:everyone", "0.0.0.0/1"])
        assert st.bindings[1].all_sources == ()

    def test_two_families_halves_do_not_mix(self):
        assert _src_status(["0.0.0.0/1", "8000::/1"]).bindings[1].all_sources == ()


# ---------------------------------------------------------------------------
# Sources that add up across zones
# ---------------------------------------------------------------------------

def _two_zones(a_sources, b_sources, b_target="ACCEPT"):
    return FirewalldStatus(active=True, default_zone="FedoraServer", target="default",
                           bindings=[_bind("FedoraServer", "default"),
                                     ZoneBinding(name="trusted", target="ACCEPT", sources=tuple(a_sources)),
                                     ZoneBinding(name="bta", target=b_target, sources=tuple(b_sources))])


class TestSourcesAcrossZones:
    """0.0.0.0/1 in one accepting zone and 128.0.0.0/1 in another let every
    IPv4 client in, as one zone bound to 0.0.0.0/0 does."""

    @pytest.mark.parametrize("a, b", [(["0.0.0.0/1"], ["128.0.0.0/1"]), (["::/1"], ["8000::/1"])])
    def test_halves_in_two_accepting_zones_are_alerted(self, a, b):
        st = _two_zones(a, b)
        assert st.incoming_policy == "allow"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert finding.template_vars == {"zones": "trusted, bta", "sources": f"{a[0]}, {b[0]}"}
        assert finding.cmd == ("sudo firewall-cmd --permanent --zone=FedoraServer --add-service=ssh && "
                               f"sudo firewall-cmd --permanent --zone=trusted --remove-source={a[0]} && "
                               f"sudo firewall-cmd --permanent --zone=bta --remove-source={b[0]} && "
                               "sudo firewall-cmd --reload")
        assert [d.points for d in result.deductions] == [3]
        assert "firewall.firewalld_source_zone_open" not in _keys(result)

    def test_a_half_in_a_filtering_zone_does_not_add_up(self):
        st = _two_zones(["0.0.0.0/1"], ["128.0.0.0/1"], b_target="default")
        assert st.incoming_policy == "reject"
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        assert "firewall.firewalld_source_zone_open" in _keys(result)
        assert not result.deductions

    def test_halves_of_two_families_do_not_add_up(self):
        assert _two_zones(["0.0.0.0/1"], ["8000::/1"]).incoming_policy == "reject"

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_narrow_source_message_does_not_vouch_for_the_source(self, lang):
        from bob import i18n
        i18n.init(lang)
        try:
            result = check_firewall(_ufw_off(), firewalld=_src_status(["192.168.1.10/32"]), t=i18n.t)
        finally:
            i18n.init(lang="en")
        msg = next(f for f in result.findings if f.key == "firewall.firewalld_source_zone_open").message
        # "trust" alone would match the zone name 'trusted' — the bench caught it.
        assert ("whether they deserve that trust" in msg) if lang == "en" \
            else ("méritent cette confiance" in msg)
        assert "192.168.1.10/32" in msg and "{" not in msg


# ---------------------------------------------------------------------------
# One address family at a time
# ---------------------------------------------------------------------------

class TestOneFamilyAtATime:
    """Measured on Fedora 44: ``rule family="ipv4" priority="-100" accept`` in
    FedoraServer (target default) opened 8080 over IPv4 while BOB said reject —
    ``family`` was read as a selector and the rule ignored."""

    def test_an_ipv4_catch_all_accept_opens_ipv4_only(self):
        st = _with("default", zone_rich=('rule family="ipv4" priority="-100" accept',))
        assert (st.family_policy("ipv4"), st.family_policy("ipv6")) == ("allow", "reject")
        result = check_firewall(_ufw_off(), firewalld=st, t=_t)
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert finding.template_vars == {"zone": "FedoraServer", "families": "IPv4"}
        assert ("--zone=FedoraServer --remove-rich-rule="
                "'rule family=\"ipv4\" priority=\"-100\" accept'") in finding.cmd

    def test_an_ipv6_catch_all_accept_opens_ipv6_only(self):
        st = _with("default", zone_rich=('rule family="ipv6" priority="-100" accept',))
        assert (st.family_policy("ipv4"), st.family_policy("ipv6")) == ("reject", "allow")

    def test_a_policy_rule_of_one_family_counts_for_it(self):
        st = _with("default", _pol("bt1", "CONTINUE", -100, rich=('rule family="ipv4" priority="10" accept',)))
        assert (st.family_policy("ipv4"), st.family_policy("ipv6")) == ("allow", "reject")

    def test_a_whole_ipv4_source_leaves_ipv6_to_the_interface_zone(self):
        """Without this the IPv6 section would say IPv6 is not filtered."""
        st = _src_status(["0.0.0.0/0"])
        assert (st.family_policy("ipv4"), st.family_policy("ipv6")) == ("allow", "reject")


@pytest.mark.parametrize("lang, needle", [("en", "every IPv4 packet"), ("fr", "paquets IPv4")])
def test_the_rule_message_names_its_family(lang, needle):
    from bob import i18n
    st = _with("default", zone_rich=('rule family="ipv4" priority="-100" accept',))
    i18n.init(lang)
    try:
        msg = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=i18n.t).findings
                   if f.key == "firewall.firewalld_policy_open").message
    finally:
        i18n.init(lang="en")
    assert needle in msg and "IPv6" not in msg


def test_a_both_family_rule_names_both():
    st = _with("default", zone_rich=('rule priority="100" accept',))
    finding = next(f for f in check_firewall(_ufw_off(), firewalld=st, t=_t).findings
                   if f.key == "firewall.firewalld_policy_open")
    assert finding.template_vars["families"] == "IPv4/IPv6"
