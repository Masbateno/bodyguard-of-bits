"""v0.26.0 — firewalld source zones are taken in firewalld's order.

Measured on Debian 13 (firewalld 2.3.1, installed for the pass), from
192.168.1.10 to a listener on 8099: zones bobA (0.0.0.0/1) and bobB
(128.0.0.0/1) with target ACCEPT, and a DROP zone keeping ssh, bound to
192.168.1.10/32.

* without the DROP zone: 8099 open;
* the DROP zone named aaacarve (sorts first): 8099 dropped, SSH up;
* named zzzcarve (sorts last): 8099 open;
* zzzcarve at ingress-priority -10: dropped; aaacarve at +10: open.

Between source zones the lowest ingress-priority classifies first, then the
zone name; the first source that matches wins, not the narrowest. 0.24.3 added
the declared sources up and alerted "every client … every port is open" with
the DROP zone first. Decided: the pooled ALERT holds when what the open zones
really take covers every public address of the family, and it names what
another zone classifies first.

Found on the way: the IPv6 "not public" table held 2000::/3 inside "::/1" and
missed e000::/3, so the public share of IPv6 was read against e000::/3.
"""

import ipaddress

import pytest

from bob.checks import _firewalld as fwd
from bob.checks._firewalld import FirewalldStatus, HostPolicy, ZoneBinding, source_coverage, source_dispatch
from bob.checks.firewall import FirewallStatus, check_firewall
from tests.helpers import _t


def _ufw_off():
    return FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _measured(carve=None, carve_prio=0, carve_src="192.168.1.10/32"):
    bindings = [ZoneBinding(name="public", interfaces=("enp3s0",), physical=("enp3s0",), target="default"),
                ZoneBinding(name="bobA", target="ACCEPT", sources=("0.0.0.0/1",)),
                ZoneBinding(name="bobB", target="ACCEPT", sources=("128.0.0.0/1",))]
    if carve:
        bindings.append(ZoneBinding(name=carve, target="DROP", sources=(carve_src,),
                                    ingress_priority=carve_prio))
    return FirewalldStatus(active=True, default_zone="public", target="default",
                           services=["ssh"], bindings=bindings)


def _alert(st):
    res = check_firewall(_ufw_off(), firewalld=st, t=_t, ssh_ports=[22])
    return next((f for f in res.findings if f.key == "firewall.firewalld_policy_open"), None), res


class TestTheMeasuredOrder:
    @pytest.mark.parametrize("carve, prio, taken", [
        (None, 0, ()),
        ("aaacarve", 0, (("aaacarve", "192.168.1.10/32"),)),
        ("zzzcarve", 0, ()),
        ("zzzcarve", -10, (("zzzcarve", "192.168.1.10/32"),)),
        ("aaacarve", 10, ()),
    ])
    def test_what_the_drop_zone_takes(self, carve, prio, taken):
        assert _measured(carve, prio).pooled_scope == (not taken, taken)

    def test_the_first_match_wins_not_the_narrowest(self):
        zones = [ZoneBinding(name="a", sources=("0.0.0.0/0",)), ZoneBinding(name="z", sources=("10.0.0.0/8",))]
        entry = source_dispatch(zones, {"z"})[4]
        assert entry["open"] == [] and entry["zones"] == {}


class TestTheAlert:
    def test_without_exception_the_0243_text(self):
        alert, _ = _alert(_measured())
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled"
        assert "exceptions" not in alert.template_vars

    def test_a_drop_zone_first_is_named_and_the_alert_holds(self):
        alert, res = _alert(_measured("aaacarve"))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled_except"
        assert alert.template_vars["exceptions"] == "192.168.1.10/32 (aaacarve)"
        assert sum(d.points for d in res.deductions if d.key == "firewall.firewalld_policy_open") == 3

    def test_a_drop_zone_last_takes_nothing(self):
        alert, _ = _alert(_measured("zzzcarve"))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled"

    def test_a_small_public_range_taken_first_keeps_the_alert(self):
        # Decided after review: 8.8.8.0/24 kept out raised the domain 7/10 → 10/10
        # while nearly all of the internet stayed open.
        alert, res = _alert(_measured("aaacarve", carve_src="8.8.8.0/24"))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled_near_except"
        assert alert.template_vars["exceptions"] == "8.8.8.0/24 (aaacarve)"
        assert alert.template_vars["public"] == "> 99.9"
        assert sum(d.points for d in res.deductions if d.key == "firewall.firewalld_policy_open") == 3
        assert "firewall.firewalld_source_zones_cumulated" not in [f.key for f in res.findings]

    def test_a_large_public_range_taken_first_ends_the_alert(self):
        alert, res = _alert(_measured("aaacarve", carve_src="64.0.0.0/3"))
        assert alert is None
        cumulated = next(f for f in res.findings if f.key == "firewall.firewalld_source_zones_cumulated")
        assert float(cumulated.template_vars["public"]) < fwd.NEAR_ALL_PUBLIC

    def test_the_threshold(self):
        assert fwd._nearly_all(99, 100) and not fwd._nearly_all(98, 100)

    def test_every_public_address_without_the_private_ranges(self):
        public = [str(n) for n in fwd._subtract([ipaddress.ip_network("0.0.0.0/0")],
                                                 [ipaddress.ip_network("10.0.0.0/8")])]
        half = len(public) // 2
        st = FirewalldStatus(active=True, default_zone="public", target="default", services=["ssh"],
                             bindings=[ZoneBinding(name="public", interfaces=("enp3s0",),
                                                   physical=("enp3s0",), target="default"),
                                       ZoneBinding(name="bobA", target="ACCEPT", sources=tuple(public[:half])),
                                       ZoneBinding(name="bobB", target="ACCEPT", sources=tuple(public[half:]))])
        alert, _ = _alert(st)
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled_public"
        assert st.pooled_scope == (False, ())


class TestTheCumulatedShare:
    def test_a_closed_zone_first_is_left_out(self):
        [(_, _, share, _)] = source_coverage(
            [ZoneBinding(name="bobA", sources=("0.0.0.0/2",)), ZoneBinding(name="bobB", sources=("64.0.0.0/3",))],
            closed=[ZoneBinding(name="aaacarve", sources=("0.0.0.0/3",))])
        assert share == 25.0     # 37.5 % less the 12.5 % aaacarve classifies first

    def test_a_closed_zone_last_changes_nothing(self):
        [(_, _, share, _)] = source_coverage(
            [ZoneBinding(name="bobA", sources=("0.0.0.0/2",)), ZoneBinding(name="bobB", sources=("64.0.0.0/3",))],
            closed=[ZoneBinding(name="zzzcarve", sources=("0.0.0.0/3",))])
        assert share == 37.5


def test_the_ipv6_public_space_is_2000_slash_3_less_documentation():
    public, space = fwd._public_share([ipaddress.ip_network("2000::/3")], 6)
    # 2000::/3 less the documentation ranges 2001:db8::/32 and 3fff::/20 (RFC 9637)
    assert public == space == ipaddress.ip_network("2000::/3").num_addresses - 2 ** 96 - 2 ** 108
    assert fwd._public_share([ipaddress.ip_network("e000::/3")], 6)[0] == 0


def test_short_of_all_of_it_is_never_printed_100():
    from bob.checks.firewall import _pct
    share = 100.0 * (2 ** 32 - 256) / 2 ** 32       # 8.8.8.0/24 left out, measured
    assert _pct(share) == "> 99.9" and _pct(share, "fr") == "> 99,9"
    assert _pct(100.0) == "100" and _pct(99.94) == "99.9"


class TestAZoneBoundToAWholeFamily:
    """The same order applies to a zone bound to 0.0.0.0/0."""

    def _st(self, carve=None, carve_src="192.168.1.10/32"):
        bindings = [ZoneBinding(name="public", interfaces=("enp3s0",), physical=("enp3s0",), target="default"),
                    ZoneBinding(name="trusted", target="ACCEPT", sources=("0.0.0.0/0",))]
        if carve:
            bindings.append(ZoneBinding(name=carve, target="DROP", sources=(carve_src,)))
        return FirewalldStatus(active=True, default_zone="public", target="default",
                               services=["ssh"], bindings=bindings)

    def test_judged_as_the_host_while_it_takes_every_public_address(self):
        for st in (self._st(), self._st("aaacarve"), self._st("zzzcarve", "64.0.0.0/3"),
                   self._st("aaacarve", "8.8.8.0/24")):
            assert "trusted" in [z.name for z in st.judged_zones] and st.incoming_policy == "allow"

    def test_a_public_range_taken_first_makes_it_a_source_zone(self):
        st = self._st("aaacarve", "64.0.0.0/3")
        assert "trusted" not in [z.name for z in st.judged_zones]
        assert [z.name for z, _ in st.open_sources] == ["trusted"]
        alert, res = _alert(st)
        assert alert is None
        cumulated = next(f for f in res.findings if f.key == "firewall.firewalld_source_zones_cumulated")
        assert cumulated.template_vars["share"] == "87.5"     # 0.0.0.0/0 less 64.0.0.0/3


class TestTheWholeFamilyAlertNamesTheException:
    """Measured on Debian 13: trusted on 0.0.0.0/0, a DROP zone on
    192.168.1.10/32 named aaacarve closed 8099 to that host, named zzzcarve it
    did not — the zone's alert said "every client … goes through it" both ways."""

    def _st(self, carve):
        return TestAZoneBoundToAWholeFamily()._st(carve)

    def test_classified_first(self):
        alert, _ = _alert(self._st("aaacarve"))
        assert alert.message == "firewall.firewalld_policy_open_source_except"
        assert alert.template_vars["exceptions"] == "192.168.1.10/32 (aaacarve)"

    def test_classified_last(self):
        alert, _ = _alert(self._st("zzzcarve"))
        assert alert.message == "firewall.firewalld_policy_open_source"

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_text_renders(self, lang):
        from bob import i18n
        i18n.init(lang)
        try:
            res = check_firewall(_ufw_off(), firewalld=self._st("aaacarve"), t=i18n.t, ssh_ports=[22])
        finally:
            i18n.init(lang="en")
        msg = next(f for f in res.findings if f.key == "firewall.firewalld_policy_open").message
        assert "192.168.1.10/32 (aaacarve)" in msg and "{" not in msg


class TestRichRulesThatRefuse:
    """v0.26.0, after review — measured on Debian 13 (firewalld 2.3.1): bobA at
    target ACCEPT bound to 192.168.1.10/32 with `rule family="ipv4" port
    port="8099" protocol="tcp" reject` refused 8099 to that host and let 8097
    in; BOB said "every port is open to those addresses"."""

    RULE = 'rule family="ipv4" port port="8099" protocol="tcp" reject'

    def test_which_rules_refuse(self):
        rules = (self.RULE, 'rule family="ipv4" source address="10.0.0.0/8" drop',
                 'rule service name="ssh" reject type="icmp-host-prohibited"',
                 'rule family="ipv4" port port="8097" protocol="tcp" accept')
        assert fwd.refusing_rules(rules) == rules[:3]

    def _caveat_after(self, res, key):
        keys = [f.key for f in res.findings]
        i = keys.index(key)
        assert keys[i + 1] == "firewall.firewalld_open_zone_refuses_some"
        assert res.findings[i].qualified_by == ("firewall.firewalld_open_zone_refuses_some",)
        assert res.findings[i + 1].template_vars == {"zone": "bobA", "count": 1}

    def test_a_source_zone(self):
        st = FirewalldStatus(active=True, default_zone="public", target="default", services=["ssh"],
                             bindings=[ZoneBinding(name="public", interfaces=("enp3s0",),
                                                   physical=("enp3s0",), target="default"),
                                       ZoneBinding(name="bobA", target="ACCEPT", sources=("192.168.1.10/32",),
                                                   rich_rules=(self.RULE,))])
        res = check_firewall(_ufw_off(), firewalld=st, t=_t, ssh_ports=[22])
        self._caveat_after(res, "firewall.firewalld_source_zone_open")

    def test_the_interface_zone(self):
        st = FirewalldStatus(active=True, default_zone="bobA", target="ACCEPT", services=["ssh"],
                             bindings=[ZoneBinding(name="bobA", interfaces=("enp3s0",), physical=("enp3s0",),
                                                   target="ACCEPT", rich_rules=(self.RULE,))])
        res = check_firewall(_ufw_off(), firewalld=st, t=_t, ssh_ports=[22])
        self._caveat_after(res, "firewall.firewalld_policy_open")

    def test_pooled_zones(self):
        st = _measured()
        st.bindings[1] = ZoneBinding(name="bobA", target="ACCEPT", sources=("0.0.0.0/1",),
                                     rich_rules=(self.RULE,))
        res = check_firewall(_ufw_off(), firewalld=st, t=_t, ssh_ports=[22])
        self._caveat_after(res, "firewall.firewalld_policy_open")

    def test_no_refusing_rule_no_caveat(self):
        res = check_firewall(_ufw_off(), firewalld=_measured(), t=_t, ssh_ports=[22])
        assert "firewall.firewalld_open_zone_refuses_some" not in [f.key for f in res.findings]


def test_a_host_policy_that_drops_first_closes_the_pooled_zones():
    """After review, measured on Debian 13: bobA (0.0.0.0/1) and bobB
    (128.0.0.0/1) at ACCEPT, and a policy ANY → HOST at priority -10, target
    DROP, ssh allowed: 8099 was dropped; without the policy it was open.
    A negative-priority policy decides before the zones' own rules."""
    st = _measured()
    st.host_policies = [HostPolicy(name="bobpol", ingress=("ANY",), target="DROP", priority=-10)]
    alert, res = _alert(st)
    assert alert is None and st.open_sources == []
    assert "firewall.firewalld_source_zones_cumulated" not in [f.key for f in res.findings]


@pytest.mark.parametrize("source_prio, iface_prio, alerted", [
    (0, 0, True),      # equal priority: a source zone before an interface's (Fedora 44, 0.24.3)
    (10, 0, False),    # the interface's zone classifies first
    (0, 10, True),     # the source zones classify first
])
def test_the_interface_zone_order_against_the_pooled_zones(source_prio, iface_prio, alerted):
    """After review: the order between the interface's zone and the source
    zones — measured on Fedora 44 in 0.24.3 (trusted on 0.0.0.0/0 at +100,
    FedoraServer at -100 or 0: 8080 refused; -100 / +100: reachable)."""
    st = FirewalldStatus(active=True, default_zone="public", target="default", services=["ssh"],
                         bindings=[ZoneBinding(name="public", interfaces=("enp3s0",), physical=("enp3s0",),
                                               target="default", ingress_priority=iface_prio),
                                   ZoneBinding(name="bobA", target="ACCEPT", sources=("0.0.0.0/1",),
                                               ingress_priority=source_prio),
                                   ZoneBinding(name="bobB", target="ACCEPT", sources=("128.0.0.0/1",),
                                               ingress_priority=source_prio)])
    alert, _ = _alert(st)
    assert (alert is not None) is alerted


class TestAWholeFamilyRefusedInTheZone:
    """After review: a source zone of IPv4 sources at target ACCEPT with a
    catch-all IPv4 reject was reported open — through its IPv6 half, which no
    packet of an IPv4 source reaches. Judged on its sources' families now."""

    def _st(self, rule, src="192.168.1.10/32"):
        return FirewalldStatus(active=True, default_zone="public", target="default", services=["ssh"],
                               bindings=[ZoneBinding(name="public", interfaces=("enp3s0",),
                                                     physical=("enp3s0",), target="default"),
                                         ZoneBinding(name="bobA", target="ACCEPT", sources=(src,),
                                                     rich_rules=(rule,))])

    @pytest.mark.parametrize("rule, open_", [
        ('rule family="ipv4" reject', False),
        ('rule priority="-10" family="ipv4" drop', False),
        ('rule family="ipv6" reject', True),
    ])
    def test_by_the_sources_family(self, rule, open_):
        assert bool(self._st(rule).open_sources) is open_

    def test_a_non_address_source_keeps_both_families(self):
        assert fwd.source_families(ZoneBinding(name="z", sources=("ipset:bob",))) == fwd.FAMILIES
        assert fwd.source_families(ZoneBinding(name="z", sources=("10.0.0.0/8",))) == ("ipv4",)


def test_a_positive_priority_host_policy_drops_before_the_target():
    """0.24.3, measured on Fedora 44: a policy DROP at +100 closed 8080 under
    target ACCEPT — positive priorities run after the zone's rules but before
    its target."""
    st = _measured()
    st.host_policies = [HostPolicy(name="bobpol", ingress=("ANY",), target="DROP", priority=10)]
    alert, _ = _alert(st)
    assert alert is None and st.open_sources == []


def test_uncounted_ipset_sources_are_said_and_make_the_score_a_ceiling():
    """After review: ipset and MAC sources take no part in the shares, so an
    alert for nearly all public addresses can be missed — said, as a
    visibility INFO."""
    from bob.visibility import is_visibility_key
    st = FirewalldStatus(active=True, default_zone="public", target="default", services=["ssh"],
                         bindings=[ZoneBinding(name="public", interfaces=("enp3s0",), physical=("enp3s0",),
                                               target="default"),
                                   ZoneBinding(name="bobA", target="ACCEPT", sources=("ipset:bigset",))])
    _, res = _alert(st)
    info = next(f for f in res.findings if f.key == "firewall.firewalld_sources_not_counted")
    assert info.template_vars == {"zones": "bobA"}
    assert is_visibility_key("firewall.firewalld_sources_not_counted")
    _, res = _alert(_measured())
    assert "firewall.firewalld_sources_not_counted" not in [f.key for f in res.findings]


class TestTheSameInIPv6:
    """After review: the IPv6 sum was not measured on a host (none with a
    global IPv6 address was at hand); the same classification is guarded here
    through check_firewall — order, first match, what is taken first, the step.
    2000::/3 holds 2^125 addresses: a /10 is 0.78 %, a /12 0.20 %, a /13 0.10 %."""

    @staticmethod
    def _v6(*carves):
        bindings = [ZoneBinding(name="public", interfaces=("enp3s0",), physical=("enp3s0",), target="default"),
                    ZoneBinding(name="bobA", target="ACCEPT", sources=("::/1",)),
                    ZoneBinding(name="bobB", target="ACCEPT", sources=("8000::/1",))]
        bindings += [ZoneBinding(name=name, target="DROP", sources=(src,), ingress_priority=prio)
                     for name, src, prio in carves]
        return FirewalldStatus(active=True, default_zone="public", target="default",
                               services=["ssh"], bindings=bindings)

    @pytest.mark.parametrize("carve, prio, taken", [
        ("aaacarve", 0, (("aaacarve", "fd00::1/128"),)),
        ("zzzcarve", 0, ()),
        ("zzzcarve", -10, (("zzzcarve", "fd00::1/128"),)),
        ("aaacarve", 10, ()),
    ])
    def test_the_order(self, carve, prio, taken):
        assert self._v6((carve, "fd00::1/128", prio)).pooled_scope == (not taken, taken)

    def test_the_first_match_wins_not_the_narrowest(self):
        zones = [ZoneBinding(name="a", sources=("::/0",)), ZoneBinding(name="z", sources=("2001:db8::/32",))]
        entry = source_dispatch(zones, {"z"})[6]
        assert entry["open"] == [] and entry["zones"] == {}

    def test_a_private_range_taken_first_is_named(self):
        alert, res = _alert(self._v6(("aaacarve", "fd00::1/128", 0)))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled_except"
        assert alert.template_vars["exceptions"] == "fd00::1/128 (aaacarve)"
        assert sum(d.points for d in res.deductions if d.key == "firewall.firewalld_policy_open") == 3

    def test_a_small_public_range_taken_first_keeps_the_alert(self):
        alert, _ = _alert(self._v6(("aaacarve", "2606:4700::/32", 0)))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled_near_except"
        assert alert.template_vars["public"] == "> 99.9"

    def test_99_percent_is_the_alert(self):
        # 0.78 % + 0.20 % taken first: 99.02 % of the public addresses left.
        alert, res = _alert(self._v6(("aaacarve", "2000::/10", 0), ("aaacarve2", "2400::/12", 0)))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled_near_except"
        assert alert.template_vars["public"] == "99"
        assert sum(d.points for d in res.deductions if d.key == "firewall.firewalld_policy_open") == 3

    def test_98_9_percent_is_the_info(self):
        # + 0.10 %: 98.93 % left — the cumulated INFO, no alert.
        alert, res = _alert(self._v6(("aaacarve", "2000::/10", 0), ("aaacarve2", "2400::/12", 0),
                                     ("aaacarve3", "2800::/13", 0)))
        assert alert is None
        cumulated = next(f for f in res.findings if f.key == "firewall.firewalld_source_zones_cumulated")
        assert cumulated.template_vars["public"] == "98.9"
        assert not [d for d in res.deductions if d.key == "firewall.firewalld_policy_open"]

    def test_a_closed_zone_last_takes_nothing(self):
        alert, _ = _alert(self._v6(("zzzcarve", "2000::/4", 0)))
        assert alert.message == "firewall.firewalld_policy_open_sources_pooled"
