"""v0.31.3 — a UFW rule limited to an interface no network client arrives on
does not open a port to the network.

Measured on Ubuntu Server 26.04, MicroK8s 1.35.6, 8 November 2026
(~/.cache/bob-fieldtest/netnsbench/rt0313/ufw-1.txt): UFW at default deny with
the rules MicroK8s documents (`ufw allow in on cali+`, `ufw allow in on
vxlan.calico`) and `allow 22/tcp`. From the LAN only 22 answered; 139, 445,
80, 443 and every Kubernetes port were refused. The services section read
Samba (445, 139) and Nextcloud (80, 443) "open to the internet — UFW rule allows
from any address (Anywhere)", ALERT −2 each: 8 points for ports no client from
the network could reach. calico's interfaces hold link-local addresses only
(cali*) or a /32 (vxlan.calico); enp3s0 holds 192.168.1.0/24, a /64 and both
default routes. The interface reader keeps a rule whose interface it cannot
place: BOB can overstate, never understate.
"""

from __future__ import annotations

import pytest

from bob.checks import _ufw
from bob.checks import ipv6 as ipv6_mod
from bob.checks import ports as ports_mod
from bob.checks import services as svc
from bob.checks._run import CommandResult

#: `ip -o addr show` on the Ubuntu node, the public IPv6 put in 2001:db8::/32.
_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever
2: enp3s0    inet 192.168.1.12/24 metric 100 brd 192.168.1.255 scope global dynamic enp3s0\\       valid_lft 41361sec
2: enp3s0    inet6 2001:db8:7c60:0:d250:99ff:fe76:ada7/64 scope global dynamic mngtmpaddr noprefixroute \\       valid_lft 86367sec
2: enp3s0    inet6 fe80::d250:99ff:fe76:ada7/64 scope link \\       valid_lft forever preferred_lft forever
6: calic83105ccb66    inet6 fe80::ecee:eeff:feee:eeee/64 scope link \\       valid_lft forever preferred_lft forever
7: calid90c19d66fa    inet6 fe80::ecee:eeff:feee:eeee/64 scope link \\       valid_lft forever preferred_lft forever
8: vxlan.calico    inet 10.1.144.128/32 scope global vxlan.calico\\       valid_lft forever preferred_lft forever
8: vxlan.calico    inet6 fe80::64f0:2aff:fef7:9384/64 scope link \\       valid_lft forever preferred_lft forever
"""
_DEF4 = "default via 192.168.1.254 dev enp3s0 proto dhcp src 192.168.1.12 metric 100 \n"
_DEF6 = "default nhid 2403510314 via fe80::1 dev enp3s0 proto ra metric 100 expires 1591sec pref medium\n"

#: `ufw status numbered` on that node, as measured.
_UFW = """\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] OpenSSH                    ALLOW IN    Anywhere
[ 3] 22/tcp                     ALLOW IN    192.168.1.10               # bob phaseB ssh
[ 4] Anywhere on vxlan.calico   ALLOW IN    Anywhere
[ 5] Anywhere                   ALLOW OUT   Anywhere on vxlan.calico   (out)
[ 6] Anywhere on cali+          ALLOW IN    Anywhere
[ 7] Anywhere                   ALLOW OUT   Anywhere on cali+          (out)
[ 8] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 9] OpenSSH (v6)               ALLOW IN    Anywhere (v6)
[10] Anywhere (v6) on vxlan.calico ALLOW IN    Anywhere (v6)
[11] Anywhere (v6)              ALLOW OUT   Anywhere (v6) on vxlan.calico (out)
[12] Anywhere (v6) on cali+     ALLOW IN    Anywhere (v6)
[13] Anywhere (v6)              ALLOW OUT   Anywhere (v6) on cali+     (out)
"""
_OUTWARD = _ufw.outward_interfaces(_ADDR, _DEF4, _DEF6)


class TestWhereTheNetworkArrives:
    def test_the_measured_node(self):
        assert _OUTWARD == {False: frozenset({"enp3s0"}), True: frozenset({"enp3s0"})}

    def test_link_local_and_host_routes_are_not_a_network(self):
        assert not {"calic83105ccb66", "calid90c19d66fa", "vxlan.calico", "lo"} & (_OUTWARD[False] | _OUTWARD[True])

    def test_a_default_route_brings_the_network_even_on_a_32(self):
        """A point-to-point uplink (ppp) holds a /32 and the default route."""
        addr = "3: ppp0    inet 10.64.64.64 peer 10.64.64.65/32 scope global ppp0\n"
        assert "ppp0" in _ufw.outward_interfaces(addr, "default dev ppp0 scope link \n", "")[False]

    def test_a_lan_without_default_route_still_counts(self):
        addr = "2: eth1    inet 192.168.50.2/24 brd 192.168.50.255 scope global eth1\n"
        assert "eth1" in _ufw.outward_interfaces(addr, "", "")[False]

    def test_every_nexthop_of_a_multipath_default_counts(self):
        routes = "default proto static metric 100 \n\tnexthop via 192.0.2.1 dev eth0 weight 1 \n\tnexthop via 198.51.100.1 dev eth1 weight 1 \n"
        assert {"eth0", "eth1"} <= _ufw.outward_interfaces("", routes, "")[False]

    def test_unread_ipv6_routes_leave_ipv6_unknown(self):
        assert _ufw.outward_interfaces(_ADDR, _DEF4, None)[True] is None

    def test_unread_addresses_or_routes_are_not_known(self, monkeypatch):
        import bob.checks._run as run_mod
        monkeypatch.setattr(run_mod, "run_result", lambda *a, **k: CommandResult("", False))
        assert _ufw.read_outward_interfaces() is None

    def test_the_host_is_read_with_ip(self, monkeypatch):
        import bob.checks._run as run_mod
        out = {("ip", "-o", "addr", "show"): _ADDR, ("ip", "route", "show", "default"): _DEF4,
               ("ip", "-6", "route", "show", "default"): _DEF6}
        monkeypatch.setattr(run_mod, "run_result", lambda *a, **k: CommandResult(out[a], True))
        assert _ufw.read_outward_interfaces() == _OUTWARD


class TestInterfacePatterns:
    @pytest.mark.parametrize("pattern, names, matches", [
        ("cali+", {"calic83105ccb66"}, True), ("cali+", {"enp3s0"}, False),
        ("enp3s0", {"enp3s0"}, True), ("eth0", {"eth01"}, False), ("vxlan.calico", {"enp3s0"}, False)])
    def test_a_plus_is_a_prefix(self, pattern, names, matches):
        assert _ufw.iface_matches(pattern, frozenset(names)) is matches


class TestTheRulesTheNetworkMeets:
    def test_the_pod_interface_rules_are_left_out(self):
        kept = _ufw.network_rules(_UFW, _OUTWARD)
        for n in ("[ 4]", "[ 6]", "[10]", "[12]"):
            assert n not in kept
        for n in ("[ 1]", "[ 2]", "[ 3]", "[ 8]", "[ 9]", "Status: active"):
            assert n in kept

    def test_unknown_interfaces_keep_every_rule(self):
        assert _ufw.network_rules(_UFW, None) == _UFW

    def test_an_unknown_family_keeps_its_rules(self):
        kept = _ufw.network_rules(_UFW, {False: _OUTWARD[False], True: None})
        assert "[ 4]" not in kept and "[10]" in kept and "[12]" in kept

    def test_a_rule_on_the_uplink_still_opens(self):
        ufw = _UFW + "[14] Anywhere on enp3s0       ALLOW IN    Anywhere\n"
        assert "[14]" in _ufw.network_rules(ufw, _OUTWARD)
        assert svc._classify_exposure("445/tcp", _ufw.network_rules(ufw, _OUTWARD)) == svc.Exposure.OPEN_WORLD

    @pytest.mark.parametrize("port, before, after", [
        ("445/tcp", svc.Exposure.OPEN_WORLD, svc.Exposure.NO_RULE),
        ("139/tcp", svc.Exposure.OPEN_WORLD, svc.Exposure.NO_RULE),
        ("80/tcp", svc.Exposure.OPEN_WORLD, svc.Exposure.NO_RULE),
        ("22/tcp", svc.Exposure.OPEN_WORLD, svc.Exposure.OPEN_WORLD)])
    def test_the_measured_services(self, port, before, after):
        """Measured from the LAN: 22 answered, 445, 139 and 80 did not."""
        assert svc._classify_exposure(port, _UFW) == before
        assert svc._classify_exposure(port, _ufw.network_rules(_UFW, _OUTWARD)) == after


class TestTheSectionsReadIt:
    @pytest.fixture
    def host(self, monkeypatch):
        monkeypatch.setattr(_ufw, "read_outward_interfaces", lambda: _OUTWARD)

    @pytest.mark.parametrize("collector", ["collect", "collect_all"])
    def test_services(self, host, monkeypatch, collector):
        seen = []
        monkeypatch.setattr(svc, "_run", lambda *a, **k: _UFW if a[:2] == ("ufw", "status") else "")
        monkeypatch.setattr(svc.ServiceSnapshot, "_build_snapshot",
                            classmethod(lambda cls, service, rules, *a: seen.append(rules) or cls.__new__(cls)))
        monkeypatch.setattr(svc.ServiceSnapshot, "installed", True, raising=False)
        getattr(svc.ServiceSnapshot, collector)([object()])
        assert seen and "[ 4]" not in seen[0] and "[ 6]" not in seen[0] and "[ 1]" in seen[0]

    def test_ports(self, host, monkeypatch):
        monkeypatch.setattr(ports_mod, "_run", lambda *a, **k: _UFW if a[:2] == ("ufw", "status") else "")
        snap = ports_mod.PortsSnapshot.from_system()
        assert "[ 4]" not in snap.ufw_rules and "[ 6]" not in snap.ufw_rules and "[ 1]" in snap.ufw_rules

    def test_ipv6(self, host, monkeypatch):
        monkeypatch.setattr(ipv6_mod, "_run", lambda *a, **k: _UFW if a[:2] == ("ufw", "status") else "")
        snap = ipv6_mod.IPv6Snapshot.from_system()
        assert not [a for a in snap.ufw_v6_admits if "cali" in a[0] or "vxlan" in a[0]]


class TestTheAuditPassesItOn:
    """The services and DDNS sections are fed by run_checks with the firewall
    section's `ufw status numbered` — the measured false alerts came this way."""

    def test_services_and_ddns_meet_the_network_rules(self, tmp_path, monkeypatch):
        import contextlib
        import dataclasses
        import io

        from bob import i18n
        from bob import runner
        from bob.cli import parse_args
        from bob.config import UserConfig
        from bob.profiles import load_profile
        from bob.registry import ServiceRegistry
        from bob.scoring import ScoreEngine

        real = runner.FirewallStatus.from_system
        monkeypatch.setattr(runner.FirewallStatus, "from_system",
                            classmethod(lambda cls: dataclasses.replace(real(), active=True, numbered_output=_UFW)))
        monkeypatch.setattr(_ufw, "read_outward_interfaces", lambda: _OUTWARD)
        seen = {}
        monkeypatch.setattr(runner.ServiceSnapshot, "collect",
                            classmethod(lambda cls, registry, ufw_rules=None, **kw: seen.setdefault("services", ufw_rules) and []))
        real_ddns = runner.check_ddns
        monkeypatch.setattr(runner, "check_ddns",
                            lambda snap, ufw_rules=None, **kw: seen.setdefault("ddns", ufw_rules) and real_ddns(snap, ufw_rules=ufw_rules, **kw))
        real_ctx = runner.ddns_effective_context
        monkeypatch.setattr(runner, "ddns_effective_context",
                            lambda snap, rules, *a, **kw: seen.setdefault("ddns context", rules) and real_ctx(snap, rules, *a, **kw))
        monkeypatch.setattr(runner, "display_services_panorama",
                            lambda registry, rules, *a, **kw: seen.setdefault("panorama", rules))
        i18n.init("en")
        config = parse_args(["--offline"])
        user_config = UserConfig(path=tmp_path / "config.conf")
        profile = load_profile("server")
        engine = ScoreEngine(profile=profile)
        report = runner.init_report(config, user_config, i18n.t, "0.0.0-test")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            runner.run_checks(config, i18n.t, engine, report, ServiceRegistry.load(), "local",
                              profile=profile, prev_recurrence={}, user_config=user_config)
        for section in ("services", "ddns", "ddns context", "panorama"):
            assert "[ 1]" in seen[section] and "[ 4]" not in seen[section] and "[ 6]" not in seen[section], section
