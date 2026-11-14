"""v0.36.0 — LXD and Incus route through the host, as libvirt does.

Measured on Debian 13 (Incus 6.0.4, a10360, 14 November 2026): incusbr0 is a
NAT bridge (ipv4.nat and ipv6.nat true); with Incus stopped and both
net.ipv4.ip_forward and net.ipv6.conf.all.forwarding set back to 0, starting
Incus set both to 1 again. BOB did not count LXD or Incus as a routing
mechanism, so a host running either had `firewall_drivers.ip_forward_enabled`
(−1) — and, with 0.36.0's IPv6 reading, its IPv6 twin. A bridge left behind
(lxdbr0 and the inet lxd table stayed after the LXD package was purged) does
not count without its daemon.
"""

from __future__ import annotations

from bob.checks import firewall_stack as fs


def _keys(**kw):
    snap = fs.FirewallStackSnapshot(ip_forward=True, ip6_forward=True, **kw)
    r = fs.check_firewall_stack(snap, t=lambda k, **v: k, ufw_active=False)
    return {f.key for f in r.findings}, sum(d.points for d in r.deductions)


def test_lxd_or_incus_running_excuses_both_families():
    keys, points = _keys(lxd_incus_present=True)
    assert {"firewall_drivers.ip_forward_ok", "firewall_drivers.ip6_forward_ok"} <= keys
    assert points == 0


def test_without_it_both_cost_a_point():
    keys, points = _keys()
    assert {"firewall_drivers.ip_forward_enabled", "firewall_drivers.ip6_forward_enabled"} <= keys
    assert points == 2


def test_beside_wireguard_it_is_another_mechanism():
    keys, _ = _keys(lxd_incus_present=True, wireguard_present=True, wireguard_ifaces=["wg0"],
                    forwarded_v4=0, forwarded_v6=0, uptime_s=7200.0)
    assert "firewall_drivers.ip_forward_wireguard_idle" not in keys
    assert "firewall_drivers.ip6_forward_wireguard_idle" not in keys


def test_its_bridges_own_their_forward_rules():
    snap = fs.FirewallStackSnapshot(lxd_incus_present=True)
    assert set(fs._LXD_INCUS_IFACES) <= set(fs._active_ifaces(snap))


def _env(monkeypatch, ifaces, procs):
    monkeypatch.setattr(fs, "_host_ifaces", lambda: ifaces)
    monkeypatch.setattr(fs, "_process_runs", lambda name: name in procs)


def test_the_daemon_and_its_bridge_are_both_needed(monkeypatch):
    _env(monkeypatch, ["lo", "enp3s0", "incusbr0", "incusbr-1004"], {"incusd"})
    assert fs._lxd_incus_routing() is True
    _env(monkeypatch, ["lo", "enp3s0", "lxdbr0"], {"lxd"})
    assert fs._lxd_incus_routing() is True


def test_a_bridge_left_by_a_removed_lxd_does_not_count(monkeypatch):
    _env(monkeypatch, ["lo", "enp3s0", "lxdbr0"], set())
    assert fs._lxd_incus_routing() is False


def test_a_daemon_without_a_bridge_does_not_count(monkeypatch):
    _env(monkeypatch, ["lo", "enp3s0"], {"incusd"})
    assert fs._lxd_incus_routing() is False
    _env(monkeypatch, None, {"incusd"})
    assert fs._lxd_incus_routing() is False
