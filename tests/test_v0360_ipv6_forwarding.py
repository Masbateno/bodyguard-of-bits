"""v0.36.0 — IPv6 forwarding is read and judged as IPv4's is.

Before 0.36.0 BOB read net.ipv4.ip_forward only: a host routing IPv6
between its interfaces said nothing. Measured in network namespaces on
Linux Mint 22.3 (a10360, 14 November 2026), documentation prefixes:

| case (router namespace)                                 | IPv6 routed | Ip6OutForwDatagrams |
|---------------------------------------------------------|-------------|---------------------|
| net.ipv6.conf.all.forwarding=0                          | refused     | 0                   |
| all.forwarding=1                                        | yes         | 6                   |
| the fix: all.forwarding=0 (every interface and default → 0) | refused | —                   |
| all.forwarding=0, the two interfaces' forwarding=1      | refused     | —                   |
| WireGuard client, IPv6 traffic in its tunnel            | —           | 0 (client)          |
| WireGuard gateway routing the client to a LAN           | yes         | 6 → 16 (gateway)    |

So all.forwarding is the knob that routes, and the counter tells a
WireGuard client from a gateway for IPv6 as ForwDatagrams does for IPv4.
"""

from __future__ import annotations

from pathlib import Path

from bob.checks import firewall_stack as fs
from tests.helpers import _t


def _snap(**kw):
    base = dict(ip6_forward=True, forwarded_v6=0, uptime_s=2 * 86400 + 7)
    base.update(kw)
    return fs.FirewallStackSnapshot(**base)


def _findings(snap):
    r = fs.check_firewall_stack(snap, t=_t, ufw_active=False)
    return r, [(f.level.value, f.key) for f in r.findings]


def test_ipv6_forwarding_without_a_mechanism_costs_a_point_and_offers_the_fix():
    r, keys = _findings(_snap())
    assert ("warn", "firewall_drivers.ip6_forward_enabled") in keys
    assert sum(d.points for d in r.deductions) == 1
    f = next(f for f in r.findings if f.key == "firewall_drivers.ip6_forward_enabled")
    assert "net.ipv6.conf.all.forwarding=0" in f.cmd


def test_ipv6_forwarding_off_says_nothing_of_it():
    _, keys = _findings(_snap(ip6_forward=False))
    assert not any("ip6_forward" in k for _, k in keys)


def test_each_family_is_judged_on_its_own():
    r, keys = _findings(_snap(ip_forward=True))
    assert ("warn", "firewall_drivers.ip_forward_enabled") in keys
    assert ("warn", "firewall_drivers.ip6_forward_enabled") in keys
    assert sum(d.points for d in r.deductions) == 2
    _, keys = _findings(_snap(ip_forward=True, ip6_forward=False))
    assert not any("ip6_forward" in k for _, k in keys)


def test_a_running_mechanism_excuses_it():
    for kw in ({"docker_present": True}, {"libvirt_present": True}, {"kubernetes_running": True},
               {"wireguard_present": True, "wireguard_ifaces": ["wg0"], "forwarded_v6": 16}):
        r, keys = _findings(_snap(**kw))
        assert ("ok", "firewall_drivers.ip6_forward_ok") in keys, kw
        assert sum(d.points for d in r.deductions) == 0, kw


def test_a_wireguard_client_that_forwarded_no_ipv6_is_said():
    r, keys = _findings(_snap(wireguard_present=True, wireguard_ifaces=["wg0"]))
    assert ("info", "firewall_drivers.ip6_forward_wireguard_idle") in keys
    assert sum(d.points for d in r.deductions) == 0
    f = next(f for f in r.findings if f.key == "firewall_drivers.ip6_forward_wireguard_idle")
    assert f.cmd == "" and not f.fix_action


def test_an_unread_counter_claims_no_idleness():
    for kw in ({"forwarded_v6": None}, {"uptime_s": None}):
        _, keys = _findings(_snap(wireguard_present=True, wireguard_ifaces=["wg0"], **kw))
        assert ("ok", "firewall_drivers.ip6_forward_ok") in keys, kw


def test_the_counter_is_read_by_name(tmp_path, monkeypatch):
    f = tmp_path / "snmp6"
    f.write_text("Ip6InReceives                   \t3110\nIp6OutForwDatagrams             \t16\n"
                 "Ip6OutRequests                  \t2876\n")
    monkeypatch.setattr(fs, "_PROC_SNMP6", f)
    assert fs._forwarded_v6() == 16
    f.write_text("Ip6InReceives 3\n")
    assert fs._forwarded_v6() is None
    monkeypatch.setattr(fs, "_PROC_SNMP6", tmp_path / "absent")
    assert fs._forwarded_v6() is None


def test_the_all_knob_is_the_one_read(tmp_path, monkeypatch):
    f = tmp_path / "forwarding"
    for value, want in (("1\n", True), ("0\n", False)):
        f.write_text(value)
        monkeypatch.setattr(fs, "_IP6_FORWARD", f)
        assert fs._read_ip6_forward() is want
    monkeypatch.setattr(fs, "_IP6_FORWARD", tmp_path / "no-ipv6")
    assert fs._read_ip6_forward() is False
    monkeypatch.undo()
    assert fs._IP6_FORWARD == Path("/proc/sys/net/ipv6/conf/all/forwarding")


def test_desktop_and_workstation_make_it_an_info_as_for_ipv4():
    root = Path(__file__).resolve().parent.parent / "bob" / "data" / "profiles"
    for name in ("desktop.conf", "workstation.conf"):
        text = (root / name).read_text(encoding="utf-8")
        assert "firewall_drivers.ip6_forward_enabled = info" in text, name
        assert "firewall_drivers.ip_forward_enabled = info" in text, name


def test_from_system_reads_ipv6_forwarding(monkeypatch):
    monkeypatch.setattr(fs, "_read_ip6_forward", lambda: True)
    monkeypatch.setattr(fs, "_forwarded_v6", lambda: 4)
    monkeypatch.setattr(fs, "_run", lambda *a, **k: "")
    monkeypatch.setattr(fs, "_dockerd_runs", lambda: False)
    monkeypatch.setattr(fs, "_wireguard_ifaces", lambda: [])
    monkeypatch.setattr(fs, "_libvirt_routing", lambda *a, **k: False)
    monkeypatch.setattr(fs, "kubelet_running", lambda: False)
    snap = fs.FirewallStackSnapshot.from_system()
    assert snap.ip6_forward is True and snap.forwarded_v6 == 4


def test_both_families_stay_independent_under_the_real_profiles():
    """Under desktop and workstation each family is an INFO of its own, no point;
    under server each costs its point — through the shipped profile files."""
    from bob.profiles import load_profile
    from bob.scoring import ScoreEngine
    snap = fs.FirewallStackSnapshot(ip_forward=True, ip6_forward=True, forwarded_v6=0, uptime_s=7200.0)
    for name, points in (("server", 2), ("desktop", 0), ("workstation", 0)):
        res = fs.check_firewall_stack(snap, t=_t, ufw_active=False)
        engine = ScoreEngine(profile=load_profile(name))
        engine.apply(res, section="firewall_drivers")
        kept = {d.key: d.points for d in engine.breakdown}
        assert sum(kept.values()) == points, (name, kept)
        levels = {f.key: f.level.value for f in res.findings}
        assert "firewall_drivers.ip_forward_enabled" in levels and "firewall_drivers.ip6_forward_enabled" in levels
