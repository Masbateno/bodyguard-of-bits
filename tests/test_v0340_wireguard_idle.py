"""v0.34.0 — a WireGuard client that forwards nothing is said, not excused silently.

WireGuard counts as a routing mechanism (since v0.32.0, while an interface
exists), so `ip_forward=1` beside it read OK. A client routes for no one.
Measured in three network namespaces on Linux Mint 22.3 (wgfwd, 12 November
2026), ip_forward=1 on both ends: the client, traffic in its tunnel, kept
`Ip: ForwDatagrams` at 0; the gateway, answering on its own tunnel address,
at 0; routing the client to a LAN behind it, 10 (5 pings, both ways). The
interface's own `forwarding` sysctl read 1 on the client: no help.

When WireGuard is the only mechanism detected and the counter is 0, BOB says
so (INFO, no point, no fix command); otherwise nothing changes.
"""

from __future__ import annotations

from bob.checks import firewall_stack as fs
from tests.helpers import _t


def _snap(**kw):
    base = dict(ip_forward=True, wireguard_present=True, wireguard_ifaces=["wg0"],
                forwarded_v4=0, uptime_s=3 * 86400 + 5)
    base.update(kw)
    return fs.FirewallStackSnapshot(**base)


def _keys(snap):
    r = fs.check_firewall_stack(snap, t=_t, ufw_active=False)
    return [(f.level.value, f.key) for f in r.findings], sum(d.points for d in r.deductions)


def test_a_client_that_forwarded_nothing_is_said():
    keys, points = _keys(_snap())
    assert ("info", "firewall_drivers.ip_forward_wireguard_idle") in keys
    assert ("ok", "firewall_drivers.ip_forward_ok") not in keys
    assert points == 0


def test_the_finding_carries_no_fix():
    r = fs.check_firewall_stack(_snap(), t=_t, ufw_active=False)
    f = next(f for f in r.findings if f.key == "firewall_drivers.ip_forward_wireguard_idle")
    assert f.cmd == "" and not f.fix_action


def test_a_gateway_that_forwarded_stays_ok():
    keys, _ = _keys(_snap(forwarded_v4=10))
    assert ("ok", "firewall_drivers.ip_forward_ok") in keys
    assert not any(k == "firewall_drivers.ip_forward_wireguard_idle" for _, k in keys)


def test_an_unread_counter_or_uptime_claims_nothing():
    for kw in ({"forwarded_v4": None}, {"uptime_s": None}):
        keys, _ = _keys(_snap(**kw))
        assert ("ok", "firewall_drivers.ip_forward_ok") in keys, kw


def test_another_mechanism_beside_wireguard_stays_ok():
    for kw in ({"docker_present": True}, {"libvirt_present": True}, {"kubernetes_running": True}):
        keys, _ = _keys(_snap(**kw))
        assert ("ok", "firewall_drivers.ip_forward_ok") in keys, kw


def test_how_long_it_has_counted():
    seen = {}

    def t(key, **kw):
        seen.setdefault(key, kw)
        return key
    fs.check_firewall_stack(_snap(uptime_s=3 * 86400 + 5), t=t, ufw_active=False)
    assert seen["firewall_drivers.since_boot_days"] == {"days": 3}
    seen.clear()
    fs.check_firewall_stack(_snap(uptime_s=600), t=t, ufw_active=False)
    assert seen["firewall_drivers.since_boot_hours"] == {"hours": 1}


def test_the_counter_is_read_by_name(tmp_path, monkeypatch):
    snmp = tmp_path / "snmp"
    snmp.write_text(
        # ForwDatagrams moved from its usual column: read by name, not position
        "Ip: Forwarding DefaultTTL ForwDatagrams InReceives InHdrErrors InAddrErrors InUnknownProtos\n"
        "Ip: 1 64 10 1234 0 0 0\n"
        "Icmp: InMsgs\nIcmp: 3\n")
    monkeypatch.setattr(fs, "_PROC_SNMP", snmp)
    assert fs._forwarded_v4() == 10
    monkeypatch.setattr(fs, "_PROC_SNMP", tmp_path / "absent")
    assert fs._forwarded_v4() is None


def test_from_system_reads_counter_and_uptime(monkeypatch):
    monkeypatch.setattr(fs, "_run", lambda *a, **k: "")
    monkeypatch.setattr(fs, "_command_exists", lambda n: False)
    monkeypatch.setattr(fs, "_forwarded_v4", lambda: 7)
    monkeypatch.setattr(fs, "_uptime_s", lambda: 42.0)
    snap = fs.FirewallStackSnapshot.from_system()
    assert snap.forwarded_v4 == 7 and snap.uptime_s == 42.0
