"""v0.33.0 — while something routes, only the FORWARD rules it can own are excused.

0.32.0 excused every ACCEPT rule in FORWARD as soon as one routing mechanism
ran (measured, fwd0320 case 6). FORWARD is now also read in `-S` form, which
names interfaces and comments: a rule naming interfaces, none of them a running
mechanism's, or carrying MicroK8s' comment while MicroK8s does not run, costs
`firewall_drivers.iptables_forward_bypass` (WARN −1) as it would with nothing
routing. A rule naming no interface and no known comment cannot be attributed:
still excused. Measured on Ubuntu Server 26.04.1, UFW active (fwd0330):

| case                                                         | 0.32.0 | 0.33.0 |
|--------------------------------------------------------------|--------|--------|
| MicroK8s running, + `-i bobwg0` (no such interface)          | 0      | −1     |
| MicroK8s running, its two rules                              | 0      | 0      |
| MicroK8s stopped (its rules left), Docker running            | 0      | −2     |
| + `-i docker0`, Docker running                               | 0      | −2 (docker0 excused) |
| WireGuard up, gateway `-i bobwg0 -o enp3s0`, MicroK8s stopped | 0     | −2 (gateway excused) |
"""

from __future__ import annotations

import pytest

from bob.checks import firewall_stack as fs

MK8S = ['-A FORWARD -s 10.1.0.0/16 -m comment --comment "generated for MicroK8s pods" -j ACCEPT',
        '-A FORWARD -d 10.1.0.0/16 -m comment --comment "generated for MicroK8s pods" -j ACCEPT']


#: The bench host's interfaces (Ubuntu Server, fwd0330): bobwg0 exists only
#: when a test says so.
HOST = ["lo", "enp3s0", "docker0"]


def _snap(rules, **kw):
    kw.setdefault("host_ifaces", HOST)
    return fs.FirewallStackSnapshot(forward_raw_accepts=["ACCEPT all -- x"] * len(rules),
                                    forward_accepts_s=list(rules), **kw)


def _bypass(snap):
    result = fs.check_firewall_stack(snap, ufw_active=True)
    return sum(d.points for d in result.deductions if d.key == "firewall_drivers.iptables_forward_bypass")


def test_f1_an_interface_nothing_owns():
    snap = _snap(MK8S + ["-A FORWARD -i bobwg0 -j ACCEPT"], kubernetes_running=True, microk8s_running=True)
    assert fs._forward_orphans(snap) == ["-A FORWARD -i bobwg0 -j ACCEPT"] and _bypass(snap) == 1


def test_f2_microk8s_owns_its_rules():
    assert _bypass(_snap(MK8S, kubernetes_running=True, microk8s_running=True)) == 0


def test_f3_microk8s_stopped_its_rules_are_orphans():
    assert _bypass(_snap(MK8S, docker_present=True)) == 2


def test_f4_docker0_is_dockers():
    snap = _snap(MK8S + ["-A FORWARD -i docker0 -j ACCEPT"], docker_present=True)
    assert "-A FORWARD -i docker0 -j ACCEPT" not in fs._forward_orphans(snap) and _bypass(snap) == 2


def test_a_removed_docker_network_is_still_dockers_while_docker_runs():
    # an existing interface is excused anyway; ownership decides for one gone
    snap = _snap(["-A FORWARD -o br-0a1b2c3d -j ACCEPT"], docker_present=True)
    assert fs._forward_orphans(snap) == []


def test_f5_a_gateway_rule_one_of_whose_interfaces_runs():
    snap = _snap(MK8S + ["-A FORWARD -i bobwg0 -o enp3s0 -j ACCEPT"], wireguard_present=True,
                 wireguard_ifaces=["bobwg0"], host_ifaces=HOST + ["bobwg0"])
    assert fs._forward_orphans(snap) == MK8S and _bypass(snap) == 2


def test_a_negated_interface_attributes_nothing():
    snap = _snap(["-A FORWARD -i docker0 ! -o docker0 -j ACCEPT"], docker_present=True)
    assert fs._forward_orphans(snap) == []
    snap = _snap(["-A FORWARD ! -i bobwg0 -j ACCEPT"], docker_present=True)
    assert fs._forward_orphans(snap) == []          # no positive interface: not attributable, excused


def test_no_interface_no_known_comment_stays_excused():
    assert _bypass(_snap(["-A FORWARD -s 10.42.0.0/16 -j ACCEPT"], kubernetes_running=True)) == 0


def test_an_iptables_wildcard_owns_by_prefix():
    assert fs._owned("bobwg+", ("bobwg0",)) and fs._owned("dock+", fs._DOCKER_IFACES)
    assert not fs._owned("eth+", ("bobwg0",))


def test_an_iptables_wildcard_is_a_prefix():
    assert fs._forward_orphans(_snap(["-A FORWARD -o docker+ -j ACCEPT"], docker_present=True)) == []
    # -i bobwg+ matches the WireGuard interface bobwg0 that runs
    snap = _snap(["-A FORWARD -i bobwg+ -j ACCEPT"], wireguard_present=True, wireguard_ifaces=["bobwg0"],
                 host_ifaces=HOST + ["bobwg0"])
    assert fs._forward_orphans(snap) == []
    # eth+ owned by nothing and matching no interface of the host: stale
    snap = _snap(["-A FORWARD -i eth+ -j ACCEPT"], wireguard_present=True, wireguard_ifaces=["bobwg0"],
                 host_ifaces=HOST + ["bobwg0"])
    assert fs._forward_orphans(snap) == ["-A FORWARD -i eth+ -j ACCEPT"]
    # enp+ matches enp3s0, which exists: unknown, excused
    snap = _snap(["-A FORWARD -i enp+ -j ACCEPT"], wireguard_present=True, wireguard_ifaces=["bobwg0"],
                 host_ifaces=HOST + ["bobwg0"])
    assert fs._forward_orphans(snap) == []


def test_from_system_reads_the_s_form(monkeypatch):
    calls = {}
    def run(*a, **k):
        calls[a] = True
        return "-P FORWARD ACCEPT\n-A FORWARD -i bobwg0 -j ACCEPT\n" if a == ("iptables", "-S", "FORWARD") else ""
    monkeypatch.setattr(fs, "_run", run)
    monkeypatch.setattr(fs, "_command_exists", lambda n: False)
    monkeypatch.setattr(fs, "_dockerd_runs", lambda: True)
    monkeypatch.setattr(fs, "_wireguard_ifaces", lambda: [])
    monkeypatch.setattr(fs, "_libvirt_routing", lambda: False)
    monkeypatch.setattr(fs, "kubelet_running", lambda: False)
    monkeypatch.setattr(fs, "_process_runs", lambda name: False)
    monkeypatch.setattr(fs, "_host_ifaces", lambda: ["lo", "enp3s0"])
    snap = fs.FirewallStackSnapshot.from_system()
    assert snap.forward_accepts_s == ["-A FORWARD -i bobwg0 -j ACCEPT"]
    assert snap.host_ifaces == ["lo", "enp3s0"]


# --- After review (12 November 2026): an existing interface BOB cannot
# attribute is unknown, not proof of a bypass. Reproduced in code before the
# change: with a kubelet running, `-i antrea-gw0` and `-i lxdbr0 -o enp3s0`
# cost −1 each although their interfaces exist; 0.32.0 excused both.

def test_an_existing_interface_bob_cannot_attribute_is_excused():
    rules = ["-A FORWARD -i antrea-gw0 -j ACCEPT", "-A FORWARD -i lxdbr0 -o enp3s0 -j ACCEPT"]
    snap = _snap(rules, kubernetes_running=True, host_ifaces=HOST + ["antrea-gw0", "lxdbr0"])
    assert fs._forward_orphans(snap) == [] and _bypass(snap) == 0


def test_one_missing_interface_makes_the_rule_stale():
    # the gateway of case 5 once WireGuard's interface is gone
    snap = _snap(["-A FORWARD -i bobwg0 -o enp3s0 -j ACCEPT"], docker_present=True)
    assert _bypass(snap) == 1


def test_interfaces_unlisted_attribute_nothing():
    snap = _snap(["-A FORWARD -i bobwg0 -j ACCEPT"], docker_present=True, host_ifaces=None)
    assert fs._forward_orphans(snap) == [] and _bypass(snap) == 0


def test_each_case_says_its_own_reason():
    snap = _snap(MK8S[:1] + ["-A FORWARD -i bobwg0 -j ACCEPT"], docker_present=True)
    msgs = [f.message.split(" ")[0] for f in fs.check_firewall_stack(snap, ufw_active=True).findings
            if f.key == "firewall_drivers.iptables_forward_bypass"]
    assert msgs == ["firewall_drivers.iptables_forward_orphan", "firewall_drivers.iptables_forward_stale"]


def test_from_system_lists_the_interfaces(monkeypatch, tmp_path):
    for name in ("lo", "enp3s0"):
        (tmp_path / name).mkdir()
    monkeypatch.setattr(fs, "_SYS_NET", tmp_path)
    assert fs._host_ifaces() == ["enp3s0", "lo"]
    monkeypatch.setattr(fs, "_SYS_NET", tmp_path / "absent")
    assert fs._host_ifaces() is None


# --- Review 4 (12 November 2026): a known interface does not excuse a missing
# one in the same rule. Before this, `-i unknown0 -o docker0` was excused by
# docker0 although unknown0 does not exist.

@pytest.mark.parametrize("rule, host, points", [
    ("-A FORWARD -i unknown0 -o docker0 -j ACCEPT", HOST, 1),
    ("-A FORWARD -i docker0 -o unknown0 -j ACCEPT", HOST, 1),
    ("-A FORWARD -i docker0 -o enp3s0 -j ACCEPT", HOST, 0),
    ("-A FORWARD -i unknown0 -o enp3s0 -j ACCEPT", HOST + ["unknown0"], 0),
])
def test_each_interface_is_judged_on_its_own(rule, host, points):
    assert _bypass(_snap([rule], docker_present=True, host_ifaces=host)) == points
