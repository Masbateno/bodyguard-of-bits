"""v0.25.0 — a running kubelet routes, and its FORWARD rules are its own.

Measured on a real Ubuntu Server 26.04 with MicroK8s 1.35 running: BOB
deducted for the FORWARD rule MicroK8s writes for its pod network ("generated
for MicroK8s pods", 10.1.0.0/16) and offered ``sysctl net.ipv4.ip_forward=0``
as the fix for IP forwarding — applied, it cuts every pod off. A running
kubelet is now a routing context, like Docker, WireGuard or libvirt.
"""

from __future__ import annotations

import pytest

from bob.checks import _run as runmod
from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
from tests.helpers import _keys, _t

_MICROK8S_RULE = "ACCEPT     all  --  10.1.0.0/16          0.0.0.0/0            /* generated for MicroK8s pods */"


def _snap(**kw):
    base = dict(forward_raw_accepts=[_MICROK8S_RULE], ip_forward=True, rules_readable=True)
    base.update(kw)
    return FirewallStackSnapshot(**base)


def test_a_kubernetes_node_routes():
    result = check_firewall_stack(_snap(kubernetes_running=True), t=_t)
    keys = _keys(result)
    assert "firewall_drivers.forward_routing_ok" in keys and "firewall_drivers.ip_forward_ok" in keys
    assert not result.deductions


def test_without_a_kubelet_it_is_still_questioned():
    keys = _keys(check_firewall_stack(_snap(), t=_t))
    assert "firewall_drivers.iptables_forward_bypass" in keys and "firewall_drivers.ip_forward_enabled" in keys


@pytest.mark.parametrize("comm, running", [("kubelite", True), ("kubelet", True), ("k3s-server", True),
                                           ("containerd", False), ("sshd", False)])
def test_the_kubelet_by_process_name(tmp_path, monkeypatch, comm, running):
    proc = tmp_path / "proc"
    (proc / "1").mkdir(parents=True)
    (proc / "1" / "comm").write_text(comm + "\n")
    (proc / "self").mkdir()
    real = runmod.Path
    monkeypatch.setattr(runmod, "Path", lambda p, *a: real(str(proc)) if p == "/proc" else real(p, *a))
    assert runmod.kubelet_running() is running


def test_the_snapshot_asks():
    import inspect
    assert "kubernetes_running=kubelet_running()," in inspect.getsource(FirewallStackSnapshot.from_system)
