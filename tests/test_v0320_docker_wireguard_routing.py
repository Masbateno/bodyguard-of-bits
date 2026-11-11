"""v0.32.0 — Docker and WireGuard count as routing while they run.

0.31.4 counted them as soon as `docker` or /var/lib/docker existed, or `wg`
or /etc/wireguard/*.conf: installed, not routing. With IP forwarding on, that
turned `firewall_drivers.ip_forward_enabled` (WARN −1) into "routing daemon
detected" (OK), as libvirt did until v0.31.3. Measured on Ubuntu Server 26.04
(11 November 2026, route0320): Docker stopped left docker0, its 15 DOCKER rules
and /var/lib/docker, and no dockerd process; WireGuard configured had no
interface until wg-quick brought one up, whose uevent said DEVTYPE=wireguard
(a tun device has no DEVTYPE).
"""

from __future__ import annotations

import pytest

from bob.checks import firewall_stack as fs


@pytest.fixture
def proc(tmp_path, monkeypatch):
    root = tmp_path / "proc"
    root.mkdir()
    monkeypatch.setattr(fs, "_PROC", root)

    def add(pid, comm):
        (root / pid).mkdir()
        (root / pid / "comm").write_text(comm + "\n")
    return add


@pytest.fixture
def sysnet(tmp_path, monkeypatch):
    root = tmp_path / "net"
    root.mkdir()
    monkeypatch.setattr(fs, "_SYS_NET", root)

    def add(name, uevent):
        (root / name).mkdir()
        (root / name / "uevent").write_text(uevent)
    return add


class TestDocker:
    def test_dockerd_running(self, proc):
        proc("812", "containerd")
        proc("901", "dockerd")
        assert fs._dockerd_runs() is True

    def test_installed_and_stopped(self, proc):
        proc("812", "containerd")
        assert fs._dockerd_runs() is False

    def test_a_name_that_only_starts_alike(self, proc):
        proc("901", "dockerd-rootless")
        assert fs._dockerd_runs() is False


class TestWireGuard:
    def test_an_interface(self, sysnet):
        sysnet("lo", "INTERFACE=lo\nIFINDEX=1\n")
        sysnet("bobwg0", "DEVTYPE=wireguard\nINTERFACE=bobwg0\nIFINDEX=12\n")
        assert fs._wireguard_interface() is True

    def test_a_tun_is_not_wireguard(self, sysnet):
        sysnet("bobtun0", "INTERFACE=bobtun0\nIFINDEX=13\n")
        sysnet("docker0", "DEVTYPE=bridge\nINTERFACE=docker0\nIFINDEX=11\n")
        assert fs._wireguard_interface() is False


@pytest.mark.parametrize("dockerd, wg", [(True, False), (False, True)], ids=["docker-runs", "wireguard-up"])
def test_from_system_reads_them(monkeypatch, dockerd, wg):
    monkeypatch.setattr(fs, "_dockerd_runs", lambda: dockerd)
    monkeypatch.setattr(fs, "_wireguard_ifaces", lambda: ["wg0"] if wg else [])
    monkeypatch.setattr(fs, "_run", lambda *a, **k: "")
    monkeypatch.setattr(fs, "_command_exists", lambda n: False)
    monkeypatch.setattr(fs, "_libvirt_routing", lambda: False)
    monkeypatch.setattr(fs, "kubelet_running", lambda: False)
    snap = fs.FirewallStackSnapshot.from_system()
    assert (snap.docker_present, snap.wireguard_present) == (dockerd, wg)


def test_installed_and_stopped_leaves_ip_forward_unexplained():
    snap = fs.FirewallStackSnapshot(ip_forward=True, docker_present=False, wireguard_present=False,
                                    libvirt_present=False, kubernetes_running=False)
    keys = {f.key for f in fs.check_firewall_stack(snap).findings}
    assert "firewall_drivers.ip_forward_enabled" in keys
