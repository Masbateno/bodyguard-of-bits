"""v0.36.0 — the virtualisation section names Incus, and no longer an orphan LXD bridge.

Measured on Debian 13 (a10360, 14 November 2026): after the LXD package was
purged, lxdbr0 (and the inet lxd table) stayed, and the section kept saying
"LXD/LXC detected — lxdbr0 …"; with Incus 6.0.4 running (incusd, incusbr0,
incusbr-1004) it named neither. A bridge alone now names LXD only while lxd
runs; Incus is named by its binary, or by an incusbr* bridge while incusd runs.
"""

from __future__ import annotations

import pytest

from bob.checks import virtualization as V


def _names(monkeypatch, ifaces, binaries=(), procs=()):
    monkeypatch.setattr(V, "_get_network_interfaces", lambda: list(ifaces))
    monkeypatch.setattr(V, "_command_exists", lambda n: n in binaries)
    monkeypatch.setattr(V, "_process_runs", lambda n: n in procs)
    monkeypatch.setattr(V, "_libvirt_routing", lambda **kw: False)
    monkeypatch.setattr(V, "_get_snap_network_packages", lambda: [])
    return [(t.name, t.iface) for t in V.VirtSnapshot.from_system().technologies]


def test_an_orphan_lxd_bridge_names_nothing(monkeypatch):
    assert _names(monkeypatch, ["lo", "enp3s0", "lxdbr0"]) == []


def test_lxd_running_with_its_bridge_is_named(monkeypatch):
    assert _names(monkeypatch, ["lxdbr0"], procs={"lxd"}) == [("LXD/LXC", "lxdbr0")]


def test_the_lxd_client_alone_still_names_it(monkeypatch):
    assert _names(monkeypatch, [], binaries={"lxc"}) == [("LXD/LXC", "lxdbr0")]


@pytest.mark.parametrize("kw", [dict(binaries={"incus"}), dict(procs={"incusd"})])
def test_incus_is_named(monkeypatch, kw):
    assert _names(monkeypatch, ["incusbr0", "incusbr-1004"], **kw) == [("Incus", "incusbr0")]


def test_an_orphan_incus_bridge_names_nothing(monkeypatch):
    assert _names(monkeypatch, ["incusbr0"]) == []
