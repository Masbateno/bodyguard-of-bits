"""v0.31.1 — a bridge port or a bond slave is not weighed by its own sysctls.

0.31.0 read the redirect, source-route and martian-logging knobs per interface.
A bridge port and a bond slave hand their frames to their master before their
own IP stack sees them, so their own conf/<name> values decide nothing.
Measured on Kali in network namespaces (7 November 2026,
``netnsbench/bridgeport-redirect-0311.txt``), an ICMPv6 redirect sent through
the port, conf/all and conf/default at 0:

| case | the port | its master | redirect | 0.31.0 |
|---|---|---|---|---|
| A bridge | 1 | 0 | refused | the port flagged (−1) |
| B bridge | 0 | 1 | accepted | the bridge flagged |
| D bond | 1 | 0 | refused | the slave flagged (−1) |
| E bond | 0 | 1 | accepted | the bond flagged |
| F VRF member | 1 | 0 | accepted (its own IP stack) | the member flagged |

Seen on a Mint desktop: enp10s0, a port of br0, alone at 1 — "IPv6 redirects
accepted", −1, at the top of "to fix". A VRF member keeps its own stack and
stays weighed; /sys shows no device type for a VRF, so the port is told by its
own markers (``brport/``, ``bonding_slave/``), not by its master's kind.
"""

from __future__ import annotations

import pytest

from bob.checks import hardening as h
from tests.test_v0310_sysctl_per_iface import _proc, _v4, _v6


def _sysfs(monkeypatch, tmp_path, bridge_ports=(), bond_slaves=(), others=()):
    for name in (*bridge_ports, *bond_slaves, *others):
        (tmp_path / name).mkdir()
    for name in bridge_ports:
        (tmp_path / name / "brport").mkdir()
    for name in bond_slaves:
        (tmp_path / name / "bonding_slave").mkdir()
    monkeypatch.setattr(h, "_SYS_NET", tmp_path)


class TestTheMeasuredCases:

    def test_a_bridge_port_alone_at_1(self, monkeypatch, tmp_path):
        """A — the Mint's setting: refused by the kernel, not flagged."""
        _proc(monkeypatch, {**_v6("accept_redirects", all=False, default=False, br0=False, p0=True),
                            **_v6("forwarding", br0=False, p0=False, default=False)},
              ifaces=("br0", "p0"))
        _sysfs(monkeypatch, tmp_path, bridge_ports=("p0",), others=("br0",))
        assert h._on(h._effective_by_iface("accept_redirects", "v6", "ipv6")) == []

    def test_the_bridge_at_1(self, monkeypatch, tmp_path):
        """B — polarity: the bridge decides, and is flagged."""
        _proc(monkeypatch, {**_v6("accept_redirects", all=False, default=False, br0=True, p0=False),
                            **_v6("forwarding", br0=False, p0=False, default=False)},
              ifaces=("br0", "p0"))
        _sysfs(monkeypatch, tmp_path, bridge_ports=("p0",), others=("br0",))
        assert h._on(h._effective_by_iface("accept_redirects", "v6", "ipv6")) == ["br0"]

    def test_a_bond_slave_alone_at_1(self, monkeypatch, tmp_path):
        """D — refused by the kernel, not flagged."""
        _proc(monkeypatch, {**_v6("accept_redirects", all=False, default=False, bond0=False, p0=True),
                            **_v6("forwarding", bond0=False, p0=False, default=False)},
              ifaces=("bond0", "p0"))
        _sysfs(monkeypatch, tmp_path, bond_slaves=("p0",), others=("bond0",))
        assert h._on(h._effective_by_iface("accept_redirects", "v6", "ipv6")) == []

    def test_a_vrf_member_is_still_weighed(self, monkeypatch, tmp_path):
        """F — its own stack accepted the redirect: flagged, as in 0.31.0."""
        _proc(monkeypatch, {**_v6("accept_redirects", all=False, default=False, vrf0=False, p0=True),
                            **_v6("forwarding", vrf0=False, p0=False, default=False)},
              ifaces=("vrf0", "p0"))
        _sysfs(monkeypatch, tmp_path, others=("vrf0", "p0"))
        assert h._on(h._effective_by_iface("accept_redirects", "v6", "ipv6")) == ["p0"]


class TestEveryKnob:

    @pytest.mark.parametrize("knob, rule", [("send_redirects", "or"), ("log_martians", "or"),
                                            ("accept_redirects", "redirects")])
    def test_the_ipv4_knobs_skip_a_port(self, monkeypatch, tmp_path, knob, rule):
        values = {**_v4(knob, all=False, default=False, br0=False, enp10s0=True),
                  **_v4("forwarding", br0=False, enp10s0=False, default=False)}
        _proc(monkeypatch, values, ifaces=("br0", "enp10s0"))
        _sysfs(monkeypatch, tmp_path, bridge_ports=("enp10s0",), others=("br0",))
        assert "enp10s0" not in h._effective_by_iface(knob, rule)

    def test_rp_filter_skips_a_port(self, monkeypatch, tmp_path):
        """A port at 0 beside a bridge at 2 does not make the host read "disabled"."""
        values = {"net.ipv4.conf.all.rp_filter": 0, "net.ipv4.conf.br0.rp_filter": 2,
                  "net.ipv4.conf.enp10s0.rp_filter": 0}

        class Dir:
            def iterdir(self):
                return [type("E", (), {"name": n})() for n in ("all", "default", "lo", "br0", "enp10s0")]
        monkeypatch.setattr(h, "_IPV4_CONF", Dir())
        monkeypatch.setattr(h, "_read_sysctl_int", lambda key: values.get(key))
        _sysfs(monkeypatch, tmp_path, bridge_ports=("enp10s0",), others=("br0",))
        assert h._effective_rp_filter() == (2, 0, "br0")


class TestWhatCannotBeRead:

    def test_an_unreadable_marker_is_weighed(self, monkeypatch):
        """Never hide: a port BOB cannot tell is counted, as in 0.31.0."""
        class Denied:
            def __truediv__(self, other):
                return self

            def is_dir(self):
                raise PermissionError("denied")
        monkeypatch.setattr(h, "_SYS_NET", Denied())
        assert h._l2_port("enp10s0") is False

    def test_no_interface_directory(self, monkeypatch, tmp_path):
        monkeypatch.setattr(h, "_SYS_NET", tmp_path)
        assert h._l2_port("gone0") is False
