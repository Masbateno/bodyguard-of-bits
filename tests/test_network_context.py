"""
Unit tests for bob.checks.network_context module.

All tests use snapshots built directly — no subprocess calls.

Run with: python -m pytest tests/test_network_context.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.network_context import (
    ConnectionInfo,
    InterfaceInfo,
    NetworkContextSnapshot,
    _extract_process,
    _interface_type,
    _is_private_or_loopback,
    _parse_connections,
    _parse_interfaces,
    _split_addr_port,
    check_network_context,
    top_remote_ips,
)
from tests.helpers import _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snapshot(**overrides) -> NetworkContextSnapshot:
    defaults = dict(interfaces=[], connections=[])
    defaults.update(overrides)
    return NetworkContextSnapshot(**defaults)


def make_iface(**kwargs) -> InterfaceInfo:
    defaults = dict(name="enp3s0", if_type="ethernet", is_up=True, address="192.168.1.1/24")
    defaults.update(kwargs)
    return InterfaceInfo(**defaults)


def make_conn(**kwargs) -> ConnectionInfo:
    defaults = dict(
        local_addr="192.168.1.42", local_port=12345,
        remote_addr="142.250.74.14", remote_port=443,
        process="chrome",
    )
    defaults.update(kwargs)
    return ConnectionInfo(**defaults)


def has_level(result, level: str) -> bool:
    return level in [f.level.value for f in result.findings]


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


# ---------------------------------------------------------------------------
# check_network_context — basic findings
# ---------------------------------------------------------------------------

class TestCheckNetworkContext:
    def test_no_findings_for_clean_system(self):
        """No tunnel, no sensitive connections → no findings at all."""
        snap = make_snapshot(interfaces=[make_iface()], connections=[])
        result = check_network_context(snap, t=_t)
        assert result.findings == []

    def test_no_warn_for_normal_connection(self):
        snap = make_snapshot(connections=[make_conn(remote_port=443)])
        result = check_network_context(snap, t=_t)
        assert not has_level(result, "warn")

    def test_no_deductions_for_normal_traffic(self):
        snap = make_snapshot(
            interfaces=[make_iface()],
            connections=[make_conn(remote_port=443)],
        )
        result = check_network_context(snap, t=_t)
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Tunnel interface detection
# ---------------------------------------------------------------------------

class TestTunnelInterface:
    def test_info_for_active_tunnel(self):
        """The tunnel interface name must be passed to the translation function."""
        received = {}

        def _t_capture(key, **kwargs):
            if key == "network_context.tunnel_active":
                received.update(kwargs)
            return key

        snap = make_snapshot(interfaces=[
            make_iface(name="tun0", if_type="tunnel", is_up=True),
        ])
        check_network_context(snap, t=_t_capture)
        assert received.get("name") == "tun0"

    def test_no_tunnel_info_when_down(self):
        snap = make_snapshot(interfaces=[
            make_iface(name="tun0", if_type="tunnel", is_up=False),
        ])
        result = check_network_context(snap, t=_t)
        info_msgs = [f.message for f in result.findings if f.level.value == "info"]
        assert not any("tun0" in m for m in info_msgs)


# ---------------------------------------------------------------------------
# Sensitive remote port detection
# ---------------------------------------------------------------------------

class TestSensitiveRemotePort:
    def test_warn_on_external_db_connection(self):
        snap = make_snapshot(connections=[
            make_conn(remote_addr="1.2.3.4", remote_port=3306),  # MySQL
        ])
        result = check_network_context(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_on_external_db_connection(self):
        snap = make_snapshot(connections=[
            make_conn(remote_addr="1.2.3.4", remote_port=5432),  # PostgreSQL
        ])
        result = check_network_context(snap, t=_t)
        assert total_deductions(result) >= 2

    def test_no_warn_on_private_db_connection(self):
        """Connection to private IP on sensitive port is not flagged."""
        snap = make_snapshot(connections=[
            make_conn(remote_addr="192.168.1.100", remote_port=3306),
        ])
        result = check_network_context(snap, t=_t)
        assert not has_level(result, "warn")

    def test_no_warn_on_public_normal_port(self):
        snap = make_snapshot(connections=[
            make_conn(remote_addr="8.8.8.8", remote_port=443),
        ])
        result = check_network_context(snap, t=_t)
        assert not has_level(result, "warn")


# ---------------------------------------------------------------------------
# _interface_type
# ---------------------------------------------------------------------------

class TestInterfaceType:
    def test_loopback(self):
        assert _interface_type("lo") == "loopback"

    def test_ethernet_enp(self):
        assert _interface_type("enp3s0") == "ethernet"

    def test_ethernet_eth(self):
        assert _interface_type("eth0") == "ethernet"

    def test_ethernet_ens(self):
        assert _interface_type("ens33") == "ethernet"

    def test_wifi_wlan(self):
        assert _interface_type("wlan0") == "wifi"

    def test_wifi_wlp(self):
        assert _interface_type("wlp2s0") == "wifi"

    def test_libvirt_bridge(self):
        assert _interface_type("virbr0") == "bridge"

    def test_docker_bridge(self):
        assert _interface_type("docker0") == "bridge"

    def test_br_prefix(self):
        assert _interface_type("br-abc123") == "bridge"

    def test_tun_tunnel(self):
        assert _interface_type("tun0") == "tunnel"

    def test_tap_tunnel(self):
        assert _interface_type("tap0") == "tunnel"

    def test_veth_virtual(self):
        assert _interface_type("veth0abc") == "virtual"

    def test_br0_bridge(self):
        assert _interface_type("br0") == "bridge"

    def test_br1_bridge(self):
        assert _interface_type("br1") == "bridge"


# ---------------------------------------------------------------------------
# _parse_interfaces
# ---------------------------------------------------------------------------

class TestParseInterfaces:
    IP_OUTPUT = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP\n"
        "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
        "    inet 192.168.1.42/24 brd 192.168.1.255 scope global dynamic enp3s0\n"
        "3: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN\n"
        "    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0\n"
    )

    def test_loopback_excluded(self):
        ifaces = _parse_interfaces(self.IP_OUTPUT)
        assert not any(i.name == "lo" for i in ifaces)

    def test_ethernet_included(self):
        ifaces = _parse_interfaces(self.IP_OUTPUT)
        assert any(i.name == "enp3s0" for i in ifaces)

    def test_bridge_included(self):
        ifaces = _parse_interfaces(self.IP_OUTPUT)
        assert any(i.name == "virbr0" for i in ifaces)

    def test_ip_address_parsed(self):
        ifaces = _parse_interfaces(self.IP_OUTPUT)
        eth = next(i for i in ifaces if i.name == "enp3s0")
        assert eth.address == "192.168.1.42/24"

    def test_up_status(self):
        ifaces = _parse_interfaces(self.IP_OUTPUT)
        eth = next(i for i in ifaces if i.name == "enp3s0")
        assert eth.is_up

    def test_down_status(self):
        ifaces = _parse_interfaces(self.IP_OUTPUT)
        br = next(i for i in ifaces if i.name == "virbr0")
        assert not br.is_up

    def test_empty_string_returns_empty(self):
        assert _parse_interfaces("") == []


# ---------------------------------------------------------------------------
# _parse_connections
# ---------------------------------------------------------------------------

class TestParseConnections:
    SS_OUTPUT = (
        "State    Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n"
        "ESTAB    0      0      192.168.1.42:35824  142.250.74.14:443  "
        'users:(("chrome",pid=2109,fd=45))\n'
        "ESTAB    0      0      192.168.1.42:51200  93.184.216.34:80\n"
    )

    def test_two_connections_parsed(self):
        conns = _parse_connections(self.SS_OUTPUT)
        assert len(conns) == 2

    def test_remote_addr_parsed(self):
        conns = _parse_connections(self.SS_OUTPUT)
        assert conns[0].remote_addr == "142.250.74.14"

    def test_remote_port_parsed(self):
        conns = _parse_connections(self.SS_OUTPUT)
        assert conns[0].remote_port == 443

    def test_process_extracted(self):
        conns = _parse_connections(self.SS_OUTPUT)
        assert conns[0].process == "chrome"

    def test_no_process_is_empty_string(self):
        conns = _parse_connections(self.SS_OUTPUT)
        assert conns[1].process == ""

    def test_empty_string_returns_empty(self):
        assert _parse_connections("") == []

    def test_header_only_returns_empty(self):
        assert _parse_connections("State    Recv-Q Send-Q Local Address:Port\n") == []


# ---------------------------------------------------------------------------
# _split_addr_port
# ---------------------------------------------------------------------------

class TestSplitAddrPort:
    def test_standard(self):
        assert _split_addr_port("192.168.1.42:443") == ("192.168.1.42", 443)

    def test_no_colon(self):
        addr, port = _split_addr_port("nocolon")
        assert addr == "" and port == 0

    def test_invalid_port(self):
        addr, port = _split_addr_port("192.168.1.1:abc")
        assert addr == "" and port == 0


# ---------------------------------------------------------------------------
# _is_private_or_loopback
# ---------------------------------------------------------------------------

class TestIsPrivateOrLoopback:
    def test_loopback_127(self):
        assert _is_private_or_loopback("127.0.0.1")

    def test_private_10(self):
        assert _is_private_or_loopback("10.0.0.1")

    def test_private_172_16(self):
        assert _is_private_or_loopback("172.16.0.1")

    def test_private_172_31(self):
        assert _is_private_or_loopback("172.31.255.255")

    def test_not_private_172_15(self):
        assert not _is_private_or_loopback("172.15.0.1")

    def test_private_192_168(self):
        assert _is_private_or_loopback("192.168.1.1")

    def test_public(self):
        assert not _is_private_or_loopback("8.8.8.8")

    def test_public_142(self):
        assert not _is_private_or_loopback("142.250.74.14")


# ---------------------------------------------------------------------------
# top_remote_ips
# ---------------------------------------------------------------------------

class TestTopRemoteIps:
    def test_returns_top_n(self):
        conns = [
            make_conn(remote_addr="1.2.3.4"),
            make_conn(remote_addr="1.2.3.4"),
            make_conn(remote_addr="5.6.7.8"),
        ]
        top = top_remote_ips(conns, n=2)
        assert top[0] == ("1.2.3.4", 2)

    def test_excludes_private_ips(self):
        conns = [
            make_conn(remote_addr="192.168.1.100"),
            make_conn(remote_addr="8.8.8.8"),
        ]
        top = top_remote_ips(conns, n=3)
        ips = [ip for ip, _ in top]
        assert "192.168.1.100" not in ips
        assert "8.8.8.8" in ips

    def test_empty_connections(self):
        assert top_remote_ips([], n=3) == []
