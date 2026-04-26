"""
Network context check for BOB (sections C + E).

Collects and audits:
  E — Network interfaces: name, type, status, IPv4 address
  C — Established TCP connections: count, top remote IPs

The check is split into two parts:
  1. NetworkContextSnapshot.from_system() — collects raw data via subprocess.
  2. check_network_context(snapshot)      — pure logic, returns a CheckResult.

Usage:
    from bob.checks.network_context import (
        NetworkContextSnapshot, check_network_context,
    )
    snapshot = NetworkContextSnapshot.from_system()
    result   = check_network_context(snapshot)
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from bob.checks._run import _identity_t, _run
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InterfaceInfo:
    """
    Single network interface snapshot.

    Args:
        name:     Interface name (e.g. "enp3s0", "virbr0", "tun0").
        if_type:  Categorised type string (see _interface_type()).
        is_up:    True if the interface has the UP flag.
        address:  Primary IPv4 CIDR address, or "" if none assigned.
    """
    name:    str
    if_type: str
    is_up:   bool
    address: str


@dataclass
class ConnectionInfo:
    """
    Single established TCP connection.

    Args:
        local_addr:  Local IP address string.
        local_port:  Local port number.
        remote_addr: Remote IP address string.
        remote_port: Remote port number.
        process:     Process name extracted from ss output, or "".
    """
    local_addr:  str
    local_port:  int
    remote_addr: str
    remote_port: int
    process:     str


@dataclass
class NetworkContextSnapshot:
    """
    Raw snapshot of network interfaces and established connections.

    Args:
        interfaces:  All non-loopback, non-veth interfaces found on the system.
        connections: All currently established TCP connections.
    """
    interfaces:  list[InterfaceInfo] = field(default_factory=list)
    connections: list[ConnectionInfo] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "NetworkContextSnapshot":
        """
        Collect network context from the live system via subprocess.

        Returns:
            Populated NetworkContextSnapshot. Never raises.
        """
        iface_output = _run("ip", "-4", "addr", "show")
        interfaces   = _parse_interfaces(iface_output)

        conn_output = _run("ss", "-tnp", "state", "established")
        connections = _parse_connections(conn_output)

        return cls(interfaces=interfaces, connections=connections)


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

# Ports that are inherently local — an established outbound connection on these
# remote ports is unusual and worth noting.
_SENSITIVE_REMOTE_PORTS = {3306, 5432, 6379, 27017, 5984}  # MySQL, PG, Redis, Mongo, CouchDB


def check_network_context(snapshot: NetworkContextSnapshot, t=None) -> CheckResult:
    """
    Audit the network context snapshot and return findings.

    Scoring philosophy: this section is informational — interfaces and
    ordinary connections carry no deductions. Only genuinely suspicious
    patterns (unknown tunnel interface, DB connection to external IP) produce
    findings beyond INFO.

    Args:
        snapshot: NetworkContextSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult — findings only (no score deductions for normal context).
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- Interfaces ---
    # Flag active tunnel interfaces — may indicate an unknown VPN
    for iface in snapshot.interfaces:
        if iface.if_type == "tunnel" and iface.is_up:
            result.info(
                message=_t("network_context.tunnel_active", name=iface.name),
            )

    # --- Connections ---
    external = [
        c for c in snapshot.connections
        if not _is_private_or_loopback(c.remote_addr)
    ]

    # Flag established connections to external IPs on sensitive ports
    for conn in external:
        if conn.remote_port in _SENSITIVE_REMOTE_PORTS:
            result.warn(
                message=_t(
                    "network_context.sensitive_remote",
                    addr=conn.remote_addr,
                    port=conn.remote_port,
                ),
                nature="action",
            )
            result.add_deduction(
                reason=_t(
                    "network_context.sensitive_remote",
                    addr=conn.remote_addr,
                    port=conn.remote_port,
                ),
                points=2,
                context="public",
            )

    return result


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------

def _interface_type(name: str) -> str:
    """Categorise a network interface by its name prefix."""
    if name == "lo":
        return "loopback"
    if re.match(r"^(eth|enp|ens|em|eno)\d", name):
        return "ethernet"
    if re.match(r"^(wlan|wlp|wifi)\d", name):
        return "wifi"
    if re.match(r"^(virbr|br\d)", name):
        return "bridge"
    if re.match(r"^(docker|br-)", name):
        return "bridge"
    if re.match(r"^tun\d", name):
        return "tunnel"
    if re.match(r"^tap\d", name):
        return "tunnel"
    if re.match(r"^veth", name):
        return "virtual"
    return "other"


def _parse_interfaces(ip_output: str) -> list[InterfaceInfo]:
    """
    Parse `ip -4 addr show` output into a list of InterfaceInfo.

    Skips loopback and veth interfaces — they add noise without value.
    """
    results: list[InterfaceInfo] = []
    current_name = ""
    current_up   = False
    current_addr = ""

    for line in ip_output.splitlines():
        # Interface header: "2: enp3s0: <BROADCAST,MULTICAST,UP,...> ... state UP ..."
        m_iface = re.match(r"^\d+:\s+(\S+):\s+<[^>]*>", line)
        if m_iface:
            # Flush previous
            if current_name:
                _flush_interface(results, current_name, current_up, current_addr)
            current_name = m_iface.group(1).rstrip("@:").split("@")[0]
            # Use operational state (state UP/DOWN/UNKNOWN) not flag bits —
            # an interface can have the UP flag but state DOWN (NO-CARRIER).
            m_state  = re.search(r"\bstate\s+(\w+)", line)
            op_state = m_state.group(1).upper() if m_state else "UNKNOWN"
            current_up   = op_state in ("UP", "UNKNOWN")
            current_addr = ""
            continue

        # IPv4 address line: "    inet 192.168.1.x/24 brd ..."
        m_addr = re.match(r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if m_addr and current_name:
            current_addr = m_addr.group(1)

    # Flush last
    if current_name:
        _flush_interface(results, current_name, current_up, current_addr)

    return results


def _flush_interface(
    results: list[InterfaceInfo],
    name: str,
    is_up: bool,
    address: str,
) -> None:
    """Append an InterfaceInfo, skipping loopback and veth."""
    if_type = _interface_type(name)
    if if_type in ("loopback", "virtual"):
        return
    results.append(InterfaceInfo(
        name=name, if_type=if_type, is_up=is_up, address=address,
    ))


def _parse_connections(ss_output: str) -> list[ConnectionInfo]:
    """
    Parse `ss -tnp state established` output into ConnectionInfo list.

    Expected format (with or without process column):
        ESTAB  0  0  192.168.1.42:52345  142.250.74.14:443  users:(("chrome",...))
    The header line is skipped.
    """
    results: list[ConnectionInfo] = []
    for line in ss_output.splitlines():
        # Skip header
        if line.startswith("State") or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        # parts[0]=State/Netid, parts[1]=Recv-Q, parts[2]=Send-Q,
        # parts[3]=Local, parts[4]=Peer, parts[5]=Process (optional)
        local_raw = parts[3]
        peer_raw  = parts[4]
        process   = _extract_process(parts[5] if len(parts) > 5 else "")

        local_addr, local_port = _split_addr_port(local_raw)
        remote_addr, remote_port = _split_addr_port(peer_raw)

        if local_addr and remote_addr:
            results.append(ConnectionInfo(
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                process=process,
            ))
    return results


def _split_addr_port(raw: str) -> tuple[str, int]:
    """Split "addr:port" into (addr, port). Returns ("", 0) on failure."""
    try:
        idx  = raw.rfind(":")
        if idx < 0:
            return "", 0
        return raw[:idx], int(raw[idx + 1:])
    except (ValueError, IndexError):
        return "", 0


def _extract_process(raw: str) -> str:
    """Extract process name from ss users field like users:(("chrome",pid=...,fd=...))."""
    m = re.search(r'users:\(\("([^"]+)"', raw)
    return m.group(1) if m else ""


def _is_private_or_loopback(addr: str) -> bool:
    """Return True if addr is a loopback or RFC-1918 private address."""
    if addr.startswith("127.") or addr == "::1":
        return True
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
    )


# ---------------------------------------------------------------------------
# Summary helper (used by display layer)
# ---------------------------------------------------------------------------

def top_remote_ips(connections: list[ConnectionInfo], n: int = 3) -> list[tuple[str, int]]:
    """Return the top-n remote IPs by connection count, excluding private/loopback."""
    external = [
        c.remote_addr for c in connections
        if not _is_private_or_loopback(c.remote_addr)
    ]
    return Counter(external).most_common(n)
