"""
Listening ports check for BOB.

Analyses all ports currently listening on the system, excluding ports
already audited by checks/services.py, and classifies each one by
its UFW coverage and listen address.

Split into two parts:
  1. PortsSnapshot.from_system() — collects data via subprocess (ss).
  2. check_ports(snapshot, t)    — pure logic, returns a CheckResult.

Usage:
    from bob.checks.ports import PortsSnapshot, check_ports

    audited = {"22/tcp", "80/tcp"}   # already handled by services check
    snapshot = PortsSnapshot.from_system()
    result = check_ports(snapshot, audited_ports=audited, t=t)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from bob.checks._run import TranslationFunc, _identity_t, _run
from bob.scoring import CheckResult

# Ports above this threshold are considered ephemeral (kernel-assigned)
EPHEMERAL_THRESHOLD = 32767

# System-internal ports that are safe to ignore without UFW rules
# Format: (port, proto, description)
_SYSTEM_PORTS: list[tuple[int, str, str]] = [
    (53,  "tcp", "DNS"),
    (53,  "udp", "DNS"),
    (67,  "udp", "DHCP"),
    (68,  "udp", "DHCP"),
    (546, "udp", "DHCPv6"),
    (547, "udp", "DHCPv6"),
    (1900,"udp", "UPnP/SSDP (local discovery)"),
    (5353,"udp", "mDNS"),
    (6666,"udp", "clipboard sync (qlipper/KDE)"),
]

# Processes that legitimately own system-internal ports.
# Empty string = unknown owner; treat as system daemon to avoid false positives.
_SYSTEM_DAEMONS: frozenset[str] = frozenset({
    "", "avahi-daemon", "systemd", "systemd-resolve", "systemd-resolved",
    "systemd-network", "systemd-networkd", "dnsmasq", "named", "unbound",
    "NetworkManager", "dhcpd", "miniupnpd", "upnpd",
})

_LOOPBACK = re.compile(r"^(127\.|::1$)")
_ALL_INTERFACES = re.compile(r"^(0\.0\.0\.0|::|\*)$")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class PortCategory(Enum):
    """Classification of a listening port."""
    EPHEMERAL       = "ephemeral"        # >32767 — kernel-assigned
    SYSTEM_INTERNAL = "system_internal"  # DNS, DHCP, mDNS — OS services
    COVERED         = "covered"          # UFW rule exists
    UNCOVERED_PUBLIC  = "uncovered_public"   # 0.0.0.0 without UFW rule
    UNCOVERED_LOCAL   = "uncovered_local"    # loopback/LAN — lower risk
    NETBIOS         = "netbios"          # Samba NetBIOS ports (137/138)


@dataclass
class ListeningPort:
    """
    A single port currently listening on the system.

    Args:
        port:     Port number.
        proto:    Protocol string: "tcp" or "udp".
        address:  Listen address (e.g. "0.0.0.0", "127.0.0.1", "::").
        raw_line: Raw line from `ss` output for the report.
    """
    port:     int
    proto:    str
    address:  str
    raw_line: str
    process:  str = ""
    iface:    str = ""   # non-empty when bound to a specific interface (e.g. "virbr0")

    @property
    def port_proto(self) -> str:
        """Return "port/proto" string e.g. "22/tcp"."""
        return f"{self.port}/{self.proto}"

    @property
    def is_all_interfaces(self) -> bool:
        """True if listening on all interfaces (0.0.0.0 or ::), not interface-scoped."""
        return bool(_ALL_INTERFACES.match(self.address)) and not self.iface

    @property
    def is_loopback(self) -> bool:
        """True if listening on loopback only."""
        return bool(_LOOPBACK.match(self.address))


@dataclass
class PortsSnapshot:
    """
    Raw snapshot of all listening ports collected from the system.

    Args:
        ports:      List of all listening ports parsed from ss output.
        ufw_rules:  Output of `ufw status numbered` for exposure classification.
        ss_output:  Full ss output for the report.
    """
    ports:     list[ListeningPort]
    ufw_rules: str
    ss_output: str

    @classmethod
    def from_system(cls) -> "PortsSnapshot":
        """
        Collect listening ports from the live system via ss.

        Returns:
            Populated PortsSnapshot. Never raises.
        """
        ss_output  = _run("ss", "-tulnp")
        ufw_rules  = _run("ufw", "status", "numbered")
        ports      = _parse_ss_output(ss_output)

        return cls(ports=ports, ufw_rules=ufw_rules, ss_output=ss_output)

    @property
    def loopback_only_ports(self) -> set[str]:
        """Set of 'port/proto' strings where ALL bindings are loopback."""
        bindings: dict[str, list[ListeningPort]] = defaultdict(list)
        for lp in self.ports:
            bindings[lp.port_proto].append(lp)
        return {pp for pp, lps in bindings.items() if all(lp.is_loopback for lp in lps)}

    @property
    def active_external_ports(self) -> set[str]:
        """Set of 'port/proto' strings with at least one non-loopback binding."""
        return {lp.port_proto for lp in self.ports if not lp.is_loopback}


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_ports(
    snapshot: PortsSnapshot,
    audited_ports: set[str] | None = None,
    network_context: str = "local",
    default_incoming_policy: str = "deny",
    ufw_active: bool = True,
    t: TranslationFunc | None = None,
) -> CheckResult:
    """
    Evaluate listening ports and return findings.

    Args:
        snapshot:                PortsSnapshot from the system.
        audited_ports:           Set of "port/proto" strings already handled by
                                 the services check. These are skipped here.
        network_context:         "local" or "public".
        default_incoming_policy: UFW default incoming policy ("deny", "allow",
                                 "reject", "unknown"). When "deny" or "reject",
                                 ports without an explicit rule are already
                                 blocked — findings are downgraded to INFO.
        t:                       Translation function.

    Returns:
        CheckResult with port findings.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if audited_ports is None:
        audited_ports = set()

    has_uncovered_public = False
    reported_system_ports: set[str] = set()  # deduplicate system internal ports
    reported_warn_ports:   set[str] = set()  # deduplicate warn/alert ports (multi-address)
    reported_alert_ports:  set[str] = set()  # deduplicate alert ports
    reported_local_ports:  set[str] = set()  # deduplicate local/loopback ports (multi-address)

    for lport in snapshot.ports:
        pp = lport.port_proto

        # Skip ports already handled by services check
        if pp in audited_ports:
            continue

        category = _categorize_port(lport, snapshot.ufw_rules)

        if category == PortCategory.EPHEMERAL:
            continue  # silently ignored — kernel-assigned, no security relevance

        if category == PortCategory.SYSTEM_INTERNAL:
            # Deduplicate — same port/proto may appear on multiple loopback addresses
            if pp in reported_system_ports:
                continue
            reported_system_ports.add(pp)
            svc_name = _system_port_name(lport.port, lport.proto)
            result.info(
                message=_t("ports.system_port",
                           port=pp,
                           service=svc_name),
            )
            continue

        if category == PortCategory.NETBIOS:
            if pp in reported_warn_ports:
                continue
            reported_warn_ports.add(pp)
            if not ufw_active:
                result.info(message=_t("ports.uncovered", port=pp))
                continue
            result.warn(
                message=_t("ports.uncovered", port=pp),
                nature="improvement",
                cmd=f"sudo ufw allow from 192.168.1.0/24 to any port {lport.port} proto {lport.proto}",
            )
            result.add_deduction(
                reason=_t("deduction.netbios_no_rule", port=pp),
                points=1,
                context=network_context,
            )
            continue

        if category == PortCategory.COVERED:
            # Already covered by a rule — no finding needed (services handles this)
            continue

        if category == PortCategory.UNCOVERED_PUBLIC:
            if pp in reported_alert_ports:
                continue
            reported_alert_ports.add(pp)

            # Downgrade to INFO when there is nothing actionable to show.
            if not ufw_active:
                pp_info = f"{pp} ({lport.process})" if lport.process else pp
                result.info(message=_t("ports.uncovered_ufw_inactive", port=pp_info))
                continue
            if default_incoming_policy in ("deny", "reject"):
                pp_info = f"{pp} ({lport.process})" if lport.process else pp
                result.info(message=_t("ports.uncovered_default_deny", port=pp_info))
                continue

            has_uncovered_public = True
            pp_display = f"{pp} ({lport.process})" if lport.process else pp
            note = _t("ports.process_disclaimer", process=lport.process) if lport.process else ""
            if lport.process:
                result.warn(
                    message=_t("ports.uncovered", port=pp_display),
                    nature="improvement",
                    cmd=f"sudo ufw deny {pp}",
                    note=note,
                )
            else:
                result.alert(
                    message=_t("ports.uncovered", port=pp_display),
                    nature="action",
                    cmd=f"sudo ufw deny {pp}",
                )
            result.add_deduction(
                reason=_t("deduction.port_no_rule", port=pp),
                points=2 if network_context in ("public", "ddns") else 1,
                context=network_context,
            )

        elif category == PortCategory.UNCOVERED_LOCAL:
            if pp in reported_local_ports:
                continue
            reported_local_ports.add(pp)
            result.info(
                message=_t("ports.uncovered_local", port=pp),
            )

    if not has_uncovered_public and ufw_active:
        result.ok(message=_t("ports.all_covered"))

    return result


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _categorize_port(lport: ListeningPort, ufw_rules: str) -> PortCategory:
    """Classify a single listening port."""

    # Ephemeral — only applies to UDP; TCP sockets in ss -l are always LISTEN (server sockets)
    if lport.proto == "udp" and lport.port > EPHEMERAL_THRESHOLD:
        return PortCategory.EPHEMERAL

    # System internal — only when the owning process is a known system daemon.
    # User-space apps (e.g. Spotify on 1900/udp) fall through to normal checks.
    for sys_port, sys_proto, _ in _SYSTEM_PORTS:
        if lport.port == sys_port and lport.proto == sys_proto:
            if lport.process in _SYSTEM_DAEMONS:
                return PortCategory.SYSTEM_INTERNAL
            break  # same port, user-space owner — fall through

    # Check UFW coverage first — applies to all ports including NetBIOS
    if _is_covered_by_ufw(lport.port, lport.proto, ufw_rules):
        return PortCategory.COVERED

    # NetBIOS (Samba) — not covered by UFW, suggest LAN-scoped rule
    if lport.port in (137, 138) and lport.proto == "udp":
        return PortCategory.NETBIOS

    # Uncovered — distinguish public vs local
    if lport.is_all_interfaces:
        return PortCategory.UNCOVERED_PUBLIC

    return PortCategory.UNCOVERED_LOCAL


def _is_covered_by_ufw(port: int, proto: str, ufw_rules: str) -> bool:
    """Return True if a UFW rule covers this port/proto."""
    pattern = re.compile(
        r"\[\s*\d+\]\s+.*\b" + re.escape(str(port)) +
        r"(?:/" + re.escape(proto) + r")?\b",
        re.IGNORECASE,
    )
    for line in ufw_rules.splitlines():
        if re.match(r"\s*\[\s*\d+\]", line) and pattern.search(line):
            return True
    return False


def _system_port_name(port: int, proto: str) -> str:
    """Return human-readable name for a known system port."""
    for sys_port, sys_proto, name in _SYSTEM_PORTS:
        if port == sys_port and proto == sys_proto:
            return name
    return f"{port}/{proto}"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_ss_output(output: str) -> list[ListeningPort]:
    """
    Parse the output of `ss -tuln` into ListeningPort objects.

    Expected format (abbreviated):
        udp   UNCONN 0  0  0.0.0.0:5353  0.0.0.0:*
        tcp   LISTEN 0  0  0.0.0.0:22    0.0.0.0:*

    Returns:
        List of ListeningPort objects. Lines that cannot be parsed are skipped.
    """
    ports: list[ListeningPort] = []
    seen: set[tuple] = set()

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto_raw = parts[0].lower()
        if proto_raw not in ("tcp", "udp"):
            continue

        # Local address is the 5th field (index 4): "address:port"
        local_addr = parts[4]
        if not local_addr or local_addr == "Local":
            continue

        # Split address:port — handle IPv6 [::]:port and addr%iface:port
        addr, port_str, iface = _split_addr_port(local_addr)
        if addr is None or port_str is None:
            continue

        try:
            port_num = int(port_str)
        except ValueError:
            continue

        # Deduplicate — same port/proto/address may appear multiple times
        key = (port_num, proto_raw, addr)
        if key in seen:
            continue
        seen.add(key)

        # Extract process name from users:(("name",...)) column if present
        process = ""
        if len(parts) >= 7:
            m = re.search(r'users:\(\("([^"]+)"', parts[6])
            if m:
                process = m.group(1)

        ports.append(ListeningPort(
            port=port_num,
            proto=proto_raw,
            address=addr,
            raw_line=line,
            process=process,
            iface=iface,
        ))

    return ports


def _split_addr_port(local_addr: str) -> tuple[str | None, str | None, str]:
    """
    Split a local address string into (address, port, iface).

    iface is non-empty when the address is scoped to a specific interface
    (e.g. "0.0.0.0%virbr0:67" → ("0.0.0.0", "67", "virbr0")).

    Handles:
      - "0.0.0.0:22"
      - "0.0.0.0%virbr0:67"
      - "127.0.0.53%lo:53"
      - "[::]:22"
      - "[::1]:631"
      - "192.168.1.255:137"
    """
    # IPv6 bracket notation: [addr]:port
    ipv6_match = re.match(r"^\[([^\]]+)\]:(\d+)$", local_addr)
    if ipv6_match:
        return ipv6_match.group(1), ipv6_match.group(2), ""

    # Wildcard notation: *:port (some ss versions)
    wild_match = re.match(r"^\*:(\d+)$", local_addr)
    if wild_match:
        return "*", wild_match.group(1), ""

    # IPv4 with optional %iface: addr%iface:port or addr:port
    ipv4_match = re.match(r"^([^:%]+)(?:%([^:]+))?:(\d+)$", local_addr)
    if ipv4_match:
        return ipv4_match.group(1), ipv4_match.group(3), ipv4_match.group(2) or ""

    return None, None, ""


