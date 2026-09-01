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
from dataclasses import dataclass, field
from enum import Enum

from bob.checks import _ufw
from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    _run,
    run_result,
    split_ss_address,
)
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
    # M-9 (v0.5.5): process and iface stay empty when `ss -p` lacks
    # privileges or `ss` is unavailable. Callers must treat empty as
    # "unknown", not "no process / no interface scope". is_all_interfaces
    # already accounts for this (only True when iface is empty AND
    # address matches 0.0.0.0/::).
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
        ufw_apps:   Profile name -> port specs, read from
                    /etc/ufw/applications.d. In non-verbose mode — the mode
                    BOB reads — `ufw status numbered` prints the *profile
                    name* in the To column with no port at all, so without
                    this map a host that ran the documented
                    `ufw allow OpenSSH` looked like it had no rule for 22.
                    Collected here rather than in the check because check_xxx
                    is pure by contract.
        ports_readable: False when `ss` could not be run at all (absent on
                    minimal images, or failing). Without it an empty socket
                    list reads as "0 listening ports detected", which states
                    a fact about the host that BOB never established.
    """
    ports:     list[ListeningPort]
    ufw_rules: str
    ss_output: str
    ufw_apps:  "dict[str, list[str]]" = field(default_factory=dict)
    ports_readable: bool = True

    @classmethod
    def from_system(cls) -> "PortsSnapshot":
        """
        Collect listening ports from the live system via ss.

        Returns:
            Populated PortsSnapshot. Never raises.
        """
        ss         = run_result("ss", "-tulnp")
        ufw_rules  = _run("ufw", "status", "numbered")
        ports      = _parse_ss_output(ss.stdout)

        return cls(ports=ports, ufw_rules=ufw_rules, ss_output=ss.stdout,
                   ufw_apps=_read_ufw_app_profiles(),
                   ports_readable=ss.ok)

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

    if not snapshot.ports_readable:
        # `ss` never ran, so the empty port list is BOB's ignorance rather than
        # the host's silence. Evaluating it would turn "I could not look" into
        # "nothing is listening" — the loudest kind of wrong an auditor can be.
        result.info(
            message=_t("ports.unreadable"),
            detail=_t("ports.unreadable_detail"),
            key="ports.unreadable",
        )
        return result

    if audited_ports is None:
        audited_ports = set()

    has_uncovered_public = False
    reported_system_ports: set[str] = set()  # deduplicate system internal ports
    reported_warn_ports:   set[str] = set()  # deduplicate warn/alert ports (multi-address)
    reported_alert_ports:  set[str] = set()  # deduplicate alert ports
    reported_local_ports:  set[str] = set()  # deduplicate local/loopback ports (multi-address)

    # Parse UFW rules once instead of re-scanning the rules string for every
    # listening port (was O(N×M); now O(M) parse + O(N) lookups).
    covered_ports = _parse_ufw_covered_ports(snapshot.ufw_rules, snapshot.ufw_apps)

    for lport in snapshot.ports:
        pp = lport.port_proto

        # Skip ports already handled by services check
        if pp in audited_ports:
            continue

        category = _categorize_port(lport, covered_ports)

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
                key="ports.system_port",
            )
            continue

        if category == PortCategory.NETBIOS:
            if pp in reported_warn_ports:
                continue
            reported_warn_ports.add(pp)
            if not ufw_active:
                result.info(message=_t("ports.uncovered", port=pp), key="ports.uncovered")
                continue
            result.warn_with_deduction(
                key="ports.uncovered_netbios",
                message=_t("ports.uncovered", port=pp),
                reason=_t("deduction.netbios_no_rule", port=pp),
                points=1,
                context=network_context,
                cmd=f"sudo ufw allow from 192.168.1.0/24 to any port {lport.port} proto {lport.proto}",
                nature="action",
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
                result.info(
                    message=_t("ports.uncovered_ufw_inactive", port=pp_info),
                    key="ports.uncovered_ufw_inactive",
                )
                continue
            if default_incoming_policy in ("deny", "reject"):
                pp_info = f"{pp} ({lport.process})" if lport.process else pp
                result.info(
                    message=_t("ports.uncovered_default_deny", port=pp_info),
                    key="ports.uncovered_default_deny",
                )
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
                    key="ports.uncovered",
                )
            else:
                result.alert(
                    message=_t("ports.uncovered", port=pp_display),
                    nature="action",
                    cmd=f"sudo ufw deny {pp}",
                    key="ports.uncovered",
                )
            result.add_deduction(
                reason=_t("deduction.port_no_rule", port=pp),
                points=2 if network_context in ("public", "ddns") else 1,
                context=network_context,
                key="ports.uncovered",
            )

        elif category == PortCategory.UNCOVERED_LOCAL:
            if pp in reported_local_ports:
                continue
            reported_local_ports.add(pp)
            result.info(
                message=_t("ports.uncovered_local", port=pp),
                key="ports.uncovered_local",
            )

    if not has_uncovered_public and ufw_active:
        result.ok(message=_t("ports.all_covered"), key="ports.all_covered")

    return result


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _categorize_port(
    lport: ListeningPort,
    ufw_rules: str | set[tuple[int, str | None]],
) -> PortCategory:
    """Classify a single listening port.

    ``ufw_rules`` may be the raw ``ufw status`` text (back-compat) or a
    pre-parsed set from :func:`_parse_ufw_covered_ports` (preferred for loops
    over many ports against the same ruleset).
    """

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


# The ufw rule grammar lives in bob/checks/_ufw.py, shared with `services`,
# which had its own matcher and got it wrong: it searched the whole line, so a
# rule "80/tcp ALLOW IN 192.168.1.22" made ports 1, 22, 168 and 192 all look
# covered.
_UFW_APPS_DIR = _ufw._APPS_DIR


def _read_ufw_app_profiles(directory=None):
    """See :func:`bob.checks._ufw.read_app_profiles`. I/O only."""
    return _ufw.read_app_profiles(directory)


def _expand_port_spec(spec: str):
    """See :func:`bob.checks._ufw.expand_port_spec`."""
    return _ufw.expand_port_spec(spec)


def _parse_ufw_covered_ports(
    ufw_rules: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> "list[tuple[int, int, str | None]]":
    """Parse ``ufw status numbered`` into (low, high, proto) coverage ranges.

    Application profiles, ranges and lists are all resolved — see the module
    docstring of ``bob.checks._ufw`` for what each of them used to break.
    """
    covered: list[tuple[int, int, str | None]] = []
    for line in ufw_rules.splitlines():
        rule = _ufw.parse_rule(line)
        if rule is None or not rule.to_col:
            continue
        covered.extend(_ufw.to_column_ranges(rule.to_col, app_profiles))
    return covered


def _is_covered_by_ufw(
    port: int,
    proto: str,
    ufw_rules: "str | list[tuple[int, int, str | None]]",
) -> bool:
    """Return True if a UFW rule covers this port/proto.

    Accepts either the raw ``ufw status`` text or the pre-parsed ranges from
    :func:`_parse_ufw_covered_ports`. Parsing once and querying many ports
    against the result is still the point; the lookup is a comparison against
    a handful of rules rather than a set membership, because a rule may cover
    a range and a range cannot be a set key without expanding it.
    """
    if isinstance(ufw_rules, str):
        covered = _parse_ufw_covered_ports(ufw_rules)
    else:
        covered = ufw_rules
    return _ufw.ranges_cover(covered, port, proto)


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


def _split_addr_port(local_addr: str) -> "tuple[str | None, str | None, str]":
    """Thin alias over the shared ``ss`` address grammar.

    Kept as a module-level name because tests monkeypatch it here.
    """
    return split_ss_address(local_addr)


