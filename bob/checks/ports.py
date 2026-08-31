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
from pathlib import Path
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
    """
    ports:     list[ListeningPort]
    ufw_rules: str
    ss_output: str
    ufw_apps:  "dict[str, list[str]]" = field(default_factory=dict)

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

        return cls(ports=ports, ufw_rules=ufw_rules, ss_output=ss_output,
                   ufw_apps=_read_ufw_app_profiles())

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


_UFW_NUMBERED_RE = re.compile(r"^\s*\[\s*\d+\]\s*(.*)$")
# The Action column, which terminates the "To" column.
_UFW_ACTION_RE   = re.compile(r"\s(ALLOW|DENY|REJECT|LIMIT)\b", re.IGNORECASE)
# A port specification: digits, with ranges (6000:6007) and lists (80,443),
# and an optional protocol. This is exactly what ufw stores in `dport`.
_UFW_PORTSPEC_RE = re.compile(r"^([\d,:]+)(?:/(tcp|udp))?$", re.IGNORECASE)

_UFW_APPS_DIR = Path("/etc/ufw/applications.d")


def _read_ufw_app_profiles(directory: "Path | None" = None) -> "dict[str, list[str]]":
    """Map each UFW application profile name to its port specifications.

    A profile file holds one or more ``[Name]`` sections with a ``ports=``
    line; ufw splits that value on ``|``, so Samba's
    ``137,138/udp|139,445/tcp`` is two specifications. Names may contain
    spaces ("Postfix Submission").

    I/O only — called from ``from_system``, never from the check.
    """
    apps: dict[str, list[str]] = {}
    base = directory if directory is not None else _UFW_APPS_DIR
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return apps
    for path in entries:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name: str | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                name = stripped[1:-1].strip()
            elif name and stripped.lower().startswith("ports="):
                apps[name] = [p for p in stripped.split("=", 1)[1].split("|") if p]
    return apps


def _expand_port_spec(spec: str) -> "list[tuple[int, int, str | None]]":
    """Expand one ufw port specification into (low, high, proto) ranges.

    ``22/tcp`` -> [(22, 22, "tcp")]
    ``6000:6007/tcp`` -> [(6000, 6007, "tcp")]
    ``80,443/tcp`` -> [(80, 80, "tcp"), (443, 443, "tcp")]
    ``631`` -> [(631, 631, None)] — no protocol means any protocol.

    Ranges are kept as ranges rather than expanded: a rule may legitimately
    span the whole ephemeral range, and membership is a comparison.
    """
    m = _UFW_PORTSPEC_RE.match(spec.strip())
    if not m:
        return []
    proto = m.group(2).lower() if m.group(2) else None
    out: list[tuple[int, int, str | None]] = []
    for part in m.group(1).split(","):
        if not part:
            continue
        lo_s, _, hi_s = part.partition(":")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
        except ValueError:
            continue
        if lo > hi:
            lo, hi = hi, lo
        out.append((lo, hi, proto))
    return out


def _parse_ufw_covered_ports(
    ufw_rules: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> "list[tuple[int, int, str | None]]":
    """Parse ``ufw status numbered`` into (low, high, proto) coverage ranges.

    Three forms had to be handled that the previous single regex did not, all
    of them ordinary rather than exotic:

    * **Application profiles.** In non-verbose mode ufw prints the profile
      *name* in the To column and no port at all, so ``ufw allow OpenSSH`` —
      the way Ubuntu's own documentation tells you to open SSH — left port 22
      looking uncovered. Resolved through ``app_profiles``.
    * **Ranges.** ``6000:6007/tcp`` matched only its first number, so 6001-6007
      read as uncovered while 6000/**udp** read as covered.
    * **Lists.** ``80,443/tcp`` behaved the same way: 443 uncovered, 80/udp
      covered.

    Anchored on the rule number so a port appearing later on the line — inside
    a source address such as ``192.168.1.22`` — is not mistaken for the target.
    """
    covered: list[tuple[int, int, str | None]] = []
    apps = app_profiles or {}
    for line in ufw_rules.splitlines():
        m = _UFW_NUMBERED_RE.match(line)
        if not m:
            continue
        rest = m.group(1)
        action = _UFW_ACTION_RE.search(rest)
        to_col = (rest[:action.start()] if action else rest).strip()
        # "(v6)" duplicates an existing rule; " on eth0" scopes it to an
        # interface, which this check does not model either way.
        to_col = to_col.replace("(v6)", "").strip()
        to_col = re.sub(r"\s+on\s+\S+$", "", to_col).strip()
        if not to_col:
            continue

        specs = [to_col]
        if not _UFW_PORTSPEC_RE.match(to_col):
            specs = apps.get(to_col, [])
        for spec in specs:
            covered.extend(_expand_port_spec(spec))
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
    want = proto.lower()
    # A rule with an explicit proto covers only that proto; a rule without one
    # covers any proto.
    return any(lo <= port <= hi and (rule_proto is None or rule_proto == want)
               for lo, hi, rule_proto in covered)


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
    # IPv6 bracket notation: [addr]:port, with an optional %scope inside the
    # brackets. The scope was previously left glued to the address and `iface`
    # returned empty — so the IPv4 branch honoured this docstring and the IPv6
    # branch quietly did not, and a JSON consumer read "fe80::1%eth0" as the
    # address. No verdict moved (a scoped address never matched
    # `_ALL_INTERFACES` anyway), which is why it survived.
    ipv6_match = re.match(r"^\[([^\]]+)\]:(\d+)$", local_addr)
    if ipv6_match:
        addr = ipv6_match.group(1)
        iface = ""
        if "%" in addr:
            addr, _, iface = addr.partition("%")
        return addr, ipv6_match.group(2), iface

    # Wildcard notation: *:port (some ss versions)
    wild_match = re.match(r"^\*:(\d+)$", local_addr)
    if wild_match:
        return "*", wild_match.group(1), ""

    # IPv4 with optional %iface: addr%iface:port or addr:port
    ipv4_match = re.match(r"^([^:%]+)(?:%([^:]+))?:(\d+)$", local_addr)
    if ipv4_match:
        return ipv4_match.group(1), ipv4_match.group(3), ipv4_match.group(2) or ""

    return None, None, ""


