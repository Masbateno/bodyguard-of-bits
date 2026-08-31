"""
DDNS / external exposure check for BOB.

Detects active DDNS clients (ddclient, inadyn, No-IP DUC, DuckDNS),
extracts the configured domain, and crosses with unrestricted UFW ALLOW
rules to identify ports potentially exposed to the internet.

Score: -1 global if DDNS active + open ports (not per port).

Split into two parts:
  1. DdnsSnapshot.from_system() — detects DDNS clients on the live system.
  2. check_ddns(snapshot, t)    — pure logic, returns a CheckResult.

Usage:
    from bob.checks.ddns import DdnsSnapshot, check_ddns

    snapshot = DdnsSnapshot.from_system()
    result = check_ddns(snapshot, ufw_rules=rules, t=t)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks import _ufw
from bob.checks._run import _identity_t, _is_safe_config_path, _run, is_unit_active
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# DDNS client registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DdnsClientDef:
    """
    Definition of a known DDNS client.

    Args:
        name:         Human-readable client name.
        packages:     dpkg package names.
        services:     systemd service names.
        config_files: Config file paths to search for the domain.
        client_type:  Internal identifier for domain extraction logic.
    """
    name:         str
    packages:     tuple[str, ...]
    services:     tuple[str, ...]
    config_files: tuple[str, ...]
    client_type:  str

_DDNS_CLIENTS: list[DdnsClientDef] = [
    DdnsClientDef(
        name="ddclient",
        packages=("ddclient",),
        services=("ddclient",),
        config_files=("/etc/ddclient.conf",),
        client_type="ddclient",
    ),
    DdnsClientDef(
        name="inadyn",
        packages=("inadyn",),
        services=("inadyn",),
        config_files=("/etc/inadyn.conf", "/etc/inadyn/inadyn.conf"),
        client_type="inadyn",
    ),
    DdnsClientDef(
        name="No-IP DUC",
        packages=("noip2",),
        services=("noip2",),
        config_files=("/etc/no-ip2.conf",),
        client_type="noip",
    ),
    DdnsClientDef(
        name="DuckDNS (script)",
        packages=(),
        services=(),
        config_files=("/etc/cron.d/duckdns", "/root/duckdns/duck.sh"),
        client_type="duckdns",
    ),
]

# Private IP ranges — these source restrictions make a rule "local only"
_PRIVATE_SOURCE = re.compile(
    r"(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)"
)

# System-internal ports that should not be reported as DDNS-exposed
# (same spirit as ports._SYSTEM_PORTS — DNS runs locally, not a user service)
_DDNS_SYSTEM_PORTS: set[int] = {53, 67, 68, 546, 547, 5353}

# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class DdnsSnapshot:
    """
    DDNS detection result for the live system.

    Args:
        client_name:  Name of the detected DDNS client, or None.
        domain:       Configured domain extracted from config, or None.
        active:       True if the DDNS service is currently running.
        installed:    True if the DDNS client was found on the system.
        ufw_apps:     UFW application-profile name -> port specs, so the open-port
                      scan can resolve a rule written as `ufw allow OpenSSH`.
    """
    client_name: str | None
    domain:      str | None
    active:      bool
    installed:   bool
    ufw_apps:    "dict[str, list[str]]" = field(default_factory=dict)

    @classmethod
    def from_system(cls) -> "DdnsSnapshot":
        """
        Detect DDNS clients on the live system.

        Returns:
            DdnsSnapshot. Never raises.
        """
        for client_def in _DDNS_CLIENTS:
            installed = _is_installed(client_def)
            if not installed:
                continue

            active = _is_active(client_def)
            domain = _extract_domain(client_def)

            return cls(
                client_name=client_def.name,
                domain=domain,
                active=active,
                installed=True,
                ufw_apps=_ufw.read_app_profiles(),
            )

        return cls(client_name=None, domain=None, active=False, installed=False,
                   ufw_apps=_ufw.read_app_profiles())

    @classmethod
    def none(cls) -> "DdnsSnapshot":
        """Return a snapshot representing no DDNS client detected."""
        return cls(client_name=None, domain=None, active=False, installed=False)

    @classmethod
    def detected(
        cls,
        client_name: str,
        domain: str | None = None,
        active: bool = True,
    ) -> "DdnsSnapshot":
        """Factory for building test snapshots."""
        return cls(
            client_name=client_name,
            domain=domain,
            active=active,
            installed=True,
        )

# ---------------------------------------------------------------------------
# Context helper
# ---------------------------------------------------------------------------

def ddns_effective_context(
    snapshot: DdnsSnapshot,
    ufw_rules: str,
    loopback_ports=None,
    active_ports=None,
) -> str:
    """
    Return "ddns" if DDNS is active with at least one open unrestricted port,
    otherwise "local".

    Called before the services check in the runner so that service exposure
    deductions are scored at public-equivalent weight when DDNS is running.
    """
    if not snapshot.active:
        return "local"
    return "ddns" if _find_open_ports(
        ufw_rules, loopback_ports, active_ports, snapshot.ufw_apps
    ) else "local"

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_ddns(
    snapshot: DdnsSnapshot,
    ufw_rules: str = "",
    t=None,
    loopback_ports: set[str] | None = None,
    active_ports: set[str] | None = None,
) -> CheckResult:
    """
    Evaluate DDNS snapshot and return findings.

    Args:
        snapshot:       DdnsSnapshot from the system.
        ufw_rules:      Output of `ufw status numbered` for open port detection.
        t:              Translation function.
        loopback_ports: Set of port strings (e.g. "6379/tcp") bound exclusively
                        to loopback — excluded from the exposed ports list.
        active_ports:   Set of port strings that have at least one non-loopback
                        listener (from ss). Only these are reported as exposed.
                        If None, no filtering by listener state is applied.

    Returns:
        CheckResult with DDNS findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # No DDNS client found
    if not snapshot.installed:
        result.ok(message=_t("ddns.none"), key="ddns.none")
        return result

    # Installed but inactive
    if not snapshot.active:
        result.info(
            message=_t("ddns.inactive", client=snapshot.client_name),
            key="ddns.inactive",
        )
        return result

    # Active DDNS client
    result.warn(
        message=_t("ddns.found", client=snapshot.client_name),
        nature="improvement",
        key="ddns.found",
    )

    if snapshot.domain:
        from bob.output import sanitize as _sanitize
        safe_domain = _sanitize(snapshot.domain, max_len=253)
        result.info(
            message=_t("ddns.domain", domain=safe_domain),
            key="ddns.domain",
        )
    else:
        result.info(message=_t("ddns.no_domain"), key="ddns.no_domain")

    # Find open ports (ALLOW without source restriction, system ports and loopback excluded)
    open_ports = _find_open_ports(
        ufw_rules, loopback_ports=loopback_ports, active_ports=active_ports,
        app_profiles=snapshot.ufw_apps,
    )

    if not open_ports:
        result.ok(message=_t("ddns.no_open_ports"), key="ddns.no_open_ports")
        return result

    # Open ports detected — warn and deduct.
    # The port list is interpolated into the WARN message itself so the reader
    # immediately sees which ports are at risk, instead of seeing them as
    # separate "→ 22/tcp" sub-items under the INFO advice (terrain Mint test,
    # 15-05-2026 — visually confusing).
    ports_str = ", ".join(open_ports)
    result.warn_with_deduction(
        key="ddns.warn",
        message=_t("ddns.warn", ports=ports_str),
        points=1,
        nature="improvement",
    )

    # Expose the ports list for programmatic access (compare.py baseline diff,
    # tests). The user-facing rendering is the WARN message above.
    result.open_ports = open_ports

    # Note Fail2ban advice — port list is already in the WARN above.
    result.info(message=_t("ddns.advice"), key="ddns.advice")

    return result

# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _config_present(path: Path) -> bool:
    """True if ``path`` exists and is a safe (absolute, non-symlink) config file.

    Robust against an unreadable path: both ``Path.exists()`` and
    ``_is_safe_config_path`` (via ``is_symlink()``) call ``stat``/``lstat``,
    which raise ``PermissionError`` when a parent directory is not searchable
    (e.g. a DuckDNS script under a hardened ``/root`` the auditor cannot enter,
    or a user-namespace where root maps to an unprivileged uid). A read-only
    auditor must degrade such a path to "absent" rather than crash the whole
    audit. See the ddns-robustness backlog note.
    """
    try:
        return path.exists() and _is_safe_config_path(path)
    except OSError:
        return False


def _is_installed(client_def: DdnsClientDef) -> bool:
    """Return True if the DDNS client is installed via dpkg or config file."""
    # dpkg check
    for pkg in client_def.packages:
        output = _run("dpkg", "-l", pkg)
        if re.search(r"^ii\s+" + re.escape(pkg), output, re.MULTILINE):
            return True

    # Config file check (for script-based clients like DuckDNS)
    for cfg_path in client_def.config_files:
        if _config_present(Path(cfg_path)):
            return True

    return False

def _is_active(client_def: DdnsClientDef) -> bool:
    """Return True if the DDNS service is currently active."""
    for svc in client_def.services:
        if is_unit_active(svc):
            return True

    # DuckDNS: check cron entry
    if client_def.client_type == "duckdns":
        for cfg_path in client_def.config_files:
            if _config_present(Path(cfg_path)):
                return True

    return False

def _extract_domain(client_def: DdnsClientDef) -> str | None:
    """
    Attempt to extract the configured domain from the client's config file.

    Returns:
        Domain string, or None if not found.
    """
    for cfg_path in client_def.config_files:
        path = Path(cfg_path)
        if not _config_present(path):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        domain = None

        if client_def.client_type == "ddclient":
            domain = _extract_ddclient_domain(content)
        elif client_def.client_type == "inadyn":
            domain = _extract_inadyn_domain(content)
        elif client_def.client_type == "noip":
            domain = _extract_noip_domain(content)
        elif client_def.client_type == "duckdns":
            domain = _extract_duckdns_domain(content)

        if domain:
            return domain

    return None

def _extract_ddclient_domain(content: str) -> str | None:
    """Extract domain from ddclient.conf."""
    # Standard key: hostname = domain.tld
    match = re.search(r"^(?:host|hostname)\s*=\s*(.+)", content, re.MULTILINE)
    if match:
        return match.group(1).strip().strip('"')

    # DuckDNS format: last non-comment line may be the domain
    # e.g. "http://masbateno.duckdns.org" or just "masbateno"
    for line in reversed(content.splitlines()):
        line = line.strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        if any(kw in line for kw in ("protocol=", "use=", "login=", "password=")):
            continue
        # Strip http:// or https://
        domain = re.sub(r"^https?://", "", line)
        if domain and re.match(r"^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$", domain):
            return domain

    return None

def _extract_inadyn_domain(content: str) -> str | None:
    """Extract domain from inadyn.conf."""
    match = re.search(r"hostname\s*=\s*(.+)", content, re.MULTILINE)
    if match:
        value = match.group(1).strip().strip('"')
        if re.match(r"^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$", value):
            return value
    return None

def _extract_noip_domain(content: str) -> str | None:
    """Extract domain from no-ip2.conf."""
    match = re.search(r"^hostname\s+(\S+)", content, re.MULTILINE)
    if match:
        return match.group(1)
    return None

def _extract_duckdns_domain(content: str) -> str | None:
    """Extract domain from DuckDNS script or cron entry."""
    # DuckDNS update URL: ?domains=myhost — reconstruct full domain
    param_match = re.search(r"[?&]domains=([a-z0-9-]+)", content)
    if param_match:
        return f"{param_match.group(1)}.duckdns.org"
    # Fallback: full domain already present in content
    match = re.search(r"([a-z0-9-]+\.duckdns\.org)", content)
    if match:
        return match.group(1)
    return None

# ---------------------------------------------------------------------------
# UFW helpers
# ---------------------------------------------------------------------------

def _find_open_ports(
    ufw_rules: str,
    loopback_ports: set[str] | None = None,
    active_ports: set[str] | None = None,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> list[str]:
    """
    Find ports with unrestricted ALLOW rules (no source IP restriction).

    Filters applied (in order):
    - System-internal ports (DNS, DHCP, mDNS…) are always excluded.
    - Loopback-only ports are excluded (service not reachable externally).
    - If active_ports is provided, only ports with a real non-loopback
      listener are included — prevents dangling UFW rules (no running
      service) and bare rules (no /proto) from generating phantom entries.

    Returns:
        List of port/proto strings e.g. ["80/tcp", "443/tcp"].
    """
    open_ports: list[str] = []

    for line in ufw_rules.splitlines():
        rule = _ufw.parse_rule(line)
        if rule is None or not rule.to_col:
            continue
        if rule.action not in ("ALLOW", "LIMIT"):
            continue
        # The source restriction lives in the From column. Reading the whole
        # line let a private *destination* — `ufw allow from any to 192.168.1.5
        # port 8080` prints `192.168.1.5 8080/tcp` — pass for a private source,
        # so a world-open port was filed as restricted.
        if _PRIVATE_SOURCE.search(rule.from_col):
            continue
        # A blanket "Anywhere ALLOW IN Anywhere" is UFW's own default row, not a
        # port to report.
        if not rule.to_col or rule.to_col.lower().startswith("anywhere"):
            continue

        for lo, hi, proto in _ufw.to_column_ranges(rule.to_col, app_profiles):
            protos = (proto,) if proto else ("tcp", "udp")
            for port_num in range(lo, hi + 1):
                if port_num in _DDNS_SYSTEM_PORTS:
                    continue
                for pr in protos:
                    port_proto = f"{port_num}/{pr}"
                    if loopback_ports and port_proto in loopback_ports:
                        continue
                    if active_ports is not None and port_proto not in active_ports:
                        continue
                    if port_proto not in open_ports:
                        open_ports.append(port_proto)

    return open_ports

