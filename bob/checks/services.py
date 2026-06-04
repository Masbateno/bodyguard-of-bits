"""
Network services check for BOB.

Detects installed network services, their systemd state, and their
UFW exposure level for each listening port.

Split into two parts:
  1. ServiceSnapshot.from_system()  — collects data via subprocess.
  2. check_services(snapshots, t)   — pure logic, returns a CheckResult.

Usage:
    from bob.checks.services import ServiceSnapshot, check_services
    from bob.registry import ServiceRegistry

    registry = ServiceRegistry.load()
    snapshots = ServiceSnapshot.collect(registry)
    result = check_services(snapshots, t=t)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, _is_safe_config_path, _run
from bob.registry import Service, ServiceRegistry
from bob.scoring import CheckResult
from bob.sysinfo import _is_private_or_loopback_ipv4, _is_private_or_loopback_ipv6

logger = logging.getLogger(__name__)

# I-5 (v0.7.4): private-IP detection delegates to sysinfo helpers (single
# source of truth, per v0.5.6 architectural unification). Pre-v0.7.4 this
# module shipped a duplicate hand-rolled regex that drifted from sysinfo.
_IPV4_TOKEN_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?")
_IPV6_TOKEN_RE = re.compile(r"(?<![\w:])([0-9a-fA-F:]*::[0-9a-fA-F:]*)(?:/\d+)?")


def _line_has_private_or_loopback(line: str) -> bool:
    """Return True if ``line`` references an IP within a private/loopback range.

    Used by _classify_exposure to distinguish OPEN_LOCAL from OPEN_WORLD.
    Delegates to sysinfo._is_private_or_loopback_ipv4 / _ipv6 so the
    CGNAT / ULA / link-local definitions remain unified across the codebase.
    """
    for m in _IPV4_TOKEN_RE.finditer(line):
        if _is_private_or_loopback_ipv4(m.group(1)):
            return True
    for m in _IPV6_TOKEN_RE.finditer(line):
        # Strip zone-id (`fe80::1%eth0`) before passing to the helper;
        # IPv6Address rejects the `%` suffix.
        token = m.group(1).split("%", 1)[0]
        if _is_private_or_loopback_ipv6(token):
            return True
    return False

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ServiceState(Enum):
    """Systemd service state."""
    ACTIVE_ENABLED    = "active_enabled"
    ACTIVE_DISABLED   = "active_disabled"
    INACTIVE_ENABLED  = "inactive_enabled"
    INACTIVE_DISABLED = "inactive_disabled"
    UNKNOWN           = "unknown"

    @property
    def is_active(self) -> bool:
        return self in (ServiceState.ACTIVE_ENABLED, ServiceState.ACTIVE_DISABLED)

    @property
    def is_inactive(self) -> bool:
        return self in (ServiceState.INACTIVE_ENABLED, ServiceState.INACTIVE_DISABLED)

class Exposure(Enum):
    """UFW exposure level for a single port."""
    OPEN_WORLD = "open_world"   # ALLOW without source restriction
    OPEN_LOCAL = "open_local"   # ALLOW restricted to private IP/range
    DENY       = "deny"         # explicit DENY rule
    NO_RULE          = "no_rule"           # no UFW rule covers this port
    LOOPBACK         = "loopback"          # service bound to localhost only — UFW rule irrelevant
    LOOPBACK_NO_RULE = "loopback_no_rule"  # loopback-only, no UFW rule — covered by default deny
    NOT_LISTENING    = "not_listening"     # port in registry but not actively listening

# Resolved after ServiceState is defined
_STATE_PRIORITY = {
    ServiceState.ACTIVE_ENABLED:    4,
    ServiceState.ACTIVE_DISABLED:   3,
    ServiceState.INACTIVE_ENABLED:  2,
    ServiceState.INACTIVE_DISABLED: 1,
    ServiceState.UNKNOWN:           0,
}

# ---------------------------------------------------------------------------
# Service snapshot
# ---------------------------------------------------------------------------

@dataclass
class ServiceSnapshot:
    """
    State of a single service as detected on the live system.

    Args:
        service:     Service definition from the registry.
        installed:   True if the service was detected on this system.
        install_via: How the service was detected: "dpkg", "snap", "binary", or "".
        state:       Systemd service state.
        ports:       Resolved port list (may differ from registry defaults if auto-detected).
        exposures:   Mapping of port string to Exposure enum value.
                     e.g. {"22/tcp": Exposure.OPEN_WORLD, "22/udp": Exposure.NO_RULE}
    """
    service:     Service
    installed:   bool
    install_via: str
    state:       ServiceState
    ports:       list[str]
    exposures:   dict[str, Exposure] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.service.label

    @property
    def risk(self) -> str:
        return self.service.risk

    @property
    def is_active(self) -> bool:
        return self.state.is_active

    @classmethod
    def _build_snapshot(
        cls,
        service: Service,
        ufw_rules: str,
        loopback_ports: set[str] | None,
        all_listening_ports: set[str] | None,
    ) -> "ServiceSnapshot":
        """
        Build a ServiceSnapshot for a single service, installed or not.

        Contains all exposure-override logic in one place to avoid
        duplication between collect() and collect_all().
        """
        installed, via = _detect_installation(service)

        if installed:
            state = _detect_state(service)
            ports = _resolve_ports(service)
            exposures = {
                port: _classify_exposure(port, ufw_rules)
                for port in ports
            }

            # Override exposure for ports bound exclusively to loopback
            if loopback_ports:
                for port in ports:
                    if port in loopback_ports:
                        if exposures[port] == Exposure.OPEN_WORLD:
                            exposures[port] = Exposure.LOOPBACK
                        elif exposures[port] == Exposure.NO_RULE:
                            exposures[port] = Exposure.LOOPBACK_NO_RULE

            # Override exposure for registry ports not actively listening
            if all_listening_ports is not None:
                for port in ports:
                    if port not in all_listening_ports and exposures.get(port) == Exposure.NO_RULE:
                        exposures[port] = Exposure.NOT_LISTENING
        else:
            state     = ServiceState.UNKNOWN
            ports     = list(service.ports)
            exposures = {}

        return cls(
            service=service,
            installed=installed,
            install_via=via,
            state=state,
            ports=ports,
            exposures=exposures,
        )

    @classmethod
    def collect(
        cls,
        registry: ServiceRegistry,
        ufw_rules: str | None = None,
        loopback_ports: set | None = None,
        all_listening_ports: set | None = None,
    ) -> list["ServiceSnapshot"]:
        """
        Collect snapshots for installed services only.

        Args:
            registry:           Loaded ServiceRegistry.
            ufw_rules:          Output of `ufw status numbered` (injected for testing).
                                If None, fetched from the system.
            loopback_ports:     Set of port strings bound exclusively to loopback.
            all_listening_ports: Set of all actively listening port strings.

        Returns:
            List of ServiceSnapshot for every installed service.
            Non-installed services are excluded.
        """
        if ufw_rules is None:
            ufw_rules = _run("ufw", "status", "numbered")
        return [
            snap
            for snap in (
                cls._build_snapshot(service, ufw_rules, loopback_ports, all_listening_ports)
                for service in registry
            )
            if snap.installed
        ]

    @classmethod
    def collect_all(
        cls,
        registry: ServiceRegistry,
        ufw_rules: str | None = None,
        loopback_ports: set | None = None,
        all_listening_ports: set | None = None,
    ) -> list["ServiceSnapshot"]:
        """
        Collect snapshots for ALL services in the registry.

        Unlike collect(), non-installed services are included with
        installed=False and an empty exposures dict. Used for the
        services panorama display.

        Args:
            registry:           Loaded ServiceRegistry.
            ufw_rules:          Output of `ufw status numbered` (injected for testing).
                                If None, fetched from the system.
            loopback_ports:     Set of port strings bound exclusively to loopback.
            all_listening_ports: Set of all actively listening port strings.

        Returns:
            List of ServiceSnapshot for every service in the registry.
        """
        if ufw_rules is None:
            ufw_rules = _run("ufw", "status", "numbered")
        return [
            cls._build_snapshot(service, ufw_rules, loopback_ports, all_listening_ports)
            for service in registry
        ]

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_services(
    snapshots: list[ServiceSnapshot],
    network_context: str = "local",
    ufw_active: bool = True,
    t: TranslationFunc | None = None,
) -> CheckResult:
    """
    Evaluate service snapshots and return findings and deductions.

    Args:
        snapshots:       List of installed ServiceSnapshots.
        network_context: "local" or "public" — affects deduction weight.
        ufw_active:      False when UFW is inactive — adjusts exposure messages.
        t:               Translation function. If None, key names are used.

    Returns:
        CheckResult with all service findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    for snap in snapshots:
        _check_single_service(snap, result, network_context, ufw_active, _t)

    return result

def _check_single_service(
    snap: ServiceSnapshot,
    result: CheckResult,
    network_context: str,
    ufw_active: bool,
    _t,
) -> None:
    """Evaluate a single service snapshot and add findings to result."""

    # Inactive and disabled
    if snap.state == ServiceState.INACTIVE_DISABLED:
        if snap.service.is_high_or_critical:
            # v0.8.0 drift batch: dormant critical security service = no
            # actual defence. +1pt to score so the finding actually moves
            # the verdict (previously bare warn = visible but no impact).
            result.warn_with_deduction(
                key="services.state.installed_inactive_critical",
                message=_t("services.state.installed_inactive_critical", label=snap.label),
                points=1,
                nature="improvement",
            )
        else:
            result.info(
                message=_t("services.state.inactive_disabled", label=snap.label),
                key="services.state.inactive_disabled",
            )
        return

    # Active but not enabled at boot
    if snap.state == ServiceState.ACTIVE_DISABLED:
        # v0.8.0 drift batch: running but not enabled = lost at next reboot.
        # +1pt so it counts in the score.
        result.warn_with_deduction(
            key="services.state.active_disabled",
            message=_t("services.state.active_disabled", label=snap.label),
            points=1,
            nature="improvement",
        )

    # Active and enabled — OK
    if snap.state == ServiceState.ACTIVE_ENABLED:
        result.ok(
            message=_t("services.state.active_enabled"),
            key="services.state.active_enabled",
        )

    # Unknown state — informational
    if snap.state == ServiceState.UNKNOWN:
        result.info(
            message=_t("services.state.unknown"),
            key="services.state.unknown",
        )

    # Analyse each port exposure
    for port, exposure in snap.exposures.items():
        _check_port_exposure(snap, port, exposure, result, network_context, ufw_active, _t)

def _check_port_exposure(
    snap: ServiceSnapshot,
    port: str,
    exposure: Exposure,
    result: CheckResult,
    network_context: str,
    ufw_active: bool,
    _t,
) -> None:
    """Add findings for a single port exposure."""

    if not ufw_active and exposure in (Exposure.NO_RULE, Exposure.LOOPBACK_NO_RULE):
        exp_key = f"services.exposure.{exposure.value}_ufw_inactive"
    else:
        exp_key = f"services.exposure.{exposure.value}"
    port_msg = _t("services.port_exposure", port=port, exposure=_t(exp_key))

    if exposure == Exposure.OPEN_WORLD:
        # High/critical services exposed to internet get extra penalty in public context
        base_points = 1
        if snap.service.is_high_or_critical and network_context in ("public", "ddns"):
            base_points = 3
        elif snap.service.is_high_or_critical:
            base_points = 2

        _exposure_key = f"services.exposed.{snap.service.id}"
        if snap.service.is_high_or_critical:
            result.alert(
                message=port_msg,
                nature="action",
                key=_exposure_key,
            )
        else:
            result.warn(
                message=port_msg,
                nature="improvement",
                key=_exposure_key,
            )
        result.add_deduction(
            reason=_t("deduction.service_open_world", label=snap.label, port=port),
            points=base_points,
            context=network_context,
            key=_exposure_key,
        )

    elif exposure == Exposure.OPEN_LOCAL:
        result.warn(
            message=port_msg,
            nature="structural",
            key="services.exposure.open_local",
        )

    elif exposure == Exposure.DENY:
        result.ok(message=port_msg, key="services.exposure.deny")

    elif exposure == Exposure.NO_RULE:
        result.info(message=port_msg, key="services.exposure.no_rule")

    elif exposure == Exposure.LOOPBACK:
        result.info(message=port_msg, key="services.exposure.loopback")

    elif exposure == Exposure.LOOPBACK_NO_RULE:
        result.info(message=port_msg, key="services.exposure.loopback_no_rule")

    elif exposure == Exposure.NOT_LISTENING:
        result.info(message=port_msg, key="services.exposure.not_listening")

# ---------------------------------------------------------------------------
# System detection helpers
# ---------------------------------------------------------------------------

def _detect_installation(service: Service) -> tuple[bool, str]:
    """
    Check if a service is installed via dpkg, snap, or binary.

    Uses dpkg-query (scripting API) rather than dpkg -l (display only)
    for reliable status parsing.

    Returns:
        Tuple of (installed: bool, method: str).
        Method is one of: "dpkg", "snap", "binary", or "".
    """
    # dpkg-query check — stable scripting interface, locale-independent
    for pkg in service.packages:
        output = _run("dpkg-query", "-W", "-f=${Status}", pkg)
        if "install ok installed" in output:
            return True, "dpkg"

    # snap check
    for snap_pkg in service.detection.snap:
        output = _run("snap", "list", snap_pkg)
        if snap_pkg in output and "error" not in output.lower():
            return True, "snap"

    # binary check
    for binary_path in service.detection.binary:
        if Path(binary_path).is_file():
            return True, "binary"

    return False, ""

def _detect_single_unit_state(svc_name: str) -> ServiceState:
    """
    Determine the systemd state of a single service unit.

    Handles template services (e.g. wg-quick@) by finding the first
    active instance.

    Returns:
        ServiceState enum value for this unit.
    """
    # Handle template services like wg-quick@
    if svc_name.endswith("@"):
        list_output = _run("systemctl", "list-units", "--all", svc_name + "*")
        if not list_output.strip():
            return ServiceState.INACTIVE_DISABLED
        match = re.search(r"(\S+\.service)", list_output)
        if match:
            svc_name = match.group(1)
        else:
            return ServiceState.INACTIVE_DISABLED

    active  = _run("systemctl", "is-active",  svc_name).strip()
    enabled = _run("systemctl", "is-enabled", svc_name).strip()

    is_active  = active  == "active"
    is_enabled = enabled == "enabled"

    if is_active and is_enabled:
        return ServiceState.ACTIVE_ENABLED
    if is_active:
        return ServiceState.ACTIVE_DISABLED
    if is_enabled:
        return ServiceState.INACTIVE_ENABLED
    if active in ("inactive", "failed", "activating"):
        return ServiceState.INACTIVE_DISABLED
    return ServiceState.UNKNOWN

def _detect_state(service: Service) -> ServiceState:
    """
    Determine the effective systemd state of a service.

    Aggregates across all units in service.services: returns the
    highest-priority state found. This prevents a first-match bug
    where an inactive unit would mask an active sibling.

    Priority: ACTIVE_ENABLED > ACTIVE_DISABLED > INACTIVE_ENABLED
              > INACTIVE_DISABLED > UNKNOWN

    Returns:
        ServiceState enum value.
    """
    best = ServiceState.UNKNOWN
    for svc_name in service.services:
        state = _detect_single_unit_state(svc_name)
        if _STATE_PRIORITY[state] > _STATE_PRIORITY[best]:
            best = state
    return best

def _resolve_ports(service: Service) -> list[str]:
    """
    Resolve the actual ports for a service.

    For services with config_key="auto", attempts to read the port
    from the service's configuration file. Falls back to registry defaults.

    Returns:
        List of port strings in "number/proto" format.
    """
    if service.config_key == "auto":
        detected = _auto_detect_port(service)
        if detected:
            return [detected]

    return list(service.ports)

def _auto_detect_port(service: Service) -> str | None:
    """
    Attempt to detect the actual port from the service configuration file.

    Returns:
        Port string like "8080/tcp", or None if detection fails.
    """
    for config_file in service.detection.config_files:
        path = Path(config_file)
        if not path.exists() or not _is_safe_config_path(path):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # JSON config files (e.g. Transmission settings.json uses "rpc-port")
        if path.suffix == ".json":
            try:
                data = json.loads(content)
                for key in ("rpc-port", "port"):
                    if key in data and isinstance(data[key], int):
                        proto = "tcp"
                        if service.ports:
                            proto = service.ports[0].split("/")[-1]
                        return f"{data[key]}/{proto}"
            except (ValueError, KeyError):
                pass
            continue  # Don't fall through to regex on JSON files

        # Strip comment lines before searching to avoid matching
        # commented-out directives like "# port = 2121"
        content_clean = re.sub(r"^\s*#.*$", "", content, flags=re.MULTILINE)

        # Generic patterns — specific services may need custom parsing
        # Port = 8080 / port=8080 / listen 8080 / HTTP_PORT = 3000
        # listen_port=21 (vsftpd)
        match = re.search(
            r"(?:^|\s)(?:listen_port|port|listen|HTTP_PORT|http_port)(?:\s*[=:]\s*|\s+)(\d+)",
            content_clean,
            re.IGNORECASE | re.MULTILINE,
        )
        if match:
            port_num = match.group(1)
            # Determine proto from registry default
            proto = "tcp"
            if service.ports:
                proto = service.ports[0].split("/")[-1]
            return f"{port_num}/{proto}"

    return None

def _classify_exposure(port: str, ufw_rules: str) -> Exposure:
    """
    Classify how a port is handled by UFW rules.

    Args:
        port:      Port string like "22/tcp" or "5353/udp".
        ufw_rules: Output of `ufw status numbered`.

    Returns:
        Exposure enum value.
    """
    port_num  = port.split("/")[0]
    proto     = port.split("/")[1] if "/" in port else "tcp"

    if not port_num.isdigit() or not (1 <= int(port_num) <= 65535):
        logger.warning("Invalid port number in registry: %r", port_num)
        return Exposure.NO_RULE
    if proto not in ("tcp", "udp"):
        logger.warning("Invalid protocol in registry: %r", proto)
        return Exposure.NO_RULE

    port_pattern = re.compile(
        r"\b" + re.escape(port_num) + r"(?:/" + re.escape(proto) + r")?\b",
        re.IGNORECASE,
    )

    # UFW uses first-match semantics — process rules in order and return immediately
    for line in ufw_rules.splitlines():
        # Skip non-rule lines
        if not re.match(r"\s*\[\s*\d+\]", line):
            continue

        if not port_pattern.search(line):
            continue

        line_upper = line.upper()

        if "DENY" in line_upper:
            return Exposure.DENY
        elif "ALLOW" in line_upper:
            # Check if rule has a source restriction to a private range
            if _line_has_private_or_loopback(line):
                return Exposure.OPEN_LOCAL
            else:
                return Exposure.OPEN_WORLD

    return Exposure.NO_RULE
