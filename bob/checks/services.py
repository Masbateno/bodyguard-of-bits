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

import glob as _glob
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from bob.checks import _ufw
from bob.checks._run import TranslationFunc, _identity_t, _run, path_exists
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
        app_profiles: "dict[str, list[str]] | None" = None,
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
                port: _classify_exposure(port, ufw_rules, app_profiles)
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
        # `ufw allow OpenSSH` prints the profile name, not a port, in
        # non-verbose output — the form Ubuntu's own documentation recommends.
        app_profiles = _ufw.read_app_profiles()
        return [
            snap
            for snap in (
                cls._build_snapshot(service, ufw_rules, loopback_ports,
                                    all_listening_ports, app_profiles)
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
        # `ufw allow OpenSSH` prints the profile name, not a port, in
        # non-verbose output — the form Ubuntu's own documentation recommends.
        app_profiles = _ufw.read_app_profiles()
        return [
            cls._build_snapshot(service, ufw_rules, loopback_ports,
                                    all_listening_ports, app_profiles)
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
    # Read whenever the registry declares a config file, not only when the
    # strategy is spelled "auto". Eight services carried a config path under
    # ``config_key: "ask"`` — a strategy documented as "prompt the operator"
    # that no code implements — so their file was declared and never opened,
    # and an nginx on 8443 was audited as 80 and 443 while the port actually
    # exposed went unexamined.
    if service.config_key == "auto" or service.detection.config_files:
        detected = _auto_detect_ports(service)
        if detected:
            return detected

    return list(service.ports)

def _is_safe_service_config(path: Path, declared: str) -> bool:
    """Whether a service config file is safe to read.

    Stricter than a plain existence check and looser than
    ``_is_safe_config_path``, which refuses every symlink. A config tree
    legitimately links into itself: nginx enables a site by symlinking
    ``sites-enabled/default`` to ``sites-available/default``, and following
    that link is exactly what nginx does — refusing it left the `listen`
    directives unread on every Debian install, since ``nginx.conf`` carries
    none of them.

    The link is followed only while it stays inside the same service config
    directory, so ``sites-enabled/evil -> /etc/shadow`` is still refused and
    the trust boundary in SECURITY.md holds: nothing outside the service's own
    tree can be drawn into an audit report through a planted link.
    """
    if not path.is_absolute():
        return False
    if not path.is_symlink():
        return True
    root = Path(declared.split("*", 1)[0]).parent
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _auto_detect_ports(service: Service) -> "list[str]":
    """Detect the ports a service actually listens on, from its own config.

    Returns every port the config declares, because `listen` is additive: an
    nginx serving 80 and 443 declares both, and answering with one of them
    would drop the other out of the audit entirely. An overriding `port` key
    yields a single value — the last one.

    Returns an empty list when nothing could be read or understood, which the
    caller reads as "fall back to the registry defaults".
    """
    for declared, config_file in _expand_config_paths(service.detection.config_files):
        path = Path(config_file)
        if not path_exists(path) or not _is_safe_service_config(path, declared):
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
                    if key not in data:
                        continue
                    # A hand-edited file quotes what the daemon writes as an
                    # int; both mean the same port.
                    raw_value = data[key]
                    if isinstance(raw_value, bool) or not isinstance(
                        raw_value, (int, str)
                    ):
                        continue
                    number = _port_from_directive(str(raw_value))
                    if number is None:
                        continue
                    proto = "tcp"
                    if service.ports:
                        proto = service.ports[0].split("/")[-1]
                    return [f"{number}/{proto}"]
            except (ValueError, KeyError):
                pass
            continue  # Don't fall through to regex on JSON files

        # XML config (Jellyfin network.xml uses <PublicPort>8096</PublicPort>)
        if path.suffix == ".xml":
            xml_match = re.search(r"<(\w*Port\w*)>\s*(\d+)\s*</\1>", content,
                                  re.IGNORECASE)
            if xml_match is None:
                # …or an attribute: <gui port="8385"/>.
                attr = re.search(r'\b(\w*port)\s*=\s*"(\d+)"', content,
                                 re.IGNORECASE)
                if attr:
                    xml_match = attr
            if xml_match is None:
                # Syncthing puts the listener in <address>0.0.0.0:8384</address>,
                # so the port is behind an address here too.
                xml_match = re.search(r"<(address)>\s*(\S+?)\s*</\1>", content,
                                      re.IGNORECASE)
            if xml_match:
                number = _port_from_directive(xml_match.group(2))
                if number:
                    proto = service.ports[0].split("/")[-1] if service.ports else "tcp"
                    return [f"{number}/{proto}"]
            continue  # an XML file has no directives the regex below understands

        # Caddyfile: the site address opens the block and carries no keyword —
        # `:8443 {`, `example.com:8443 {`, `https://example.com {`.
        if path.name.lower() == "caddyfile":
            caddy_match = re.search(r"^\s*\S*:(\d+)\s*\{", content, re.MULTILINE)
            if caddy_match:
                number = _port_from_directive(caddy_match.group(1))
                if number:
                    proto = service.ports[0].split("/")[-1] if service.ports else "tcp"
                    return [f"{number}/{proto}"]
            continue

        # Strip comment lines before searching to avoid matching
        # commented-out directives like "# port = 2121", and drop any
        # ``[client]`` section: in the MySQL/MariaDB family it carries the port
        # clients *connect* to, never the one the server listens on, and it is
        # written above ``[mysqld]`` in the shipped files.
        # `;` opens a comment in the INI family (xrdp.ini, gitea app.ini,
        # cockpit.conf). Only at the start of a line: in nginx `;` terminates a
        # statement, and stripping from any `;` would erase `listen 8080;`.
        # Without this a commented-out `; port=9999` was read as the live port,
        # the same shape as the commented UFW and sudoers directives of v0.15.0.
        content_clean = re.sub(r"^\s*[#;].*$", "", content, flags=re.MULTILINE)
        content_clean = re.sub(r"^\s*\[client\][^\[]*", "", content_clean,
                               flags=re.MULTILINE | re.IGNORECASE)

        # Generic patterns — specific services may need custom parsing.
        #
        # The value is captured whole and parsed by `_port_from_directive`,
        # because a directive's argument is very often an *address* and not a
        # bare number: `listen 127.0.0.1:8080;` is the ordinary way to bind
        # nginx to one interface.
        #
        # Every match is walked, not just the first: a directive whose argument
        # is not a port is common and must not end the search — vsftpd.conf
        # opens with `listen=YES` and carries `listen_port=2121` three lines
        # below.
        #
        # Which match wins depends on the directive's own nature, and the two
        # families differ. `listen`/`listener` are *additive*: a server may
        # declare several and they all apply, so the first is as representative
        # as any. A `port` key is *overriding*: redis, mysql and the YAML
        # readers all apply the last one, and an operator changing a port by
        # appending a line — the same habit that drove the v0.15.0 umask and
        # login.defs findings — would otherwise be read as not having changed
        # it at all.
        listens:   "list[str]"   = []
        last_port: "str | None"  = None
        for match in re.finditer(
            # An optional dotted prefix covers the properties/YAML style used
            # by Elasticsearch (`http.port: 9200`) and its neighbours. The
            # leading `(?:^|\s)` still means `passport` cannot match, since the
            # prefix must end in a separator.
            # `-p 11211` is memcached's flag-file style, `ListenPort` WireGuard's.
            r"(?:^|\s)(?:-p\s+(\d+)|(?:[\w.]+[._])?"
            r"(listenport|port|listen|listener)"
            # An explicit YAML type tag (`port: !!int 9200`) sits between the
            # separator and the value.
            r"(?:\s*[=:]\s*|\s+)(?:!!\w+\s+)?(\S+))",
            content_clean,
            re.IGNORECASE | re.MULTILINE,
        ):
            flag_port, keyword, value = match.groups()
            number = _port_from_directive(flag_port or value or "")
            if number is None:
                continue
            if keyword and keyword.lower() in ("listen", "listener"):
                if number not in listens:
                    listens.append(number)
            else:
                last_port = number

        numbers = listens or ([last_port] if last_port is not None else [])
        if numbers:
            # Determine proto from registry default
            proto = "tcp"
            if service.ports:
                proto = service.ports[0].split("/")[-1]
            return [f"{n}/{proto}" for n in numbers]

    return []


def _auto_detect_port(service: Service) -> "str | None":
    """First detected port, or None. Kept for callers wanting one answer."""
    detected = _auto_detect_ports(service)
    return detected[0] if detected else None

def _expand_config_paths(patterns: "tuple[str, ...]") -> "list[tuple[str, str]]":
    """Resolve any wildcard in a service's declared config paths.

    PostgreSQL versions its directory (`/etc/postgresql/16/main/`) and
    WireGuard keeps one file per interface, so a literal list cannot name
    either. Sorted for a deterministic answer when several files match.
    """
    resolved: "list[tuple[str, str]]" = []
    for pattern in patterns:
        if "*" in pattern or "?" in pattern:
            try:
                resolved.extend((pattern, hit) for hit in sorted(_glob.glob(pattern)))
            except OSError:
                continue
        else:
            resolved.append((pattern, pattern))
    return resolved


def _port_from_directive(value: str) -> "str | None":
    """Extract the listening port from a config directive's argument.

    The argument is frequently an address rather than a bare number, and the
    previous reader took the first digits it met:

        listen 127.0.0.1:8080;     -> port 127
        listen 192.168.1.10:8443;  -> port 192
        listen [::]:443 ssl;       -> no match at all, silent fallback to the
                                      registry default

    which is the v0.15.0 UFW defect in another module — an address read where
    a port was expected — and it hits the commonest production form, binding a
    service to one interface. Everything after the last colon is the port; the
    brackets of an IPv6 literal never contain one.

    ``port 0`` is not a port. Redis and others use it to mean "do not listen on
    TCP at all", which is a *hardened* configuration, and reporting `0/tcp`
    invented a socket that cannot exist. Returns None so the caller keeps
    looking rather than asserting a nonsense port.
    """
    token = value.strip().rstrip(";,").strip("\"'")
    if not token:
        return None
    # Trailing directive words (`ssl`, `http2`, `default_server`) are already
    # excluded: the regex captures one whitespace-free token.
    candidate = token.rsplit(":", 1)[-1] if ":" in token else token
    if not candidate.isdigit():
        return None
    number = int(candidate)
    if not 1 <= number <= 65535:
        return None
    return str(number)


def _classify_exposure(
    port: str,
    ufw_rules: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> Exposure:
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

    want = int(port_num)

    # UFW uses first-match semantics — process rules in order and return on the
    # first one that covers this port.
    #
    # The port is matched against the rule's To column only. Searching the whole
    # line, as this did until v0.15.0, let a source address stand in for a
    # target: one rule `80/tcp ALLOW IN 192.168.1.22` reported ports 1, 22, 168
    # and 192 as OPEN_LOCAL, and 22 is the commonest last octet on an RFC1918
    # network — so a host running SSH with no rule for it was told SSH was
    # restricted to the local network. `ports` already anchored on the To column
    # and said why in a docstring; the grammar now lives in one place.
    for line in ufw_rules.splitlines():
        rule = _ufw.parse_rule(line)
        if rule is None or not rule.to_col:
            continue
        ranges = _ufw.to_column_ranges(rule.to_col, app_profiles)
        if not _ufw.ranges_cover(ranges, want, proto):
            continue

        if rule.action == "DENY":
            return Exposure.DENY
        if rule.action in ("ALLOW", "LIMIT"):
            # The source restriction lives in the From column. Reading the whole
            # line here would let a private *destination* pass for a private
            # source.
            if _line_has_private_or_loopback(rule.from_col):
                return Exposure.OPEN_LOCAL
            return Exposure.OPEN_WORLD

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
