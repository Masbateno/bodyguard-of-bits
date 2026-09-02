"""
Service registry module for BOB.

Loads service definitions from data/services.json and exposes them
as typed Python dataclasses. This is the single source of truth for
all known network services — no other module defines services inline.

Adding a new service requires only editing data/services.json.

Usage:
    from bob.registry import ServiceRegistry

    registry = ServiceRegistry.load()

    for service in registry.all():
        print(service.label, service.risk)

    ssh = registry.get("ssh")
    critical = registry.by_risk("critical")
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from bob._paths import resolve_share_dir
from bob.sysinfo import get_user_home

logger = logging.getLogger(__name__)

# Service data location:
# - If BOB_SHARE env var is set (installed), use that share directory
# - Otherwise fall back to data/ next to this module (development)
_share_path = resolve_share_dir()
_DATA_DIR = (_share_path / "data") if _share_path else (Path(__file__).parent / "data")
_SERVICES_FILE = _DATA_DIR / "services.json"

# User plugin directory — drop *.json files here to add custom services.
# Resolved at import time via SUDO_USER so it points to the invoking user's
# home. BOB runs one-shot per audit; the import-time resolution is fine for
# production. Tests patch `bob.registry._PLUGIN_DIR` directly when needed.
_PLUGIN_DIR = get_user_home() / ".config" / "bob" / "services.d"

# Valid values for the risk field
VALID_RISKS = frozenset({"low", "medium", "high", "critical"})


# Port format: "number/proto" e.g. "22/tcp", "5353/udp"
_PORT_RE = re.compile(r"^\d{1,5}/(tcp|udp)$")


# ---------------------------------------------------------------------------
# Label transform (single source of truth)
# ---------------------------------------------------------------------------

def service_label_to_subkey(label: str) -> str:
    """Apply the canonical service-label → ``service_risk.*`` subkey transform.

    Single source of truth used by:
      * ``bob/display.py::display_risk_context`` (terminal panorama display)
      * ``bob/display.py::print_audit_summary`` (summary box service rows)
      * ``bob/explain.py::_render_dynamic_service_explain`` (T26 v0.8.1
        ``bob --explain services.exposed.<id>`` dynamic dispatch)

    M-3 (v0.8.1 audit) consolidation: the transform was previously inlined
    in all three sites (display.py:152-154, display.py:630-632, explain.py
    helper). The T26 docstring claimed display.py was the "single source
    of truth" but it had two duplicates of its own. Any change to the
    transform (e.g. a new service label containing ``&`` or ``+``) would
    silently diverge ``--explain`` from the audit's "Service network
    analysis" block. Centralised here so future contributors update one
    function instead of three.

    Examples:
        ``"SSH Server"``        → ``"ssh_server"``
        ``"Samba (Windows file sharing)"``
                                → ``"samba_windows_file_sharing"``
        ``"MySQL / MariaDB"``   → ``"mysql___mariadb"``
        ``"AdGuard Home (DNS sinkhole)"``
                                → ``"adguard_home_dns_sinkhole"``
    """
    return (label.lower()
                 .replace(" ", "_")
                 .replace("/", "_")
                 .replace("(", "")
                 .replace(")", ""))


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Detection:
    """
    Extended detection hints for services not installable via dpkg alone.

    Args:
        binary:       Bare command names, resolved via $PATH, or absolute
                      paths. The JSON schema is the reference for this
                      field; the two disagreed until v0.15.3, and the
                      code honoured neither.
        snap:         Snap package names to check via 'snap list'.
        config_files: Config file paths used to auto-detect the service port.
    """
    binary:       tuple[str, ...]
    snap:         tuple[str, ...]
    config_files: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> "Detection":
        return cls(
            binary=tuple(data.get("binary", [])),
            snap=tuple(data.get("snap", [])),
            config_files=tuple(data.get("config_files", [])),
        )

@dataclass(frozen=True)
class Service:
    """
    Immutable representation of a network service known to BOB.

    The JSON shape accepted by ``from_dict()`` is described formally in
    ``bob/data/schemas/service.schema.json`` (Draft 2020-12 JSON Schema).
    Both validators must stay in sync — the test suite enforces this.

    Args:
        id:         Unique identifier (e.g. "ssh", "nginx").
        label:      Human-readable display name (e.g. "SSH Server").
        packages:   dpkg package names to check for installation.
        services:   systemd service names to check for state.
        ports:      Default ports in "number/proto" format (e.g. "22/tcp").
        risk:       Risk classification: "low" | "medium" | "high" | "critical".
        detection:  Extended detection hints (snap, binary, config_files).
    """
    id:         str
    label:      str
    packages:   tuple[str, ...]
    services:   tuple[str, ...]
    ports:      tuple[str, ...]
    risk:       str
    detection:  Detection

    @property
    def is_critical(self) -> bool:
        return self.risk == "critical"

    @property
    def is_high_or_critical(self) -> bool:
        return self.risk in ("high", "critical")

    @property
    def main_port(self) -> str:
        """Return the first port (used for display and remediation commands)."""
        return self.ports[0] if self.ports else ""

    @classmethod
    def from_dict(cls, data: dict) -> "Service":
        """
        Build a Service from a JSON-parsed dictionary.

        Args:
            data: Dict parsed from a services.json entry.

        Returns:
            Populated Service instance.

        Raises:
            ValueError: If required fields are missing or have invalid values.
        """
        required = ("id", "label", "packages", "services", "ports", "risk")
        for required_field in required:
            if required_field not in data:
                raise ValueError(f"Service entry missing required field: {required_field!r}")

        risk = data["risk"]
        if risk not in VALID_RISKS:
            raise ValueError(
                f"Service {data['id']!r}: invalid risk {risk!r}. "
                f"Must be one of: {sorted(VALID_RISKS)}"
            )

        ports = tuple(data["ports"])
        for p in ports:
            if not _PORT_RE.match(p):
                raise ValueError(
                    f"Service {data['id']!r}: invalid port format {p!r}. "
                    f"Expected 'number/tcp' or 'number/udp'."
                )
            port_num = int(p.split("/")[0])
            if not (1 <= port_num <= 65535):
                raise ValueError(
                    f"Service {data['id']!r}: port number {port_num} out of range (1–65535)."
                )

        detection = Detection.from_dict(data.get("detection", {}))

        # v0.15.4: was "config_key 'fixed' requires at least one port" — the only
        # rule that field ever enforced. Restated without it, and deliberately
        # NOT as "every service needs a port": a service may legitimately
        # declare none and let its ports be parsed out of its own config, which
        # is what the old "auto" form meant. What is unusable is declaring
        # neither — BOB then has no way to ever learn the service's ports.
        if not ports and not detection.config_files:
            raise ValueError(
                f"Service {data['id']!r}: declares no port and no config file to "
                f"read one from — its ports could never be determined."
            )

        return cls(
            id=data["id"],
            label=data["label"],
            packages=tuple(data["packages"]),
            services=tuple(data["services"]),
            ports=ports,
            risk=risk,
            detection=detection,
        )

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_CURRENT_PLUGIN_SCHEMA_VERSION = 1

def _extract_plugin_entries(raw: object, plugin_name: str) -> list | None:
    """
    Resolve a plugin file's parsed JSON into a flat list of service entries.

    Two shapes are accepted:

    1. **Raw array** (legacy / current default): the file is a JSON array of
       service objects.
    2. **Wrapped object** (forward-compat): the file is an object with
       ``{"schema_version": 1, "services": [...]}``. The wrapper lets future
       schema versions be gated explicitly. Currently only ``schema_version: 1``
       is accepted; higher versions are rejected with a warning so users see a
       clear "upgrade BOB" hint instead of silent half-loading.

    Returns the list of service entries, or ``None`` on irrecoverable error
    (logs a warning and the caller skips the file).
    """
    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict):
        sv = raw.get("schema_version")
        if not isinstance(sv, int):
            logger.warning(
                "Plugin %s: wrapped form requires integer 'schema_version' — skipped",
                plugin_name,
            )
            return None
        if sv > _CURRENT_PLUGIN_SCHEMA_VERSION:
            logger.warning(
                "Plugin %s: schema_version=%d is newer than this BOB build supports "
                "(max %d) — skipped. Upgrade BOB or downgrade the plugin.",
                plugin_name, sv, _CURRENT_PLUGIN_SCHEMA_VERSION,
            )
            return None
        if sv < 1:
            logger.warning(
                "Plugin %s: schema_version=%d is invalid (must be >= 1) — skipped",
                plugin_name, sv,
            )
            return None
        services_raw = raw.get("services")
        if not isinstance(services_raw, list):
            logger.warning(
                "Plugin %s: wrapped form requires 'services' array — skipped",
                plugin_name,
            )
            return None
        return services_raw

    logger.warning(
        "Plugin %s must be a JSON array or a wrapped object — skipped",
        plugin_name,
    )
    return None

def _load_plugins(services: list[Service], ids_seen: set[str]) -> None:
    """
    Scan the per-user plugin directory for *.json plugin files and merge valid
    entries into the services list. Errors in individual files are logged and
    skipped — they never abort the audit.

    Each file may use either the raw-array shape or the wrapped
    {schema_version, services} shape. See _extract_plugin_entries().

    Args:
        services:  Mutable list to append valid plugin services into.
        ids_seen:  Set of already-registered IDs used for duplicate detection.
    """
    try:
        if not _PLUGIN_DIR.is_dir():
            return
    except PermissionError:
        # Directory exists but is not readable (e.g. created by root via sudo).
        # Skip plugins gracefully — the user can fix ownership separately.
        return

    _MAX_PLUGIN_SIZE = 256 * 1024  # 256 KB per plugin
    try:
        plugin_files = sorted(_PLUGIN_DIR.glob("*.json"))
    except PermissionError:
        return
    for plugin_file in plugin_files:
        try:
            with plugin_file.open(encoding="utf-8") as fh:
                content = fh.read(_MAX_PLUGIN_SIZE + 1)
            if len(content) > _MAX_PLUGIN_SIZE:
                logger.warning("Plugin %s exceeds 256 KB — skipped", plugin_file.name)
                continue
            raw = json.loads(content)
        except (OSError, ValueError) as exc:
            logger.warning("Plugin %s could not be loaded: %s — skipped", plugin_file.name, exc)
            continue

        entries = _extract_plugin_entries(raw, plugin_file.name)
        if entries is None:
            continue

        for i, entry in enumerate(entries):
            try:
                service = Service.from_dict(entry)
            except (ValueError, KeyError) as exc:
                logger.warning("Plugin %s entry #%d invalid: %s — skipped", plugin_file.name, i, exc)
                continue

            if service.id in ids_seen:
                logger.warning(
                    "Plugin %s entry #%d: duplicate id %r — skipped",
                    plugin_file.name, i, service.id,
                )
                continue

            ids_seen.add(service.id)
            services.append(service)
            logger.debug("Loaded plugin service %r from %s", service.id, plugin_file.name)

class ServiceRegistry:
    """
    Loaded collection of Service objects.

    Provides lookup by id and filtering by risk level.

    Args:
        services: Ordered list of Service objects.
    """

    def __init__(self, services: list[Service]) -> None:
        self._services: list[Service] = services
        self._by_id: dict[str, Service] = {s.id: s for s in services}

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "ServiceRegistry":
        """
        Load and validate the services registry from a JSON file.

        Args:
            path: Override the default services.json path. Useful in tests.

        Returns:
            Populated ServiceRegistry.

        Raises:
            FileNotFoundError: If the services file does not exist.
            ValueError:        If any service entry is invalid.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        json_path = path or _SERVICES_FILE

        if not json_path.exists():
            raise FileNotFoundError(
                f"Services file not found: {json_path}"
            )

        _MAX_JSON_SIZE = 1 * 1024 * 1024  # 1 MB
        with json_path.open(encoding="utf-8") as fh:
            content = fh.read(_MAX_JSON_SIZE + 1)
        if len(content) > _MAX_JSON_SIZE:
            raise ValueError("services.json exceeds maximum allowed size (1 MB)")
        raw = json.loads(content)

        if not isinstance(raw, list):
            raise ValueError(f"services.json must contain a JSON array, got {type(raw).__name__}")

        services: list[Service] = []
        ids_seen: set[str] = set()

        for i, entry in enumerate(raw):
            try:
                service = Service.from_dict(entry)
            except (ValueError, KeyError) as exc:
                raise ValueError(f"services.json entry #{i}: {exc}") from exc

            if service.id in ids_seen:
                raise ValueError(f"Duplicate service id: {service.id!r}")

            ids_seen.add(service.id)
            services.append(service)

        logger.debug("Loaded %d services from %s", len(services), json_path)

        # Merge user plugins from services.d/
        # IMPORTANT: plugins must be loaded before cls() so _by_id includes plugin services.
        _load_plugins(services, ids_seen)

        return cls(services)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def all(self) -> list[Service]:
        """Return all services in definition order."""
        return list(self._services)

    def get(self, service_id: str) -> Service | None:
        """
        Return the service with the given id, or None if not found.

        Args:
            service_id: The service id string (e.g. "ssh", "nginx").
        """
        return self._by_id.get(service_id)

    def by_risk(self, risk: str) -> list[Service]:
        """
        Return all services matching the given risk level.

        Args:
            risk: One of "low", "medium", "high", "critical".
        """
        return [s for s in self._services if s.risk == risk]

    def high_and_critical(self) -> list[Service]:
        """Return all services with risk level 'high' or 'critical'."""
        return [s for s in self._services if s.is_high_or_critical]

    def __len__(self) -> int:
        return len(self._services)

    def __iter__(self) -> Iterator[Service]:
        return iter(self._services)
