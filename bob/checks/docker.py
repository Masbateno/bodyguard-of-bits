"""
Docker security check for BOB.

Verifies that Docker is configured to not bypass UFW rules via iptables,
and lists any running containers with exposed ports.

The main risk: by default Docker manipulates iptables directly, bypassing
UFW rules entirely. This is an architectural choice with trade-offs — the
tool documents options rather than applying an automatic fix.

Split into two parts:
  1. DockerSnapshot.from_system() — collects data via subprocess.
  2. check_docker(snapshot, t)    — pure logic, returns a CheckResult.

Usage:
    from bob.checks.docker import DockerSnapshot, check_docker

    snapshot = DockerSnapshot.from_system()
    result = check_docker(snapshot, t=t)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

logger = logging.getLogger(__name__)

DAEMON_JSON_PATH = Path("/etc/docker/daemon.json")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExposedPort:
    """A port exposed by a running Docker container."""
    container_name: str
    host_port:      int
    container_port: int
    proto:          str
    host_ip:        str   # "0.0.0.0" | "127.0.0.1" | specific IP

    @property
    def port_proto(self) -> str:
        return f"{self.host_port}/{self.proto}"

    @property
    def is_public(self) -> bool:
        """True if the port is accessible from the network (not loopback-only)."""
        try:
            return not ipaddress.ip_address(self.host_ip).is_loopback
        except ValueError:
            return True  # unrecognised format — assume public to be safe

@dataclass
class DockerSnapshot:
    """
    Docker security state as collected from the live system.

    Args:
        installed:          True if docker is available.
        iptables_disabled:  True if {"iptables": false} is set in daemon.json.
        daemon_json_exists: True if /etc/docker/daemon.json exists.
        exposed_ports:      List of ports exposed by running containers.
    """
    installed:          bool
    iptables_disabled:  bool
    daemon_json_exists: bool
    exposed_ports:      list[ExposedPort] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "DockerSnapshot":
        """
        Collect Docker state from the live system.

        Returns:
            Populated DockerSnapshot. Never raises.
        """
        installed = _command_exists("docker")
        if not installed:
            return cls(
                installed=False,
                iptables_disabled=False,
                daemon_json_exists=False,
                exposed_ports=[],
            )

        daemon_json_exists, iptables_disabled = _check_daemon_json()
        exposed_ports = _get_exposed_ports()

        return cls(
            installed=True,
            iptables_disabled=iptables_disabled,
            daemon_json_exists=daemon_json_exists,
            exposed_ports=exposed_ports,
        )

    @classmethod
    def not_installed(cls) -> "DockerSnapshot":
        """Factory for a snapshot representing Docker not installed."""
        return cls(
            installed=False,
            iptables_disabled=False,
            daemon_json_exists=False,
            exposed_ports=[],
        )

    @classmethod
    def safe(cls, exposed_ports: list[ExposedPort] | None = None) -> "DockerSnapshot":
        """Factory for a safe Docker configuration (iptables disabled)."""
        return cls(
            installed=True,
            iptables_disabled=True,
            daemon_json_exists=True,
            exposed_ports=exposed_ports or [],
        )

    @classmethod
    def unsafe(cls, exposed_ports: list[ExposedPort] | None = None) -> "DockerSnapshot":
        """Factory for an unsafe Docker configuration (iptables NOT disabled)."""
        return cls(
            installed=True,
            iptables_disabled=False,
            daemon_json_exists=False,
            exposed_ports=exposed_ports or [],
        )

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_docker(
    snapshot: DockerSnapshot,
    network_context: str = "local",
    t: TranslationFunc | None = None,
) -> CheckResult:
    """
    Evaluate Docker security snapshot and return findings.

    Args:
        snapshot:        DockerSnapshot from the system.
        network_context: "local" or "public".
        t:               Translation function.

    Returns:
        CheckResult with Docker findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.installed:
        result.info(message=_t("docker.not_installed"), key="docker.not_installed")
        return result

    # iptables bypass check
    if snapshot.iptables_disabled:
        result.ok(message=_t("docker.iptables_disabled"), key="docker.iptables_disabled")
    else:
        result.warn(
            message=_t("docker.iptables_bypass"),
            nature="improvement",
            key="docker.iptables_bypass",
        )
        result.info(message=_t("docker.iptables_bypass_detail1"), key="docker.iptables_bypass_detail1")
        result.info(message=_t("docker.iptables_bypass_detail2"), key="docker.iptables_bypass_detail2")
        result.info(message=_t("docker.iptables_bypass_detail3"), key="docker.iptables_bypass_detail3")
        result.info(message=_t("docker.iptables_bypass_docs"), key="docker.iptables_bypass_docs")
        points = 1 if network_context in ("public", "ddns") else 0
        if points:
            result.add_deduction(
                reason=_t("docker.iptables_bypass"),
                points=points,
                context=network_context,
                key="docker.iptables_bypass",
            )

    # Exposed container ports
    public_ports = [p for p in snapshot.exposed_ports if p.is_public]

    if not snapshot.exposed_ports:
        result.ok(message=_t("docker.no_containers"), key="docker.no_containers")
    elif not public_ports:
        result.ok(message=_t("docker.no_public_ports"), key="docker.no_public_ports")
    else:
        for port in public_ports:
            if not snapshot.iptables_disabled:
                # Port truly bypassing UFW — escalate to alert
                result.alert(
                    message=(
                        f"{port.container_name}: {port.port_proto} "
                        f"→ {port.container_port}/{port.proto} "
                        f"({_t('docker.exposed_bypass_ufw')})"
                    ),
                    nature="action",
                    key="docker.exposed_bypass_ufw",
                )
            else:
                result.warn(
                    message=(
                        f"{port.container_name}: {port.port_proto} "
                        f"→ {port.container_port}/{port.proto}"
                    ),
                    nature="improvement",
                    key="docker.exposed_port",
                )
            if not snapshot.iptables_disabled:
                result.add_deduction(
                    reason=_t("deduction.docker_bypass",
                              container=port.container_name,
                              port=port.port_proto),
                    points=2 if network_context in ("public", "ddns") else 1,
                    context=network_context,
                    key="docker.exposed_bypass_ufw",
                )

    return result

# ---------------------------------------------------------------------------
# System helpers
# ---------------------------------------------------------------------------

def _check_daemon_json() -> tuple[bool, bool]:
    """
    Read /etc/docker/daemon.json and check if iptables is disabled.

    Returns:
        Tuple of (file_exists: bool, iptables_disabled: bool).
    """
    try:
        content = DAEMON_JSON_PATH.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return False, False
    except OSError as exc:
        logger.warning("Cannot read %s: %s", DAEMON_JSON_PATH, exc)
        return True, False

    try:
        config = json.loads(content)
        iptables_disabled = config.get("iptables") is False
        return True, iptables_disabled
    except json.JSONDecodeError as exc:
        logger.warning("Cannot parse %s: %s", DAEMON_JSON_PATH, exc)
        return True, False

def _get_exposed_ports() -> list[ExposedPort]:
    """
    List ports exposed by running Docker containers.

    Returns:
        List of ExposedPort objects.
    """
    output = _run(
        "docker", "ps", "--format",
        "{{.Names}}\t{{.Ports}}"
    )
    if not output.strip():
        return []

    ports: list[ExposedPort] = []
    seen: set[tuple[str, int, str]] = set()  # (container_name, host_port, proto)

    for line in output.strip().splitlines():
        parts = line.split("\t", 1)
        if len(parts) < 2:
            continue
        container_name = parts[0].strip()
        ports_str = parts[1].strip()

        if not ports_str:
            continue

        for port_entry in ports_str.split(", "):
            parsed = _parse_port_entry(container_name, port_entry)
            if parsed:
                key = (parsed.container_name, parsed.host_port, parsed.proto)
                if key not in seen:
                    seen.add(key)
                    ports.append(parsed)

    return ports

def _parse_port_entry(container_name: str, entry: str) -> ExposedPort | None:
    """
    Parse a Docker port mapping entry.

    Handles all known Docker formats:
      - "0.0.0.0:8080->80/tcp"       IPv4 any
      - "127.0.0.1:8080->80/tcp"     IPv4 loopback
      - ":::8080->80/tcp"            IPv6 any (short form)
      - "[::]:8080->80/tcp"          IPv6 any (bracket form)
      - "[::1]:8080->80/tcp"         IPv6 loopback
      - "80/tcp"                     internal only, no host binding → skip
      - "80/udp"                     internal only → skip

    Returns:
        ExposedPort or None if parsing fails or no host binding.
    """
    entry = entry.strip()

    # Skip internal-only ports (no host binding): "80/tcp", "443/udp"
    if re.match(r"^\d+/(tcp|udp|sctp)$", entry):
        return None

    # IPv4: "host_ip:host_port->container_port/proto"
    ipv4_match = re.match(
        r"^(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+)/(tcp|udp)$",
        entry,
    )
    if ipv4_match:
        return ExposedPort(
            container_name=container_name,
            host_ip=ipv4_match.group(1),
            host_port=int(ipv4_match.group(2)),
            container_port=int(ipv4_match.group(3)),
            proto=ipv4_match.group(4),
        )

    # IPv6 bracket form: "[::]:port->..." or "[::1]:port->..."
    ipv6_bracket = re.match(
        r"^\[([^\]]*)\]:(\d+)->(\d+)/(tcp|udp)$",
        entry,
    )
    if ipv6_bracket:
        return ExposedPort(
            container_name=container_name,
            host_ip=ipv6_bracket.group(1) or "::",
            host_port=int(ipv6_bracket.group(2)),
            container_port=int(ipv6_bracket.group(3)),
            proto=ipv6_bracket.group(4),
        )

    # IPv6 short form: ":::port->..." (Docker shorthand for [::]:port)
    ipv6_short = re.match(
        r"^:{2,3}(\d+)->(\d+)/(tcp|udp)$",
        entry,
    )
    if ipv6_short:
        return ExposedPort(
            container_name=container_name,
            host_ip="::",
            host_port=int(ipv6_short.group(1)),
            container_port=int(ipv6_short.group(2)),
            proto=ipv6_short.group(3),
        )

    # Unknown format — log and skip
    logger.debug("Docker: unrecognised port entry: %r", entry)
    return None

