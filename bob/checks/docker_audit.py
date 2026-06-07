"""
Docker container security audit for BOB (CHECK 38).

Inspects running Docker containers for dangerous security misconfigurations:
  - Privileged containers     (--privileged)
  - Docker socket in containers (/var/run/docker.sock mounted)
  - User namespace remapping  (userns-remap in daemon.json)
  - Containers running as root

The UFW bypass / iptables / exposed-port audit is handled by the existing
docker.py (ANALYSE DOCKER section).  This check focuses on container hardening.

Split:
  1. DockerAuditSnapshot.from_system() — inspects live containers via CLI.
  2. check_docker_audit(snapshot)      — pure logic, returns CheckResult.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _C_LOCALE_ENV, _command_exists, _identity_t
from bob.scoring import CheckResult


_DAEMON_JSON = Path("/etc/docker/daemon.json")
_DOCKER_SOCK = "/var/run/docker.sock"
_INSPECT_TIMEOUT = 20  # seconds


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class DockerAuditSnapshot:
    """
    Container security state from the live Docker environment.

    Args:
        docker_installed:            True if the docker binary exists.
        running_count:               Number of currently running containers.
        privileged_containers:       Containers launched with --privileged.
        socket_mounted_containers:   Containers with /var/run/docker.sock mounted.
        root_containers:             Containers running as uid 0 (or no USER set).
        host_network_containers:     Containers using the host network namespace.
        userns_remap:                True if userns-remap is set in daemon.json.
        scan_error:                  True if docker inspect failed (daemon down, etc.).
    """
    docker_installed:          bool      = False
    running_count:             int       = 0
    privileged_containers:     list[str] = field(default_factory=list)
    socket_mounted_containers: list[str] = field(default_factory=list)
    root_containers:           list[str] = field(default_factory=list)
    host_network_containers:   list[str] = field(default_factory=list)
    userns_remap:              bool      = False
    scan_error:                bool      = False

    @classmethod
    def from_system(cls) -> "DockerAuditSnapshot":
        """Inspect running containers. Never raises."""
        if not _command_exists("docker"):
            return cls(docker_installed=False)

        userns_remap = _read_userns_remap()

        # Get running container IDs
        try:
            proc = subprocess.run(
                ["docker", "ps", "-q"],
                capture_output=True, text=True,
                timeout=10, env=_C_LOCALE_ENV,
            )
            container_ids = [
                line.strip() for line in proc.stdout.splitlines() if line.strip()
            ]
        except (subprocess.TimeoutExpired, OSError):
            return cls(docker_installed=True, userns_remap=userns_remap, scan_error=True)

        if not container_ids:
            return cls(docker_installed=True, userns_remap=userns_remap)

        # Bulk inspect — one call for all containers
        privileged:     list[str] = []
        sock_mounted:   list[str] = []
        root_user:      list[str] = []
        host_net:       list[str] = []

        try:
            proc = subprocess.run(
                ["docker", "inspect"] + container_ids,
                capture_output=True, text=True,
                timeout=_INSPECT_TIMEOUT, env=_C_LOCALE_ENV,
            )
            if proc.returncode != 0:
                raise subprocess.SubprocessError(
                    f"docker inspect exited {proc.returncode}: {proc.stderr.strip()}"
                )
            containers = json.loads(proc.stdout)
            for c in containers:
                name = (c.get("Name", "").lstrip("/") or c.get("Id", "")[:12])
                host_config = c.get("HostConfig", {})

                if host_config.get("Privileged", False):
                    privileged.append(name)

                for mount in c.get("Mounts", []):
                    if mount.get("Source") == _DOCKER_SOCK:
                        sock_mounted.append(name)
                        break

                if host_config.get("NetworkMode") == "host":
                    host_net.append(name)

                user = c.get("Config", {}).get("User", "")
                if not user or user in ("root", "0", "0:0", "0:root"):
                    root_user.append(name)

        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            return cls(
                docker_installed=True,
                running_count=len(container_ids),
                userns_remap=userns_remap,
                scan_error=True,
            )

        return cls(
            docker_installed=True,
            running_count=len(container_ids),
            privileged_containers=sorted(privileged),
            socket_mounted_containers=sorted(sock_mounted),
            root_containers=sorted(root_user),
            host_network_containers=sorted(host_net),
            userns_remap=userns_remap,
        )


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_docker_audit(snapshot: DockerAuditSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check Docker container security configuration.

    Deductions:
      - 1+ privileged container(s):            −1 pt
      - Docker socket mounted in a container:  −1 pt

    INFO-only (no deduction):
      - userns-remap not configured
      - Containers running as root
      - Containers using host network mode
      - Scan error (daemon not responding)
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.scan_error:
        result.info(
            message=_t("docker_hardening.scan_error"),
            key="docker_hardening.scan_error",
        )
        return result

    # No containers running — nothing critical to report
    if snapshot.running_count == 0:
        result.ok(
            message=_t("docker_hardening.no_containers"),
            key="docker_hardening.no_containers",
        )
        return result

    # --- Privileged containers ---
    if snapshot.privileged_containers:
        names = ", ".join(snapshot.privileged_containers[:5])
        suffix = (
            f" (+{len(snapshot.privileged_containers) - 5} more)"
            if len(snapshot.privileged_containers) > 5 else ""
        )
        first = snapshot.privileged_containers[0]
        result.warn_with_deduction(
            key="docker_hardening.privileged",
            message=_t(
                "docker_hardening.privileged",
                count=len(snapshot.privileged_containers),
                containers=names + suffix,
            ),
            reason=_t(
                "docker_hardening.privileged_reason",
                count=len(snapshot.privileged_containers),
            ),
            points=1,
            detail=_t("docker_hardening.privileged_detail"),
            cmd=f"docker inspect --format '{{{{.HostConfig.Privileged}}}}' {first}",
            cmd_type="check",
        )

    # --- Docker socket mounted ---
    if snapshot.socket_mounted_containers:
        names = ", ".join(snapshot.socket_mounted_containers[:5])
        first = snapshot.socket_mounted_containers[0]
        result.warn_with_deduction(
            key="docker_hardening.socket_mounted",
            message=_t(
                "docker_hardening.socket_mounted",
                count=len(snapshot.socket_mounted_containers),
                containers=names,
            ),
            reason=_t(
                "docker_hardening.socket_mounted_reason",
                count=len(snapshot.socket_mounted_containers),
            ),
            points=1,
            detail=_t("docker_hardening.socket_mounted_detail"),
            cmd=f"docker inspect --format '{{{{json .Mounts}}}}' {first}",
            cmd_type="check",
        )

    # --- OK if no critical issues ---
    if not snapshot.privileged_containers and not snapshot.socket_mounted_containers:
        result.ok(
            message=_t(
                "docker_hardening.ok",
                count=snapshot.running_count,
            ),
            key="docker_hardening.ok",
        )

    # --- userns-remap (INFO only) ---
    if not snapshot.userns_remap:
        result.info(
            message=_t("docker_hardening.userns_not_configured"),
            detail=_t("docker_hardening.userns_not_configured_detail"),
            cmd='echo \'{"userns-remap": "default"}\' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker',
            cmd_type="fix",
            key="docker_hardening.userns_not_configured",
        )
    else:
        result.ok(
            message=_t("docker_hardening.userns_configured"),
            key="docker_hardening.userns_configured",
        )

    # --- Root containers (INFO only) ---
    if snapshot.root_containers:
        names = ", ".join(snapshot.root_containers[:5])
        suffix = (
            f" (+{len(snapshot.root_containers) - 5} more)"
            if len(snapshot.root_containers) > 5 else ""
        )
        result.info(
            message=_t(
                "docker_hardening.root_containers",
                count=len(snapshot.root_containers),
                containers=names + suffix,
            ),
            detail=_t("docker_hardening.root_containers_detail"),
            key="docker_hardening.root_containers",
        )

    # --- Host network containers (INFO only) ---
    if snapshot.host_network_containers:
        names = ", ".join(snapshot.host_network_containers[:5])
        result.info(
            message=_t(
                "docker_hardening.host_network",
                count=len(snapshot.host_network_containers),
                containers=names,
            ),
            detail=_t("docker_hardening.host_network_detail"),
            key="docker_hardening.host_network",
        )

    return result


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _read_userns_remap() -> bool:
    """Return True if userns-remap is set in /etc/docker/daemon.json."""
    try:
        config = json.loads(_DAEMON_JSON.read_text(encoding="utf-8"))
        return bool(config.get("userns-remap", ""))
    except (OSError, json.JSONDecodeError):
        return False
