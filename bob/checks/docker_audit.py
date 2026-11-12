"""
Container security audit for BOB (CHECK 38).

Inspects running containers for dangerous security misconfigurations:
  - Privileged containers     (--privileged)
  - Runtime socket in containers (docker.sock / podman.sock mounted)
  - User namespace remapping  (userns-remap in daemon.json — Docker only)
  - Containers running as root

Supports **Docker and Podman**. Podman's CLI is Docker-compatible — `podman ps`
and `podman inspect` emit the same JSON shape (HostConfig.Privileged,
NetworkMode, Mounts, Config.User) — so one parser serves both. Before v0.20.3
this was Docker-only: on a real Fedora 44 a `podman run --privileged` container
was completely invisible (measured). Since v0.33.0 every runtime root can
ask is asked, and a container two of them report is counted once.

The UFW bypass / iptables / exposed-port audit is handled by the existing
docker.py (ANALYSE DOCKER section).  This check focuses on container hardening.

Split:
  1. DockerAuditSnapshot.from_system() — inspects live containers via CLI.
  2. check_docker_audit(snapshot)      — pure logic, returns CheckResult.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _C_LOCALE_ENV, _command_exists, _identity_t, service_restart_cmd
from bob.scoring import CheckResult
from bob._atomic import read_text_capped


_DAEMON_JSON = Path("/etc/docker/daemon.json")
_DOCKER_SOCK = "/var/run/docker.sock"
_INSPECT_TIMEOUT = 20  # seconds

# Container runtimes BOB can inspect, in preference order. Both expose a
# Docker-compatible `ps -q` / `inspect` surface, so the parser is shared.
_RUNTIMES = ("docker", "podman")
# Each runtime's control socket — mounting it inside a container is
# root-equivalent on the host, whichever runtime it belongs to.
_RUNTIME_SOCKETS = {
    "docker": "/var/run/docker.sock",
    "podman": "/run/podman/podman.sock",
}


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
    runtime:                   str       = ""
    running_count:             int       = 0
    privileged_containers:     list[str] = field(default_factory=list)
    socket_mounted_containers: list[str] = field(default_factory=list)
    root_containers:           list[str] = field(default_factory=list)
    host_network_containers:   list[str] = field(default_factory=list)
    userns_remap:              bool      = False
    scan_error:                bool      = False
    #: v0.33.0 — every runtime present was asked (Docker only, before, when
    #: both were installed); which runtime holds each container named above;
    #: the runtimes whose listing failed (a stopped dockerd read as "no
    #: container"); the rootless podman containers seen in /proc, by user.
    runtimes:                  list[str] = field(default_factory=list)
    container_runtime:         dict      = field(default_factory=dict)
    failed_runtimes:           list[str] = field(default_factory=list)
    rootless_containers:       dict      = field(default_factory=dict)
    #: v0.34.0 — the accounts in the ``docker`` group (listed, or with it as
    #: their primary group) and whether a Docker socket gives that group
    #: write access now: "The docker group grants root-level privileges to
    #: the user" (Docker's post-install documentation). None: not read.
    docker_group_members:      list[str] = field(default_factory=list)
    docker_socket_group_rw:    "bool | None" = False
    #: v0.34.0, after review — the members the group's member list names:
    #: `gpasswd -d` removes those only; an account whose primary group is
    #: docker is not in that list.
    docker_group_listed:       list[str] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "DockerAuditSnapshot":
        """Inspect running containers via Docker and Podman. Never raises.

        v0.33.0 — every runtime present, not the first found: on a host with
        both, Podman's containers were never asked about. A container both
        list (podman-docker's ``docker`` runs podman) counts once, by Id."""
        runtimes = [rt for rt in _RUNTIMES if _command_exists(rt)]
        rootless = _rootless_podman()
        members, socket_rw, listed = _docker_group()
        if not runtimes:
            return cls(runtime="", docker_installed=False, rootless_containers=rootless,
                       docker_group_members=members, docker_socket_group_rw=socket_rw,
                       docker_group_listed=listed)
        is_docker = "docker" in runtimes
        userns_remap = _read_userns_remap() if is_docker else False
        snap = cls(runtime=runtimes[0], docker_installed=is_docker, runtimes=runtimes,
                   userns_remap=userns_remap, rootless_containers=rootless,
                   docker_group_members=members, docker_socket_group_rw=socket_rw,
                   docker_group_listed=listed)
        seen: "set[str]" = set()
        for rt in runtimes:
            containers = _inspect(rt)
            if containers is None:
                snap.failed_runtimes.append(rt)
                continue
            sock_path = _RUNTIME_SOCKETS.get(rt, _DOCKER_SOCK)
            for c in containers:
                cid = c.get("Id", "")
                if cid and cid in seen:
                    continue
                seen.add(cid)
                name = (c.get("Name", "").lstrip("/") or cid[:12])
                snap.container_runtime[name] = rt
                snap.running_count += 1
                host_config = c.get("HostConfig", {})
                if host_config.get("Privileged", False):
                    snap.privileged_containers.append(name)
                for mount in c.get("Mounts", []):
                    if mount.get("Source") in (_DOCKER_SOCK, sock_path):
                        snap.socket_mounted_containers.append(name)
                        break
                # Podman reports the host network as "host"; Docker too.
                if host_config.get("NetworkMode") == "host":
                    snap.host_network_containers.append(name)
                user = c.get("Config", {}).get("User", "")
                if not user or user in ("root", "0", "0:0", "0:root"):
                    snap.root_containers.append(name)
        # Nothing could be listed at all: the check says so and asserts nothing.
        snap.scan_error = len(snap.failed_runtimes) == len(runtimes)
        for lst in (snap.privileged_containers, snap.socket_mounted_containers,
                    snap.root_containers, snap.host_network_containers):
            lst.sort()
        return snap


def _inspect(runtime: str) -> "list[dict] | None":
    """The running containers of *runtime*, inspected; None when it could not
    be asked (v0.33.0: a failed ``ps`` too, which read as "no container")."""
    try:
        proc = subprocess.run([runtime, "ps", "-q"], capture_output=True, text=True,
                              timeout=10, env=_C_LOCALE_ENV)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    ids = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not ids:
        return []
    try:
        proc = subprocess.run([runtime, "inspect"] + ids, capture_output=True, text=True,
                              timeout=_INSPECT_TIMEOUT, env=_C_LOCALE_ENV)
        if proc.returncode != 0:
            return None
        return json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return None


_PROC = Path("/proc")
#: v0.34.0 — where dockerd (or its systemd socket unit) listens.
_DOCKER_SOCKETS = (Path("/var/run/docker.sock"), Path("/run/docker.sock"))


def _docker_group() -> "tuple[list[str], bool | None, list[str]]":
    """v0.34.0 — the members of the ``docker`` group (its member list and the
    accounts whose primary group it is), and whether a Docker socket is a
    socket owned by that group with group write: then each member can drive
    dockerd, which runs as root. ([], False, []) without such a group; the
    second value None when a socket could not be read; the third, the
    members the group's own list names."""
    import grp
    import pwd
    import stat
    try:
        group = grp.getgrnam("docker")
    except KeyError:
        return [], False, []
    listed = sorted(set(group.gr_mem))
    members = set(group.gr_mem)
    try:
        members |= {u.pw_name for u in pwd.getpwall() if u.pw_gid == group.gr_gid}
    except OSError:
        pass
    rw: "bool | None" = False
    for sock in _DOCKER_SOCKETS:
        try:
            st = os.stat(sock)
        except FileNotFoundError:
            continue
        except OSError:
            rw = None
            continue
        if stat.S_ISSOCK(st.st_mode) and st.st_gid == group.gr_gid and st.st_mode & stat.S_IWGRP:
            # Measured (Fedora 44, moby-engine): with dockerd and docker.socket
            # stopped the socket file stays, srw-rw---- docker, and `docker
            # ps` as a member is refused. Only a listener makes it a way in.
            listening = _unix_listening(str(sock))
            if listening:
                return sorted(members), True, listed
            if listening is None:
                rw = None
    return sorted(members), rw, listed


_PROC_NET_UNIX = Path("/proc/net/unix")
_SO_ACCEPTCON = 0x10000


def _unix_listening(path: str) -> "bool | None":
    """v0.34.0 — whether a process listens on the Unix socket *path* (the
    kernel's listening flag in /proc/net/unix, the path resolved: /var/run is
    /run). None when /proc/net/unix cannot be read."""
    want = {path, os.path.realpath(path)}
    try:
        lines = _PROC_NET_UNIX.read_text(errors="replace").splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) >= 8 and parts[7] in want:
            try:
                if int(parts[3], 16) & _SO_ACCEPTCON:
                    return True
            except ValueError:
                continue
    return False


def _rootless_podman() -> "dict[str, int]":
    """v0.33.0 — the rootless podman containers running, by user: each has a
    ``conmon`` monitor owned by that user (root's are podman's own, asked
    above). Read from /proc only — nothing is run as the user (decided with
    the user, 11 November 2026: running podman for each account could write
    in its home and depends on its session)."""
    import pwd
    counts: "dict[str, int]" = {}
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return counts
    for pid in pids:
        try:
            if (pid / "comm").read_text(errors="replace").strip() != "conmon":
                continue
            uid_line = next(ln for ln in (pid / "status").read_text(errors="replace").splitlines()
                            if ln.startswith("Uid:"))
            uid = int(uid_line.split()[1])
        except (OSError, StopIteration, ValueError, IndexError):
            continue
        if uid == 0:
            continue
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)
        counts[user] = counts.get(user, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

#: The dockremap user and group, created here when missing. Measured on Alpine
#: 3.24 with docker 29.8.2: dockerd logged "cannot add user; no useradd/adduser
#: binary found" with BusyBox adduser on its PATH, and stopped (docker 28.3.3 on
#: Alpine 3.22 had created it); with the user there it started remapped.
_DOCKREMAP_USER = (
    "{ id dockremap >/dev/null 2>&1 || if command -v useradd >/dev/null 2>&1; "
    "then sudo useradd -r -U -M -s /bin/false dockremap; "
    "else sudo addgroup -S dockremap && sudo adduser -S -D -H -G dockremap -s /bin/false dockremap; fi; }"
)

def _dockremap_range(path: str) -> str:
    """Give dockremap a subordinate range of its own in *path*, unless it has one.

    The range starts after the highest one already there (100000 at least), so
    a remapped container's root shares no host UID with another user's
    namespaces. Docker reuses a range it finds for dockremap - measured on
    Alpine 3.22, where the files did not exist and this line created them.
    """
    return (f"{{ grep -qiE '^dockremap:' {path} 2>/dev/null || cat {path} 2>/dev/null | "
            "awk -F: 'BEGIN{m=100000} NF>=3 && $2+$3>m {m=$2+$3} END{print \"dockremap:\" m \":65536\"}' | "
            f"sudo tee -a {path} >/dev/null; }}")


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

    # v0.33.0 — what was not examined, said first and whatever follows.
    if snapshot.rootless_containers:
        users = ", ".join(f"{u} ({n})" for u, n in sorted(snapshot.rootless_containers.items()))
        result.info(
            message=_t("docker_hardening.rootless_unexamined",
                       count=sum(snapshot.rootless_containers.values()), users=users),
            detail=_t("docker_hardening.rootless_unexamined_detail"),
            key="docker_hardening.rootless_unexamined",
            template_vars={"count": sum(snapshot.rootless_containers.values()), "users": users},
        )
    if snapshot.failed_runtimes and not snapshot.scan_error:
        result.info(
            message=_t("docker_hardening.runtime_unreachable", runtimes=", ".join(snapshot.failed_runtimes)),
            key="docker_hardening.runtime_unreachable",
            template_vars={"runtimes": ", ".join(snapshot.failed_runtimes)},
        )
    # v0.34.0 — the accounts the docker group makes root-equivalent.
    if snapshot.docker_group_members:
        users = ", ".join(snapshot.docker_group_members)
        if snapshot.docker_socket_group_rw:
            result.warn_with_deduction(
                key="docker_hardening.docker_group_root",
                message=_t("docker_hardening.docker_group_root",
                           count=len(snapshot.docker_group_members), users=users),
                reason=_t("docker_hardening.docker_group_root_reason", users=users),
                points=2,
                nature="action",
                detail=_t("docker_hardening.docker_group_root_detail"),
                # After review: only the listed members — `gpasswd -d` cannot
                # remove a primary group (the detail says `usermod -g`).
                cmd=" && ".join(f"sudo gpasswd -d {shlex.quote(u)} docker" for u in snapshot.docker_group_listed),
                cmd_type="fix",
                template_vars={"count": len(snapshot.docker_group_members), "users": users},
            )
        elif snapshot.docker_socket_group_rw is None:
            # After review: a socket that could not be read is unknown, not
            # "nothing listens" — the −2 is unknown, not absent (a ceiling).
            result.info(
                message=_t("docker_hardening.docker_group_unknown",
                           count=len(snapshot.docker_group_members), users=users),
                key="docker_hardening.docker_group_unknown",
                template_vars={"count": len(snapshot.docker_group_members), "users": users},
            )
        else:
            result.info(
                message=_t("docker_hardening.docker_group_dormant",
                           count=len(snapshot.docker_group_members), users=users),
                key="docker_hardening.docker_group_dormant",
                template_vars={"count": len(snapshot.docker_group_members), "users": users},
            )
    if not snapshot.runtimes and not snapshot.runtime and (snapshot.rootless_containers
                                                           or snapshot.docker_group_members):
        return result                       # no runtime root can ask: only the rootless ones were seen

    if snapshot.scan_error:
        result.info(
            message=_t("docker_hardening.scan_error"),
            key="docker_hardening.scan_error",
        )
        return result

    # No containers running — nothing critical to report
    if snapshot.running_count == 0:
        # v0.34.0 — the runtimes asked, named: on a host with Podman only the
        # section read "Docker" beside "Docker not installed".
        _asked = ", ".join(snapshot.runtimes or ([snapshot.runtime] if snapshot.runtime else [])) or "—"
        result.ok(
            message=_t("docker_hardening.no_containers", runtimes=_asked),
            key="docker_hardening.no_containers",
            template_vars={"runtimes": _asked},
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
            cmd=f"{snapshot.container_runtime.get(first, snapshot.runtime or 'docker')} inspect --format '{{{{.HostConfig.Privileged}}}}' {first}",
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
            cmd=f"{snapshot.container_runtime.get(first, snapshot.runtime or 'docker')} inspect --format '{{{{json .Mounts}}}}' {first}",
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

    # --- userns-remap (INFO only, Docker-only) ---
    # Podman has no daemon.json userns-remap knob (it is rootless-capable by
    # design and remaps per-container), so this section is meaningless there —
    # but the root/host-network sections below still apply to Podman.
    if snapshot.docker_installed:
        if not snapshot.userns_remap:
            result.info(
                message=_t("docker_hardening.userns_not_configured"),
                detail=_t("docker_hardening.userns_not_configured_detail"),
                # create-if-absent only: never clobbers an existing daemon.json (it
                # may already hold log-driver / registry-mirrors / iptables keys).
                # If the file exists the command is a no-op — the detail explains the
                # manual merge. No human-language text in the cmd (would leak locale).
                # v0.25.0: the restart in this host's init system — measured on
                # Alpine (OpenRC), it said `systemctl restart docker`.
                # And /etc/docker first: Alpine's docker package does not create
                # it, so `tee` failed there ("No such file or directory"). Nor
                # does Alpine have /etc/subuid or /etc/subgid: measured, dockerd
                # then logged "Can't create ID mappings" and stopped answering
                # while OpenRC said "started" and the command exited 0. Nor can
                # the range be left to docker where the files exist: measured
                # on Mint 22.3 (docker 29.1.3), it gave dockremap 100000:65536,
                # the range the first user account already held. See _dockremap_range.
                cmd=('test -f /etc/docker/daemon.json || { sudo mkdir -p /etc/docker && '
                     'echo \'{"userns-remap": "default"}\' | sudo tee /etc/docker/daemon.json >/dev/null && '
                     f'{_DOCKREMAP_USER} && {_dockremap_range("/etc/subuid")} && {_dockremap_range("/etc/subgid")} && '
                     f'{service_restart_cmd("docker")}; }}'),
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
        config = json.loads(read_text_capped(_DAEMON_JSON, encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return False
    # `[]`, `"text"` and `null` are valid JSON without a .get(); catching only
    # JSONDecodeError let them raise AttributeError out of the snapshot.
    if not isinstance(config, dict):
        return False
    return bool(config.get("userns-remap", ""))
