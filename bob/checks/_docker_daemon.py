"""v0.35.0 — the system Docker daemon as /proc shows it, without asking it.

Measured on Linux Mint 22.3 with docker.io 29.1.3 (a10350, 12 November 2026):

- dockerd running: the listening socket /run/docker.sock is held by dockerd
  and systemd, both uid 0;
- docker.service stopped, docker.socket active: held by systemd (PID 1) alone —
  and a `docker ps` run by root then STARTED dockerd (inactive → active), so an
  audit that asks the CLI changes the host it audits;
- a process that bound the path as root and dropped to nobody before listening
  holds it as uid 65534: the socket file looked the same (srw-rw---- root
  docker), and a member's `docker ps` was refused.

A Docker container runs under a ``containerd-shim-runc-v2 -namespace moby``
process, with or without dockerd (live-restore keeps them across a daemon stop).
"""

from __future__ import annotations

import os
from pathlib import Path

#: Where a dockerd running as root, or its systemd socket unit, listens.
DOCKER_SOCKETS = (Path("/var/run/docker.sock"), Path("/run/docker.sock"))

_PROC = Path("/proc")
_PROC_NET_UNIX = Path("/proc/net/unix")
_SO_ACCEPTCON = 0x10000


def _listening_inode(path: str) -> "str | None | bool":
    """The inode of the socket listening at *path*; False when none listens;
    None when /proc/net/unix cannot be read. The path is resolved too
    (/var/run is /run)."""
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
                    return parts[6]
            except ValueError:
                continue
    return False


def _holders(inode: str) -> "list[tuple[int, str, int]] | None":
    """(pid, comm, uid) of every process holding socket *inode*; None when
    /proc cannot be listed."""
    target = f"socket:[{inode}]"
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return None
    out = []
    for pid in pids:
        try:
            fds = list((pid / "fd").iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(fd) != target:
                    continue
            except OSError:
                continue
            try:
                comm = (pid / "comm").read_text(errors="replace").strip()
                uid = int(next(ln for ln in (pid / "status").read_text(errors="replace").splitlines()
                               if ln.startswith("Uid:")).split()[1])
            except (OSError, StopIteration, ValueError, IndexError):
                break
            out.append((int(pid.name), comm, uid))
            break
    return out


def socket_listener(path: str) -> "tuple[bool | None, set[int] | None]":
    """Whether a process listens on the Unix socket *path*, and the uids of
    the processes holding it. (None, None) when /proc/net/unix cannot be read;
    (True, None) when a listener exists but its holders could not be found."""
    inode = _listening_inode(path)
    if inode is None:
        return None, None
    if inode is False:
        return False, set()
    holders = _holders(inode)
    if not holders:
        return True, None
    return True, {uid for _pid, _comm, uid in holders}


def system_dockerd_state() -> str:
    """``running``: a dockerd process runs as root. ``socket``: none does, and
    a system Docker socket is held by systemd (PID 1) — docker.socket, which
    starts dockerd on the first request (measured). ``stopped``: no listener,
    or one that is not systemd's. ``unknown``: /proc could not be read; the
    callers then do not ask (asking could start dockerd)."""
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        try:
            if (pid / "comm").read_text(errors="replace").strip() != "dockerd":
                continue
            uid = int(next(ln for ln in (pid / "status").read_text(errors="replace").splitlines()
                           if ln.startswith("Uid:")).split()[1])
        except (OSError, StopIteration, ValueError, IndexError):
            continue
        if uid == 0:
            return "running"
    seen_unreadable = False
    for sock in DOCKER_SOCKETS:
        inode = _listening_inode(str(sock))
        if inode is None:
            seen_unreadable = True
            continue
        if not inode:
            continue
        # Measured: systemd's docker.socket is held by PID 1; a listener of
        # any other process (a non-root one, measured) is not what starts
        # dockerd, and asking it starts nothing.
        holders = _holders(inode)
        if holders is None:
            seen_unreadable = True
        elif any(pid == 1 for pid, _comm, _uid in holders):
            return "socket"
    return "unknown" if seen_unreadable else "stopped"


def _uid(pid: Path) -> "int | None":
    try:
        return int(next(ln for ln in (pid / "status").read_text(errors="replace").splitlines()
                        if ln.startswith("Uid:")).split()[1])
    except (OSError, StopIteration, ValueError, IndexError):
        return None


def _shims() -> "list[tuple[str, int]] | None":
    """(namespace, uid) of each containerd shim running; None when /proc
    cannot be listed."""
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return None
    out = []
    for pid in pids:
        try:
            argv = (pid / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if not argv or not os.path.basename(argv[0].decode(errors="replace")).startswith("containerd-shim"):
            continue
        for i, arg in enumerate(argv[:-1]):
            if arg == b"-namespace":
                uid = _uid(pid)
                if uid is not None:
                    out.append((argv[i + 1].decode(errors="replace"), uid))
                break
    return out


def _is_docker_ns(ns: str) -> bool:
    """Docker's containerd namespace: ``moby``, and the ``moby-<uid>.<gid>``
    ones containerd also listed on the bench host (a10350)."""
    return ns == "moby" or ns.startswith("moby-")


def _moby_shims() -> "list[int] | None":
    """The uid of each containerd shim in Docker's namespaces; None when
    /proc cannot be listed."""
    shims = _shims()
    return None if shims is None else [uid for ns, uid in shims if _is_docker_ns(ns)]


def containerd_elsewhere() -> "dict[str, int]":
    """v0.35.0 — containers containerd runs as root outside Docker's
    namespaces and Kubernetes' (k8s.io, read by the kubernetes section):
    namespace → count. Measured: `ctr -n default run` gave a root shim
    ``-namespace default`` that no section of 0.34.0 saw."""
    out: "dict[str, int]" = {}
    for ns, uid in _shims() or []:
        if uid == 0 and not _is_docker_ns(ns) and ns != "k8s.io":
            out[ns] = out.get(ns, 0) + 1
    return out


def moby_containers() -> "int | None":
    """How many containers of the system Docker run, counted by their
    containerd shim in Docker's namespace (``-namespace moby``) owned by
    root; None when /proc cannot be listed. Asks no daemon. v0.35.0 — a
    rootless dockerd's shims carry the same namespace and run as its user
    (measured): they are not the system daemon's."""
    uids = _moby_shims()
    return None if uids is None else sum(1 for u in uids if u == 0)


def rootless_dockerd() -> "dict[str, int]":
    """v0.35.0 — the users running a rootless dockerd, each with the number
    of its containers (shims in the moby namespace owned by that user).
    Measured on Linux Mint 22.3 (rootlesskit 1.1.1, slirp4netns): dockerd,
    containerd and the container's shim all ran as the user, and the
    container reached the internet with the host's ip_forward at 0."""
    import pwd
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return {}
    users: "dict[int, int]" = {}
    for pid in pids:
        try:
            if (pid / "comm").read_text(errors="replace").strip() != "dockerd":
                continue
        except OSError:
            continue
        uid = _uid(pid)
        if uid not in (None, 0):
            users.setdefault(uid, 0)
    for uid in _moby_shims() or []:
        if uid in users:
            users[uid] += 1
    out = {}
    for uid, n in users.items():
        try:
            name = pwd.getpwuid(uid).pw_name
        except KeyError:
            name = str(uid)
        out[name] = n
    return out
