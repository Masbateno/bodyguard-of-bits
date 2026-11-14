"""v0.36.0 — the OCI configuration of rootless containers, read as root.

Until 0.36.0 BOB counted rootless podman containers (0.33.0, their ``conmon``)
and a rootless dockerd's containers (0.35.0, their shims) and said they were
not examined: the score stayed an upper bound. Nothing is run as the user —
decided with the user on 11 November 2026 — but each container's runtime
reads an OCI ``config.json``, and root can read it where the runtime left it:

- a rootless dockerd's shim (``containerd-shim-runc-v2 -namespace moby``, run
  as the user) works in the container's bundle, inside rootlesskit's private
  mount namespace: the path does not exist from root's, but
  ``/proc/<shim>/cwd/config.json`` reaches it (measured on Linux Mint 22.3,
  docker 29.1.3 + rootlesskit 1.1.1, a10360);
- rootless podman's ``conmon`` names the bundle (``-b``), on disk in the
  user's home; read through ``/proc/<conmon>/root`` so the path resolves in
  conmon's own mount namespace (measured on Fedora 44, podman 5.8.1).

The file belongs to the user and so does every directory above it: it is
opened without following a final symlink, kept only if it is a regular file
owned by the container's user and under 1 MiB — a user cannot make root read
a file that is not theirs through it.

What a shape is worth, measured on both hosts: every container process runs as
the user on the host (in the runtime's user namespace); `--privileged` holds
every capability inside that namespace, but the host's devices keep their
permissions (/dev/sda, /dev/mem refused) and a kernel-wide sysctl is refused;
a host path mounted is read as the user (/etc/shadow refused); `--pid host`
shares the host's PID namespace, which the user sees anyway; `--network host`
is rootlesskit's own network for Docker, the host's network for podman — a
port opened there is the user's, as the ports section already sees it.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

_PROC = Path("/proc")
_CAP_LAST_CAP = Path("/proc/sys/kernel/cap_last_cap")
_MAX_CONFIG = 1 << 20

#: Mounts every runtime adds on its own (destination inside the container).
_RUNTIME_DESTINATIONS = frozenset({
    "/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/run/.containerenv", "/run/secrets", "/dev/shm",
})
#: Mounted at the same path by the runtime for a host namespace (podman: /sys
#: for --network host, /proc for --pid host, measured).
_RUNTIME_SAME_PATH = frozenset({"/sys", "/proc"})


@dataclass(frozen=True)
class RootlessContainer:
    """One rootless container: who runs it, with what, and its shape when its
    configuration was read (``read`` False: not read, the score stays an
    upper bound for it)."""
    user: str
    runtime: str                  # "docker" or "podman"
    name: str
    read: bool
    privileged: bool = False      # every capability, inside its user namespace
    sys_admin: bool = False       # CAP_SYS_ADMIN without being privileged
    host_net: bool = False        # no network namespace of its own
    host_pid: bool = False        # no PID namespace of its own
    host_paths: "tuple[str, ...]" = field(default_factory=tuple)


def _uid(pid: Path) -> "int | None":
    try:
        return int(next(ln for ln in (pid / "status").read_text(errors="replace").splitlines()
                        if ln.startswith("Uid:")).split()[1])
    except (OSError, StopIteration, ValueError, IndexError):
        return None


def _cap_total() -> "int | None":
    """How many capabilities the running kernel has (cap_last_cap + 1)."""
    try:
        return int(_CAP_LAST_CAP.read_text(encoding="ascii", errors="ignore").strip()) + 1
    except (OSError, ValueError):
        return None


def read_config(path: Path, uid: int) -> "dict | None":
    """The container's config.json, or None: not a regular file, not owned by
    *uid*, a final symlink, over 1 MiB, or not a JSON object."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_size > _MAX_CONFIG:
            return None
        chunks, size = [], 0
        while size <= _MAX_CONFIG:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > _MAX_CONFIG:
            return None
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        cfg = json.loads(b"".join(chunks).decode("utf-8", errors="replace"))
    except ValueError:
        return None
    return cfg if isinstance(cfg, dict) else None


def shape(cfg: dict, cap_total: "int | None") -> dict:
    """privileged, sys_admin, host_net, host_pid, host_paths of a config."""
    proc = cfg.get("process") if isinstance(cfg.get("process"), dict) else {}
    caps_obj = proc.get("capabilities") if isinstance(proc.get("capabilities"), dict) else {}
    bounding = caps_obj.get("bounding") if isinstance(caps_obj.get("bounding"), list) else []
    caps = {c for c in bounding if isinstance(c, str)}
    linux = cfg.get("linux") if isinstance(cfg.get("linux"), dict) else {}
    nss = linux.get("namespaces") if isinstance(linux.get("namespaces"), list) else []
    ns_types = {n.get("type") for n in nss if isinstance(n, dict)}
    privileged = cap_total is not None and len(caps) >= cap_total
    paths: "list[str]" = []
    mounts = cfg.get("mounts") if isinstance(cfg.get("mounts"), list) else []
    for m in mounts:
        if not isinstance(m, dict):
            continue
        src, dst = m.get("source"), m.get("destination")
        opts = m.get("options") if isinstance(m.get("options"), list) else []
        if m.get("type") != "bind" and "bind" not in opts and "rbind" not in opts:
            continue
        if not isinstance(src, str) or not isinstance(dst, str) or dst in _RUNTIME_DESTINATIONS:
            continue
        if src == dst and (src in _RUNTIME_SAME_PATH or src.startswith("/dev/")):
            continue                     # a host namespace's /sys or /proc, a device of --privileged
        paths.append(f"{src} -> {dst}")
    return {"privileged": privileged, "sys_admin": "CAP_SYS_ADMIN" in caps and not privileged,
            "host_net": "network" not in ns_types, "host_pid": "pid" not in ns_types,
            "host_paths": tuple(paths)}


def _arg_after(argv: "list[bytes]", *flags: bytes) -> "str | None":
    for i, arg in enumerate(argv[:-1]):
        if arg in flags:
            return argv[i + 1].decode(errors="replace")
    return None


def is_exec_conmon(argv: "list[bytes]") -> bool:
    """A conmon that watches a ``podman exec`` session, not a container: it
    carries ``-e`` / ``--exec`` (measured, podman 5.8.1: the session of a
    ``podman exec -d`` had its own conmon, named after the container)."""
    return b"-e" in argv or b"--exec" in argv


def rootless_containers() -> "list[RootlessContainer]":
    """Every rootless container found in /proc, read or not. A Docker one is a
    shim in Docker's containerd namespace that does not run as root; a podman
    one, a ``conmon`` that does not run as root."""
    import pwd
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return []
    cap_total = _cap_total()
    out: "list[RootlessContainer]" = []
    for pid in pids:
        try:
            argv = (pid / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if not argv or not argv[0]:
            continue
        prog = os.path.basename(argv[0].decode(errors="replace"))
        if prog.startswith("containerd-shim"):
            ns = _arg_after(argv, b"-namespace") or ""
            if not (ns == "moby" or ns.startswith("moby-")):
                continue
            runtime, name = "docker", (_arg_after(argv, b"-id") or "?")[:12]
            config = pid / "cwd" / "config.json"
        elif prog == "conmon":
            if is_exec_conmon(argv):
                continue
            bundle = _arg_after(argv, b"-b", b"--bundle")
            runtime = "podman"
            name = _arg_after(argv, b"-n", b"--name") or (_arg_after(argv, b"-c", b"--cid") or "?")[:12]
            config = pid / "root" / bundle.lstrip("/") / "config.json" if bundle else None
        else:
            continue
        uid = _uid(pid)
        if uid is None or uid == 0:
            continue
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)
        cfg = read_config(config, uid) if config is not None else None
        if cfg is None:
            out.append(RootlessContainer(user=user, runtime=runtime, name=name, read=False))
        else:
            out.append(RootlessContainer(user=user, runtime=runtime, name=name, read=True, **shape(cfg, cap_total)))
    return out
