"""
World-writable and unowned files — a whole-filesystem sweep, ``--exhaustive`` only.

CIS 7.1.11 / 7.1.12 ask for no world-writable file, no world-writable directory
without the sticky bit, and no file whose owner or group no longer exists. Each
is a quiet foothold: a world-writable script or config another account runs is
code injection; a world-writable directory without the sticky bit lets anyone
delete or replace anyone else's files in it; an unowned file is inherited by the
next account created with that UID.

The sweep walks every *local* filesystem (``-xdev`` per mount point; proc, sys,
tmpfs, overlay, squashfs and network filesystems excluded — /tmp and /dev/shm
are tmpfs and world-writable by design) and prunes container storage, whose
image layers are full of world-writable /tmp directories that belong to the
images, not the host. It is O(files on disk), tens of seconds on a desktop,
hence ``--exhaustive``.

Doctrine:
  - **INFO-only.** A world-writable file may be deliberate (a shared drop
    directory), and BOB cannot tell; it lists, it does not score.
  - **Not swept ≠ clean.** A timeout, an unreadable subtree or a missing
    ``find`` withholds the OK. BusyBox ``find`` (Alpine) has no ``-nouser``:
    the unowned sweep is then reported as not assessed rather than as empty.
  - **Bounded + group-killed**, as package_integrity.
"""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import _C_LOCALE_ENV, TranslationFunc, _identity_t
from bob.checks.disk import _NETWORK_FS_TYPES, _PSEUDO_FS_TYPES
from bob._atomic import read_text_capped
from bob.scoring import CheckResult

_MOUNTS = Path("/proc/self/mounts")
_TIMEOUT = 1800          # same ceiling as package_integrity: bounds a wedge, not a slow sweep
_SAMPLE = 12

#: Container storage: image layers, not host files.
_PRUNE = ("/var/lib/docker", "/var/lib/containers", "/var/lib/lxc", "/var/lib/lxd",
          "*/.local/share/containers")

_SKIP_FS = _PSEUDO_FS_TYPES | _NETWORK_FS_TYPES | {"autofs"}


def _local_roots() -> "list[str]":
    """Mount points of local, on-disk filesystems."""
    try:
        text = read_text_capped(_MOUNTS, encoding="utf-8", errors="replace")
    except OSError:
        return ["/"]
    roots: "list[str]" = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 3:
            continue
        mp, fstype = f[1].replace("\\040", " "), f[2]
        if fstype in _SKIP_FS or fstype.startswith("fuse."):
            continue
        if mp not in roots:
            roots.append(mp)
    return roots or ["/"]


def _is_gnu_find(find: str) -> bool:
    try:
        r = subprocess.run([find, "--version"], capture_output=True, text=True,
                           timeout=10, env=_C_LOCALE_ENV)
        return r.returncode == 0 and "GNU" in r.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def build_command(find: str, roots: "list[str]", gnu: bool) -> "list[str]":
    prune: "list[str]" = ["("]
    for i, p in enumerate(_PRUNE):
        prune += (["-o"] if i else []) + ["-path", p]
    prune += [")", "-prune", "-o"]
    if gnu:
        tail = ["(", "-type", "f", "-perm", "-0002", "-printf", "F %p\\0", ")", "-o",
                "(", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000",
                "-printf", "D %p\\0", ")", "-o",
                "(", "(", "-nouser", "-o", "-nogroup", ")", "-printf", "U %p\\0", ")"]
    else:
        tail = ["(", "-type", "f", "-o", "-type", "d", ")", "-perm", "-0002", "-print0"]
    return [find, *roots, "-xdev", *prune, *tail]


@dataclass
class WorldWritableSnapshot:
    """
    Args:
        ww_files:   regular files writable by everyone.
        ww_dirs:    directories writable by everyone, without the sticky bit.
        unowned:    files whose owner or group has no account (GNU find only).
        latent:     world-writable files and non-sticky directories that other
                    accounts cannot reach — some parent directory denies them
                    traversal (o-x). Writable the day that parent opens up;
                    not today. (v0.24.0 — "any account can change these" was
                    said of files behind a 0750 home.)
        unowned_assessed: False under BusyBox find (no -nouser/-nogroup).
        partial:    find could not enter some directory.
        timed_out:  the sweep hit the ceiling and was killed.
        no_find:    no find(1) on the host.
    """
    ww_files:         "list[str]" = field(default_factory=list)
    ww_dirs:          "list[str]" = field(default_factory=list)
    unowned:          "list[str]" = field(default_factory=list)
    latent:           "list[str]" = field(default_factory=list)
    unowned_assessed: bool = True
    partial:          bool = False
    timed_out:        bool = False
    no_find:          bool = False

    @classmethod
    def from_system(cls) -> "WorldWritableSnapshot":
        snap = cls()
        find = shutil.which("find")
        if not find:
            snap.no_find = True
            return snap
        gnu = _is_gnu_find(find)
        snap.unowned_assessed = gnu
        try:
            proc = subprocess.Popen(build_command(find, _local_roots(), gnu),
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    start_new_session=True, env=_C_LOCALE_ENV)
        except OSError:
            snap.no_find = True
            return snap
        try:
            out, _ = proc.communicate(timeout=_TIMEOUT)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
            snap.timed_out = True
            return snap
        snap.partial = proc.returncode != 0
        snap._parse(out, gnu)
        snap._split_unreachable()
        return snap

    def _split_unreachable(self) -> None:
        """Move world-writable paths no other account can reach into ``latent``."""
        cache: "dict[str, bool]" = {}

        def traversable(d: str) -> bool:
            if d not in cache:
                cache[d] = _traversable(d)
            return cache[d]

        def reachable(path: str) -> bool:
            parent = os.path.dirname(path)
            while parent and parent != "/":
                if not traversable(parent):
                    return False
                parent = os.path.dirname(parent)
            return True

        for lst in (self.ww_files, self.ww_dirs):
            keep = [p for p in lst if reachable(p)]
            kept = set(keep)
            self.latent.extend(p for p in lst if p not in kept)
            lst[:] = keep
        self.latent.sort()

    def _parse(self, out: bytes, gnu: bool) -> None:
        for raw in out.split(b"\0"):
            if not raw:
                continue
            text = raw.decode("utf-8", "replace")
            if gnu:
                tag, _, path = text.partition(" ")
                {"F": self.ww_files, "D": self.ww_dirs, "U": self.unowned}.get(
                    tag, []).append(path)
            else:
                # BusyBox: classify and drop sticky directories here.
                try:
                    st = os.lstat(text)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    self.ww_files.append(text)
                elif stat.S_ISDIR(st.st_mode) and not st.st_mode & stat.S_ISVTX:
                    self.ww_dirs.append(text)
        for lst in (self.ww_files, self.ww_dirs, self.unowned):
            lst.sort()


def _traversable(directory: str) -> bool:
    """Other accounts may traverse *directory* (o+x). Unknown counts as yes:
    BOB never claims a door is shut that it could not look at."""
    try:
        return bool(os.stat(directory).st_mode & stat.S_IXOTH)
    except OSError:
        return True


def _sample(paths: "list[str]") -> str:
    shown = ", ".join(paths[:_SAMPLE])
    return shown + (f" (+{len(paths) - _SAMPLE} more)" if len(paths) > _SAMPLE else "")


def check_world_writable(snapshot: WorldWritableSnapshot,
                         t: "TranslationFunc | None" = None) -> CheckResult:
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.no_find:
        result.info(message=_t("world_writable.unknown"), key="world_writable.unknown")
        return result
    if snapshot.timed_out:
        result.info(message=_t("world_writable.timed_out", seconds=_TIMEOUT),
                    key="world_writable.timed_out")
        return result

    if snapshot.ww_files:
        result.info(message=_t("world_writable.files", count=len(snapshot.ww_files),
                               paths=_sample(snapshot.ww_files)),
                    detail=_t("world_writable.files_detail"),
                    key="world_writable.files")
    if snapshot.ww_dirs:
        result.info(message=_t("world_writable.dirs", count=len(snapshot.ww_dirs),
                               paths=_sample(snapshot.ww_dirs)),
                    detail=_t("world_writable.dirs_detail"),
                    key="world_writable.dirs")
    if snapshot.unowned:
        result.info(message=_t("world_writable.unowned", count=len(snapshot.unowned),
                               paths=_sample(snapshot.unowned)),
                    detail=_t("world_writable.unowned_detail"),
                    key="world_writable.unowned")
    if snapshot.latent:
        result.info(message=_t("world_writable.latent", count=len(snapshot.latent),
                               paths=_sample(snapshot.latent)),
                    detail=_t("world_writable.latent_detail"),
                    key="world_writable.latent")
    if not snapshot.unowned_assessed:
        result.info(message=_t("world_writable.unowned_not_assessed"),
                    key="world_writable.unowned_not_assessed")
    if snapshot.partial:
        result.info(message=_t("world_writable.partial"), key="world_writable.partial")

    if not (snapshot.ww_files or snapshot.ww_dirs or snapshot.unowned or snapshot.latent
            or snapshot.partial or not snapshot.unowned_assessed):
        result.ok(message=_t("world_writable.ok"), key="world_writable.ok")
    return result
