"""
Privileged /dev device-node permission check for BOB (INFO-only, CIS-adjacent).

A narrow, deliberately cheap look at the permission bits on the device nodes
that hand a process a way around filesystem permissions entirely:

  - ``/dev/mem`` / ``/dev/kmem`` / ``/dev/port`` — direct physical / kernel
    memory access. World-readable leaks kernel memory; world-writable is a
    kernel-integrity compromise.
  - **raw block devices** (``/dev/sda``, ``/dev/nvme0n1``, …) — reading one
    bypasses every file permission on the filesystems it carries; writing one
    corrupts or backdoors them. The default is ``root:disk 0660`` (no world
    access).

Scope is kept tight on purpose: it stats a fixed list of sensitive character
devices plus the block devices already listed in ``/dev`` — it never walks the
filesystem looking for stray device nodes (``find / -type b,c`` is a real
forensic signal but far too costly for a default audit), and it only ever
``stat``s a node, never opens it, so a hostile node cannot block the audit.

Deliberately INFO-only and un-noisy: one aggregated INFO listing the nodes that
are world-accessible, never one finding per node, and no deduction — on a normal
system nothing here is world-accessible and the check is silent-OK. Privileged
``/dev`` *mounts* inside a container are a different surface, already covered by
``container_security``.

Split into:
  1. DevPrivilegedSnapshot.from_system() — collects state (never raises).
  2. check_dev_privileged(snapshot, t)   — pure analysis (INFO-only).
"""

from __future__ import annotations

import os
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult

_DEV = "/dev"

# Fixed sensitive character devices — memory/port access.
_SENSITIVE_CHAR: "tuple[str, ...]" = ("mem", "kmem", "port")

# Block-device basename prefixes that denote a raw disk (whole disk or
# partition — world access to either bypasses filesystem permissions).
_RAW_DISK_PREFIXES: "tuple[str, ...]" = (
    "sd", "nvme", "vd", "mmcblk", "hd", "xvd",
)

_WORLD_READ = 0o004
_WORLD_WRITE = 0o002


def _openness(mode: int) -> "str | None":
    """Return 'writable' / 'readable' / None for the world (other) bits."""
    if mode & _WORLD_WRITE:
        return "writable"
    if mode & _WORLD_READ:
        return "readable"
    return None


@dataclass
class DevPrivilegedSnapshot:
    """State collected about sensitive /dev device-node permissions.

    Args:
        too_open:    list of (node path, "readable"/"writable") for every
                     sensitive device that grants world access.
        dev_read:    True if /dev could be listed; False only when the listing
                     was denied — the honest "unknown", never read as clean.
    """
    too_open: "list[tuple[str, str]]" = field(default_factory=list)
    dev_read: bool = True

    @classmethod
    def from_system(cls) -> "DevPrivilegedSnapshot":
        """Collect world-access on sensitive /dev nodes. Never raises."""
        snap = cls()

        def _consider(path: str) -> None:
            try:
                st = os.stat(path)           # metadata only — never opens/blocks
            except OSError:
                return
            if not (_stat.S_ISCHR(st.st_mode) or _stat.S_ISBLK(st.st_mode)):
                return
            how = _openness(st.st_mode)
            if how is not None:
                snap.too_open.append((path, how))

        # Fixed sensitive character devices.
        for name in _SENSITIVE_CHAR:
            _consider(f"{_DEV}/{name}")

        # Raw block devices currently present in /dev (top level only).
        try:
            names = os.listdir(_DEV)
        except OSError:
            snap.dev_read = False
            return snap
        for name in names:
            if name.startswith(_RAW_DISK_PREFIXES):
                _consider(f"{_DEV}/{name}")

        # Stable, de-duplicated order for the aggregated message.
        snap.too_open = sorted(set(snap.too_open))
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_dev_privileged(snapshot: DevPrivilegedSnapshot,
                         t: TranslationFunc | None = None) -> CheckResult:
    """Analyse DevPrivilegedSnapshot and return findings (INFO-only)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.dev_read:
        result.info(message=_t("dev_privileged.unreadable"),
                    key="dev_privileged.unreadable")
        return result

    if snapshot.too_open:
        listed = ", ".join(f"{p} ({how})" for p, how in snapshot.too_open)
        result.info(
            message=_t("dev_privileged.world_accessible",
                       count=len(snapshot.too_open), nodes=listed),
            detail=_t("dev_privileged.world_accessible_detail"),
            key="dev_privileged.world_accessible",
        )
    else:
        result.ok(message=_t("dev_privileged.locked_down"),
                  key="dev_privileged.locked_down")

    return result
