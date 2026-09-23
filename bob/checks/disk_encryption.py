"""
Storage-encryption (LUKS / dm-crypt) check for BOB.

Full-disk encryption protects **data at rest**: a stolen laptop, a decommissioned
drive, a disk pulled from a server all read as noise instead of files. BOB reports
whether the root filesystem is backed by an encrypted (dm-crypt / LUKS) device.

The verdict is deliberately **profile-gated and never binary** — encryption is a
threat-model decision, not a universal rule:

  - **desktop / workstation** — the physical-theft threat is real and immediate
    (a laptop leaves the building), so an unencrypted root is WARN;
  - **server** — a headless server usually cannot prompt for a passphrase at boot,
    full-disk encryption there needs remote-unlock tooling, and the physical
    threat model is a locked rack, not a coat pocket; so an unencrypted root is
    INFO (worth knowing, not a deduction);
  - **container** — a container has no block devices of its own; data-at-rest is
    the *host's* responsibility, so the check reports "not applicable" and moves
    on;
  - **unknown / unreadable** — never read as clean.

Detection reads the running system, not `/etc/crypttab` intent:

  1. every device-mapper node under `/sys/block/dm-*/dm/uuid` whose UUID starts
     with ``CRYPT-`` is a LUKS/dm-crypt volume;
  2. the device backing ``/`` is read from `/proc/self/mounts` and resolved to its
     dm node (`/dev/mapper/NAME` → `dm-N`);
  3. the dm **stack** is walked through `/sys/block/dm-N/slaves`, so the common
     LVM-on-LUKS layout (a linear mapping sitting on a crypt device) is detected,
     not just a bare crypt mount.

BOB never turns encryption on: enabling full-disk encryption means re-installing
or re-encrypting the volume, which cannot be done unattended. The remediation is
described, not applied.

Score impact:
  - root filesystem encrypted:                    OK
  - root unencrypted, desktop / workstation:      WARN −1 pt
  - root unencrypted, server:                     INFO
  - container profile:                            OK (not applicable)
  - root device could not be resolved:            INFO (unknown)

Split into:
  1. DiskEncryptionSnapshot.from_system() — collects state.
  2. check_disk_encryption(snapshot, t, profile_name) — pure analysis.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    path_exists,
    read_text_capped,
)
from bob.scoring import CheckResult

_MOUNTS = "/proc/self/mounts"
_SYS_BLOCK = "/sys/block"
_CRYPTTAB = "/etc/crypttab"

#: Real block-device prefixes: if root sits directly on one of these it is a plain
#: partition (an encrypted root is always mounted through its dm mapper, never the
#: raw partition), so "not a dm node" means "not encrypted" — a firm False.
_REAL_BLOCK_PREFIXES = ("/dev/sd", "/dev/nvme", "/dev/vd", "/dev/mmcblk",
                        "/dev/xvd", "/dev/hd", "/dev/sr")


@dataclass
class DiskEncryptionSnapshot:
    """State collected about storage encryption.

    Args:
        readable:       False when /proc/self/mounts could not be read.
        root_source:    The device backing ``/`` (as /proc/self/mounts reports it).
        root_encrypted: True/False when resolvable, None when it cannot be told
                        (a pseudo root such as overlay/nfs, or an unreadable stack).
        crypt_volumes:  Mapper names of every LUKS/dm-crypt volume found.
        crypttab_present: True when a non-empty /etc/crypttab exists.
    """
    readable:         bool = True
    root_source:      str = ""
    root_encrypted:   "bool | None" = None
    crypt_volumes:    list[str] = field(default_factory=list)
    crypttab_present: bool = False

    @classmethod
    def from_system(cls) -> "DiskEncryptionSnapshot":
        """Inspect the running device-mapper stack. Never raises."""
        snap = cls()

        # 1. Which dm nodes are crypt targets? (dm name -> mapper name)
        crypt_nodes: set[str] = set()
        try:
            entries = os.listdir(_SYS_BLOCK)
        except OSError:
            entries = []
        for dev in entries:
            if not dev.startswith("dm-"):
                continue
            try:
                uuid = read_text_capped(Path(_SYS_BLOCK) / dev / "dm" / "uuid",
                                        encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if uuid.startswith("CRYPT-"):
                crypt_nodes.add(dev)
                name = ""
                try:
                    name = read_text_capped(Path(_SYS_BLOCK) / dev / "dm" / "name",
                                            encoding="utf-8",
                                            errors="replace").strip()
                except OSError:
                    pass
                snap.crypt_volumes.append(name or dev)

        # 2. The device backing "/" (last matching entry wins — that is effective).
        try:
            text = read_text_capped(Path(_MOUNTS), encoding="utf-8",
                                    errors="replace")
        except OSError:
            snap.readable = False
            return snap
        root_src = ""
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "/":
                root_src = parts[0]
        snap.root_source = root_src

        # 3. Resolve the root device to its dm node and walk the stack.
        snap.root_encrypted = _root_is_encrypted(root_src, crypt_nodes)

        # Supporting evidence (intent, not state): a configured crypttab.
        try:
            if path_exists(Path(_CRYPTTAB)):
                conf = read_text_capped(Path(_CRYPTTAB), encoding="utf-8",
                                        errors="replace")
                snap.crypttab_present = any(
                    line.strip() and not line.strip().startswith("#")
                    for line in conf.splitlines()
                )
        except OSError:
            pass
        return snap


def _dm_node_for(root_src: str) -> "str | None":
    """Return the ``dm-N`` node backing *root_src*, or None if it is not a dm."""
    if root_src.startswith("/dev/mapper/"):
        try:
            target = os.readlink(root_src)          # e.g. "../dm-3"
        except OSError:
            return None
        return os.path.basename(target)
    if root_src.startswith("/dev/dm-"):
        return os.path.basename(root_src)
    return None


def _stack_has_crypt(dm_node: str, crypt_nodes: "set[str]",
                     seen: "set[str]") -> bool:
    """True if *dm_node* is a crypt target or sits on one (LVM-on-LUKS)."""
    if dm_node in crypt_nodes:
        return True
    if dm_node in seen:
        return False
    seen.add(dm_node)
    try:
        slaves = os.listdir(Path(_SYS_BLOCK) / dm_node / "slaves")
    except OSError:
        return False
    for s in slaves:
        if s in crypt_nodes:
            return True
        if s.startswith("dm-") and _stack_has_crypt(s, crypt_nodes, seen):
            return True
    return False


def _root_is_encrypted(root_src: str, crypt_nodes: "set[str]") -> "bool | None":
    """Encrypted True/False, or None when it genuinely cannot be determined."""
    dm_node = _dm_node_for(root_src)
    if dm_node is None:
        # A raw partition means an unencrypted root (a crypt root mounts through
        # its mapper). Anything else (overlay, nfs, rootfs, none) is undecidable.
        if root_src.startswith(_REAL_BLOCK_PREFIXES):
            return False
        return None
    return _stack_has_crypt(dm_node, crypt_nodes, set())


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_disk_encryption(snapshot: DiskEncryptionSnapshot,
                          t: TranslationFunc | None = None,
                          profile_name: str = "server") -> CheckResult:
    """Analyse DiskEncryptionSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()
    p = profile_name.lower()
    is_portable = p in ("desktop", "workstation")

    if p == "container":
        result.ok(
            message=_t("disk_encryption.container_na"),
            key="disk_encryption.container_na",
        )
        return result

    if not snapshot.readable:
        result.info(
            message=_t("disk_encryption.unknown"),
            detail=_t("disk_encryption.unknown_detail"),
            key="disk_encryption.unknown",
        )
        return result

    enc = snapshot.root_encrypted
    if enc is True:
        result.ok(
            message=_t("disk_encryption.root_encrypted"),
            key="disk_encryption.root_encrypted",
        )
        return result

    if enc is None:
        # Root device could not be resolved (pseudo/overlay/network root).
        if snapshot.crypt_volumes:
            result.info(
                message=_t("disk_encryption.volumes_present_root_unknown",
                           count=len(snapshot.crypt_volumes)),
                detail=_t("disk_encryption.volumes_present_root_unknown_detail",
                          volumes=", ".join(snapshot.crypt_volumes)),
                key="disk_encryption.volumes_present_root_unknown",
            )
        else:
            result.info(
                message=_t("disk_encryption.unknown"),
                detail=_t("disk_encryption.unknown_detail"),
                key="disk_encryption.unknown",
            )
        return result

    # enc is False — the root filesystem is on a plain, unencrypted device.
    others = [v for v in snapshot.crypt_volumes]
    if is_portable:
        detail = _t("disk_encryption.root_unencrypted_detail")
        if others:
            detail = _t("disk_encryption.root_unencrypted_detail_with_volumes",
                        volumes=", ".join(others))
        result.warn_with_deduction(
            key="disk_encryption.root_unencrypted",
            message=_t("disk_encryption.root_unencrypted"),
            reason=_t("disk_encryption.root_unencrypted_reason"),
            points=1,
            detail=detail,
            nature="action",
        )
    else:
        result.info(
            message=_t("disk_encryption.root_unencrypted_server"),
            detail=_t("disk_encryption.root_unencrypted_server_detail"),
            key="disk_encryption.root_unencrypted_server",
        )
    return result
