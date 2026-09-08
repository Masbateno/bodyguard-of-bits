"""What machine this is, which BOB had never asked.

Every check reasoned about software and none about the hardware underneath, so
three findings stated x86 facts on machines that have no x86 in them. The
clearest was Secure Boot: absent UEFI firmware, BOB reported *"Legacy BIOS
detected"* — and a Raspberry Pi has no BIOS at all. It has a bootloader in
EEPROM, and the sentence was a guess dressed as an observation.

Architecture also decides what a *missing* thing means. No microcode package on
an x86 host is a gap; on ARM it is the correct state, because there is no
microcode package to install. The firmware check already reached that answer by
a different route (`/proc/cpuinfo` has no `vendor_id` on ARM), which worked but
did not say why, and would not have survived anyone adding a vendor fallback.

This module answers only what it can establish, and returns empty rather than
guessing — the same contract as ``package_installed`` and ``read_pam_stack``.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Where the Raspberry Pi firmware exposes the board name. A device tree exists
#: on most ARM boards; the file is NUL-terminated, which ``str.strip`` alone
#: does not remove.
_DEVICE_TREE_MODEL = Path("/proc/device-tree/model")

#: `/proc/cpuinfo` carries `Model:` on Raspberry Pi OS and `Hardware:` on older
#: kernels. Read as a fallback for a kernel built without the device tree
#: interface.
_CPUINFO = Path("/proc/cpuinfo")

#: Where Raspberry Pi OS mounts the FAT boot partition. It moved in Bookworm
#: (2023): `/boot` before, `/boot/firmware` after, with `/boot` remaining as an
#: ordinary directory on the root filesystem. Both are checked because a Pi
#: imaged years ago and upgraded in place keeps the old layout.
_BOOT_DIRS = (Path("/boot/firmware"), Path("/boot"))

def machine() -> str:
    """``uname -m``, or "" when it cannot be read."""
    try:
        return os.uname().machine
    except (OSError, AttributeError):      # pragma: no cover — POSIX only
        return ""


def raspberry_pi_model(_device_tree: "Path | None" = None,
                       _cpuinfo: "Path | None" = None) -> str:
    """The board name if this is a Raspberry Pi, else "".

    Read from the device tree first, because that string comes from the
    firmware and names the exact board ("Raspberry Pi 4 Model B Rev 1.5").
    """
    dt = _device_tree if _device_tree is not None else _DEVICE_TREE_MODEL
    try:
        # NUL-terminated: the device tree stores C strings verbatim.
        model = dt.read_bytes().decode("utf-8", "replace").replace("\x00", "").strip()
        if "raspberry pi" in model.lower():
            return model
    except OSError:
        pass

    cpuinfo = _cpuinfo if _cpuinfo is not None else _CPUINFO
    try:
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            field, _, value = line.partition(":")
            if field.strip() in ("Model", "Hardware") and "raspberry pi" in value.lower():
                return value.strip()
    except OSError:
        pass
    return ""


def is_raspberry_pi() -> bool:
    """True when the firmware or the kernel names this board a Raspberry Pi."""
    return bool(raspberry_pi_model())


def boot_firmware_dir(_candidates: "tuple[Path, ...] | None" = None) -> "Path | None":
    """The mounted Raspberry Pi boot partition, or None.

    Identified by content rather than by path: `/boot` exists on every Linux
    system, and on Bookworm it is an ordinary directory while the FAT partition
    lives at `/boot/firmware`. A directory holding `config.txt` is the one the
    firmware reads.
    """
    for path in (_candidates if _candidates is not None else _BOOT_DIRS):
        try:
            if (path / "config.txt").is_file():
                return path
        except OSError:
            continue
    return None
