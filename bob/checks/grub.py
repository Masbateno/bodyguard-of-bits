"""
GRUB bootloader configuration check for BOB (CIS §1.4).

`secure_boot.py` answers "can an unsigned bootloader run" (UEFI Secure Boot).
This check answers the *next* question: once GRUB is the bootloader, is its
configuration hardened against local/physical access?

Two concrete, low-false-positive properties:

  1. **grub.cfg permissions.** The generated `grub.cfg` should be owner-only
     (0600/0400). When it is group- or world-readable it discloses the full
     boot command line and, if a GRUB password is set, the `password_pbkdf2`
     **hash** — offline-crackable. World/group *writable* is worse still
     (tamper the boot line). Fix is a one-liner (`chmod 600`).

  2. **GRUB superuser password.** Without a `password_pbkdf2` superuser, anyone
     at the console can edit a menu entry (`e`) and boot with `init=/bin/bash`
     for an unauthenticated root shell, or drop to single-user mode. This is a
     physical/console-access control; it is reported INFO (no deduction),
     because setting it has real operational cost (it can block unattended
     reboots) and its absence is common and often deliberate.

Score impact:
  - No GRUB (systemd-boot, Pi EEPROM, extlinux, not found): INFO (n/a)
  - grub.cfg present but unreadable by BOB:                  INFO (illisible ≠ vide)
  - grub.cfg not owner-only:                                 WARN −1 pt
  - grub.cfg owner-only:                                     OK
  - GRUB superuser password absent:                          INFO (physical access)
  - GRUB superuser password present:                         OK

Split into:
  1. GrubSnapshot.from_system() — collects state from the live system.
  2. check_grub(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    path_exists,
    read_text_capped,
)
from bob.scoring import CheckResult

# The generated grub.cfg, in the order distributions place it. The first one
# that exists is the active config (Debian/Ubuntu/Kali → grub/, Fedora/RHEL/
# openSUSE → grub2/, some EFI installs under /boot/efi/EFI/<vendor>/).
_GRUB_CFG_CANDIDATES = (
    "/boot/grub/grub.cfg",
    "/boot/grub2/grub.cfg",
    "/boot/efi/EFI/grub.cfg",
)
# EFI vendor dirs vary (fedora, debian, kali, opensuse…); resolved by glob.
_GRUB_CFG_EFI_GLOB = "/boot/efi/EFI/*/grub.cfg"

# A GRUB superuser password line in the generated config, either form.
_PASSWORD_RE = re.compile(r"^\s*password(_pbkdf2)?\s+\S", re.MULTILINE)


@dataclass
class GrubSnapshot:
    """State collected about the GRUB bootloader configuration.

    Args:
        cfg_path:     Path to the active grub.cfg, or "" when none was found.
        cfg_mode:     grub.cfg permission bits (st_mode & 0o777), or None when
                      not found / not stat-able.
        readable:     False when grub.cfg exists but its contents could not be
                      read (permission) — "unreadable" is not "no password".
        password_set: True when a GRUB superuser password line is present.
    """
    cfg_path:     str = ""
    cfg_mode:     int | None = None
    readable:     bool = True
    password_set: bool = False

    @classmethod
    def from_system(cls) -> "GrubSnapshot":
        """Detect GRUB config state from the live system. Never raises."""
        snap = cls()

        path = ""
        for cand in _GRUB_CFG_CANDIDATES:
            if path_exists(Path(cand)):
                path = cand
                break
        if not path:
            import glob
            matches = sorted(glob.glob(_GRUB_CFG_EFI_GLOB))
            if matches:
                path = matches[0]

        if not path:
            return snap  # no GRUB — cfg_path stays "", check reports n/a

        snap.cfg_path = path
        try:
            snap.cfg_mode = os.stat(path).st_mode & 0o777
        except OSError:
            snap.cfg_mode = None

        try:
            text = read_text_capped(Path(path), encoding="utf-8", errors="replace")
        except OSError:
            # Present but unreadable (grub.cfg is often 0600 root-only). That is
            # not "no password" — record it so the check does not invent a
            # clean verdict from an empty read.
            snap.readable = False
            return snap

        snap.password_set = bool(_PASSWORD_RE.search(text))
        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_grub(snapshot: GrubSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """Analyse GrubSnapshot and return findings."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- No GRUB on this host -------------------------------------------------
    if not snapshot.cfg_path:
        result.info(
            message=_t("grub.not_present"),
            detail=_t("grub.not_present_detail"),
            key="grub.not_present",
        )
        return result

    # --- Permissions ---------------------------------------------------------
    mode = snapshot.cfg_mode
    if mode is None:
        result.info(
            message=_t("grub.cfg_unreadable", path=snapshot.cfg_path),
            detail=_t("grub.cfg_unreadable_detail"),
            key="grub.cfg_unreadable",
        )
    else:
        group_other = mode & 0o077
        if group_other:
            writable = bool(mode & 0o022)
            # The hash only leaks if there is one to leak *and* the file is
            # readable by non-owners; say so, otherwise state the generic risk.
            if snapshot.readable and snapshot.password_set and (mode & 0o044):
                reason = _t("grub.cfg_perms_reason_hash")
            elif writable:
                reason = _t("grub.cfg_perms_reason_writable")
            else:
                reason = _t("grub.cfg_perms_reason")
            result.warn_with_deduction(
                key="grub.cfg_perms",
                message=_t("grub.cfg_perms", path=snapshot.cfg_path,
                           mode=f"{mode:04o}"),
                reason=reason,
                points=1,
                detail=_t("grub.cfg_perms_detail"),
                cmd=f"sudo chmod 600 {snapshot.cfg_path}",
                nature="action",
            )
        else:
            result.ok(
                message=_t("grub.cfg_perms_ok", path=snapshot.cfg_path,
                           mode=f"{mode:04o}"),
                key="grub.cfg_perms_ok",
            )

    # --- Superuser password --------------------------------------------------
    # Only meaningful when the contents were actually read; an unreadable
    # grub.cfg (0600 root-only) is the *good* permission case, so silence the
    # password finding rather than assert "no password" from an unread file.
    if snapshot.readable:
        if snapshot.password_set:
            result.ok(
                message=_t("grub.password_set"),
                key="grub.password_set",
            )
        else:
            result.info(
                message=_t("grub.no_password"),
                detail=_t("grub.no_password_detail"),
                key="grub.no_password",
            )

    return result
