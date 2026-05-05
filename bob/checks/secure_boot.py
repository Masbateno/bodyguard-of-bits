"""
Secure Boot check for BOB (CHECK 32).

Verifies whether UEFI Secure Boot is enabled.  Secure Boot prevents unsigned
or tampered bootloaders and kernels from executing, protecting against
boot-level malware and physical-access attacks.

Score impact:
  - Not UEFI (legacy BIOS):          INFO  (not applicable — no deduction)
  - Cannot determine state:           INFO  (no deduction)
  - Secure Boot enabled:              OK
  - Secure Boot disabled on server:   INFO  (no deduction — less common, VMs)
  - Secure Boot disabled on desktop:  WARN  −1 pt  (bootkits, physical access)

Detection strategy (in order):
  1. ``mokutil --sb-state``  — most reliable on Ubuntu/Debian
  2. ``/sys/firmware/efi/efivars/SecureBoot-*``  — raw EFI variable fallback
  3. ``bootctl status``  — systemd-boot fallback

Split into:
  1. SecureBootSnapshot.from_system() — collects state from the live system.
  2. check_secure_boot(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import os
import glob
from dataclasses import dataclass

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# Possible states returned by the detection logic
_STATE_ENABLED    = "enabled"
_STATE_DISABLED   = "disabled"
_STATE_SETUP_MODE = "setup_mode"   # SB technically on but no PK enrolled — not secure
_STATE_NO_UEFI    = "no_uefi"
_STATE_UNKNOWN    = "unknown"


@dataclass
class SecureBootSnapshot:
    """
    State collected from the system about Secure Boot.

    Args:
        state:      One of "enabled", "disabled", "no_uefi", "unknown".
        method:     Detection method used ("mokutil", "efivars", "bootctl", "none").
    """
    state:  str = _STATE_UNKNOWN
    method: str = "none"

    @classmethod
    def from_system(cls) -> "SecureBootSnapshot":
        """Detect Secure Boot state from the live system. Never raises."""
        snap = cls()

        # 1. mokutil (most reliable)
        if _command_exists("mokutil"):
            out = (_run("mokutil", "--sb-state") or "").lower().strip()
            if "secureboot enabled" in out:
                # Setup Mode = SB technically on but no Platform Key enrolled → not secure
                if "setup mode" in out:
                    snap.state  = _STATE_SETUP_MODE
                else:
                    snap.state  = _STATE_ENABLED
                snap.method = "mokutil"
                return snap
            if "secureboot disabled" in out:
                snap.state  = _STATE_DISABLED
                snap.method = "mokutil"
                return snap
            if "efi variables are not supported" in out or "not supported" in out:
                snap.state  = _STATE_NO_UEFI
                snap.method = "mokutil"
                return snap

        # 2. EFI variable fallback — byte index 4 of the SecureBoot variable
        efi_paths = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
        if efi_paths:
            try:
                with open(efi_paths[0], "rb") as fh:
                    data = fh.read()
                # Format: 4-byte attributes + 1-byte value (0=disabled, 1=enabled)
                if len(data) >= 5 and data[4] in (0, 1):
                    snap.state  = _STATE_ENABLED if data[4] == 1 else _STATE_DISABLED
                    snap.method = "efivars"
                    return snap
            except OSError:
                pass
        elif not os.path.isdir("/sys/firmware/efi"):
            # No EFI directory at all → legacy BIOS
            snap.state  = _STATE_NO_UEFI
            snap.method = "efivars"
            return snap

        # 3. bootctl fallback
        if _command_exists("bootctl"):
            out = (_run("bootctl", "status") or "").lower()
            if "secure boot: enabled" in out:
                snap.state  = _STATE_ENABLED
                snap.method = "bootctl"
                return snap
            if "secure boot: disabled" in out:
                snap.state  = _STATE_DISABLED
                snap.method = "bootctl"
                return snap

        return snap  # state = "unknown"


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_secure_boot(snapshot: SecureBootSnapshot, t: TranslationFunc | None = None,
                      profile_name: str = "server") -> CheckResult:
    """
    Analyse SecureBootSnapshot and return findings.

    Findings:
      - No UEFI / unknown:        INFO  (no deduction)
      - Enabled:                  OK
      - Disabled on server:       INFO  (no deduction — VMs, cloud, custom kernels)
      - Disabled on desktop:      WARN  −1 pt
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    is_desktop = profile_name.lower() in ("desktop", "workstation")

    if snapshot.state == _STATE_NO_UEFI:
        result.info(
            message=_t("secure_boot.no_uefi"),
            detail=_t("secure_boot.no_uefi_detail"),
            key="secure_boot.no_uefi",
        )
        return result

    if snapshot.state == _STATE_UNKNOWN:
        result.info(
            message=_t("secure_boot.unknown"),
            detail=_t("secure_boot.unknown_detail"),
            key="secure_boot.unknown",
        )
        return result

    if snapshot.state == _STATE_ENABLED:
        result.ok(
            message=_t("secure_boot.enabled"),
            key="secure_boot.enabled",
        )
        return result

    if snapshot.state == _STATE_SETUP_MODE:
        # Setup Mode = no Platform Key enrolled → any bootloader can run → treat as disabled
        result.warn(
            message=_t("secure_boot.setup_mode"),
            detail=_t("secure_boot.setup_mode_detail"),
            nature="improvement",
            key="secure_boot.setup_mode",
        )
        result.add_deduction(
            reason=_t("secure_boot.setup_mode_reason"),
            points=1,
            context="local",
            key="secure_boot.setup_mode",
        )
        return result

    # Disabled
    if is_desktop:
        result.warn(
            message=_t("secure_boot.disabled"),
            detail=_t("secure_boot.disabled_detail"),
            nature="improvement",
            key="secure_boot.disabled",
        )
        result.add_deduction(
            reason=_t("secure_boot.disabled_reason"),
            points=1,
            context="local",
            key="secure_boot.disabled",
        )
    else:
        result.info(
            message=_t("secure_boot.disabled"),
            detail=_t("secure_boot.disabled_server_detail"),
            key="secure_boot.disabled",
        )

    return result
