"""
Firmware update audit for BOB (CHECK 45).

Checks for pending firmware updates (BIOS, UEFI, SSD, NIC, etc.) via fwupd
and verifies that CPU microcode packages are installed.

Sources (all read-only, no network calls):
  - fwupdmgr get-updates (reads cached metadata — no fwupdmgr refresh)
  - dpkg -l intel-microcode / amd64-microcode
  - /proc/cpuinfo  — to determine CPU vendor

Score impact:
  - Pending firmware updates (fwupd): WARN −1 pt
  - fwupd absent:                     INFO  0 pt
  - CPU microcode not installed:      WARN −1 pt

Split into:
  1. FirmwareSnapshot.from_system() — collects raw data.
  2. check_firmware(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _C_UTF8_LOCALE_ENV,
    _command_exists,
    _identity_t,
    _run,
    package_installed,
)
from bob.scoring import CheckResult

_VENDOR_RE = re.compile(r"^vendor_id\s*:\s*(.+)", re.MULTILINE | re.IGNORECASE)
_FWUPD_NO_UPDATES = re.compile(
    r"no upgrades? for|no updates? available|nothing to update|no devices found",
    re.IGNORECASE,
)
_FWUPD_ERROR_RE = re.compile(r"\b(error|failed)\b", re.IGNORECASE)

_MAX_ERROR_LEN  = 200
_FWUPD_TIMEOUT  = 30  # fwupdmgr can be slow on first run

# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class FirmwareSnapshot:
    """
    Raw snapshot of firmware update status.

    Attributes:
        fwupd_available:         True if fwupdmgr is installed.
        fwupd_pending_updates:   List of device names with pending firmware updates.
        fwupd_error:             Non-empty if fwupdmgr returned an error (e.g. no daemon).
        cpu_vendor:              "intel" | "amd" | "other" | "" (unknown).
        microcode_installed:     True if the CPU-appropriate microcode package is installed.
        microcode_package:       Name of the microcode package found (or "").
        microcode_not_applicable: True if CPU vendor is not Intel or AMD (no package needed).
    """
    fwupd_available:          bool       = False
    fwupd_pending_updates:    list[str]  = field(default_factory=list)
    fwupd_error:              str        = ""
    cpu_vendor:               str        = ""
    microcode_installed:      bool       = False
    microcode_package:        str        = ""
    microcode_not_applicable: bool       = False

    @classmethod
    def from_system(cls) -> "FirmwareSnapshot":
        """Collect firmware state from the live system."""
        snap = cls()

        # --- CPU vendor detection -------------------------------------------
        snap.cpu_vendor = _detect_cpu_vendor()

        # --- CPU microcode package ------------------------------------------
        if snap.cpu_vendor == "intel":
            candidates = ["intel-microcode"]
        elif snap.cpu_vendor == "amd":
            candidates = ["amd64-microcode"]
        else:
            candidates = []

        if candidates:
            for pkg in candidates:
                if _dpkg_installed(pkg):
                    snap.microcode_installed = True
                    snap.microcode_package   = pkg
                    break
        else:
            snap.microcode_not_applicable = True

        # --- fwupd ----------------------------------------------------------
        snap.fwupd_available = _command_exists("fwupdmgr")
        if snap.fwupd_available:
            # v0.11.1 F3: run under C.UTF-8 (not the default LC_ALL=C) so the
            # device tree connectors ├ └ ─ │ render as Unicode instead of
            # degrading to ``?``, which would break _parse_fwupd_updates and
            # leak connector junk as device names.
            out = _run(
                "fwupdmgr", "get-updates",
                timeout=_FWUPD_TIMEOUT, env=_C_UTF8_LOCALE_ENV,
            ) or ""
            # Error and updates are independent: both can appear in the same output.
            if _FWUPD_ERROR_RE.search(out):
                first_line = out.strip().splitlines()[0] if out.strip() else out.strip()
                snap.fwupd_error = first_line[:_MAX_ERROR_LEN]
            if out.strip() and not _FWUPD_NO_UPDATES.search(out):
                snap.fwupd_pending_updates = _parse_fwupd_updates(out)

        return snap

# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_firmware(snapshot: FirmwareSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit firmware update status and CPU microcode installation.

    Scoring:
      - Pending firmware updates:       WARN −1 pt
      - CPU microcode not installed:    WARN −1 pt
      - fwupd not installed:            INFO  0 pt
      - fwupd error:                    INFO  0 pt

    Args:
        snapshot: FirmwareSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- fwupd section -------------------------------------------------------
    if not snapshot.fwupd_available:
        result.info(
            message=_t("firmware.fwupd_missing"),
            key="firmware.fwupd_missing",
        )
    else:
        if snapshot.fwupd_error:
            result.info(
                message=_t("firmware.fwupd_error", error=snapshot.fwupd_error),
                key="firmware.fwupd_error",
            )
        if snapshot.fwupd_pending_updates:
            count   = len(snapshot.fwupd_pending_updates)
            devices = ", ".join(snapshot.fwupd_pending_updates[:3])
            if count > 3:
                devices += f" (+{count - 3})"
            result.warn_with_deduction(
                key="firmware.fwupd_updates",
                message=_t("firmware.fwupd_updates", count=count, devices=devices),
                reason=_t("firmware.fwupd_updates_reason", count=count),
                points=1,
                detail=_t("firmware.fwupd_updates_detail"),
                cmd="sudo fwupdmgr update",
                nature="action",
            )
        elif not snapshot.fwupd_error:
            result.ok(
                message=_t("firmware.fwupd_ok"),
                key="firmware.fwupd_ok",
            )

    # --- CPU microcode section -----------------------------------------------
    if snapshot.microcode_not_applicable:
        result.info(
            message=_t("firmware.microcode_na"),
            key="firmware.microcode_na",
        )
    elif snapshot.microcode_installed:
        result.ok(
            message=_t("firmware.microcode_ok", package=snapshot.microcode_package),
            key="firmware.microcode_ok",
        )
    else:
        # Unknown vendor (cpu_vendor == "" or "other") → treat same as not_applicable
        if snapshot.cpu_vendor not in ("intel", "amd"):
            result.info(
                message=_t("firmware.microcode_na"),
                key="firmware.microcode_na",
            )
        else:
            pkg = "intel-microcode" if snapshot.cpu_vendor == "intel" else "amd64-microcode"
            result.warn_with_deduction(
                key="firmware.microcode_missing",
                message=_t("firmware.microcode_missing", vendor=snapshot.cpu_vendor.upper()),
                reason=_t("firmware.microcode_missing_reason", vendor=snapshot.cpu_vendor.upper()),
                points=1,
                detail=_t("firmware.microcode_missing_detail"),
                cmd=f"sudo apt install {shlex.quote(pkg)}",
            )

    return result

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_cpu_vendor() -> str:
    """Return 'intel', 'amd', or 'unknown' based on /proc/cpuinfo vendor_id."""
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        m = _VENDOR_RE.search(text)
        if not m:
            return "unknown"
        vendor = m.group(1).strip().lower()
        if "genuineintel" in vendor or "intel" in vendor:
            return "intel"
        if "authenticamd" in vendor or "amd" in vendor:
            return "amd"
        return "unknown"
    except OSError:
        return "unknown"

def _dpkg_installed(package: str) -> bool:
    """Return True if *package* is installed, on any supported distribution.

    Named for dpkg because that is all it used to ask. A microcode package is
    called `intel-microcode` on Debian and `microcode_ctl` on Fedora, and the
    dpkg-only query answered False for every one of them outside Debian.
    """
    return package_installed(package) is not None

_TREE_ITEM_RE = re.compile(r"^[├└]─\s*")
# v0.11.1 F3: a real fwupd device name always starts with an alphanumeric.
# This rejects connector/placeholder junk (``?``, ``??UEFI dbx:``, ``│``,
# ``└─…``) that leaks through when the device tree is rendered as ``?``
# under a non-UTF-8 locale (defense in depth — the call site now forces
# C.UTF-8, but an older / minimal distro may still lack it).
_VALID_DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9]")
_FLAT_SKIP_RE = re.compile(
    r"^(Update|Version|Summary|Description|Requires|Urgency|Remote|Size|"
    r"Flags|Status|GUID|Device|AppStream|Release|\[|WARNING|Error|\s)",
    re.IGNORECASE,
)

def _parse_fwupd_updates(output: str) -> list[str]:
    """
    Extract device names from fwupdmgr get-updates output.

    Handles two output formats:
    - Flat (older fwupd): device names appear at column 0, metadata is indented.
    - Tree (fwupd 1.9+): device names appear on lines starting with ├─ or └─;
      the top-level line is the system container, │ lines are tree connectors.
    """
    lines = output.splitlines()
    is_tree = any(_TREE_ITEM_RE.match(l) for l in lines)

    devices: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if is_tree:
            if not _TREE_ITEM_RE.match(line):
                continue
            name = _TREE_ITEM_RE.sub("", line).rstrip(":").strip()
        else:
            if _FLAT_SKIP_RE.match(line):
                continue
            name = line.strip()

        if name and _VALID_DEVICE_NAME_RE.match(name) and name not in seen:
            devices.append(name)
            seen.add(name)
        if len(devices) >= 10:
            break
    return devices
