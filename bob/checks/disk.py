"""
Disk health audit for BOB.

Checks:
  - SMART overall health (PASSED / FAILED) via smartctl
  - Critical SMART attributes: reallocated sectors, pending sectors,
    uncorrectable errors
  - Partition usage (df) — warn when partitions are nearly full

The check is split into two parts:
  1. DiskSnapshot.from_system() — collects data via subprocess.
  2. check_disk(snapshot)       — pure logic, returns a CheckResult.

Score impact: deductions route to the new "disk" domain in domain_scores.py.

Usage:
    from bob.checks.disk import DiskSnapshot, check_disk

    snapshot = DiskSnapshot.from_system()
    result   = check_disk(snapshot)
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Partition usage thresholds
_WARN_USAGE_PCT:  int = 90   # WARN above this
_INFO_USAGE_PCT:  int = 80   # INFO above this

# SMART attribute IDs for critical attributes
# https://en.wikipedia.org/wiki/S.M.A.R.T.#Known_ATA_S.M.A.R.T._attributes
_ATTR_REALLOCATED_SECTORS = 5
_ATTR_PENDING_SECTORS     = 197
_ATTR_UNCORRECTABLE       = 198

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SmartResult:
    """SMART assessment for a single disk."""
    device:               str
    model:                str  = ""
    passed:               bool | None = None   # None = unknown/unavailable
    virtual:              bool = False             # SMART not applicable (VM)
    reallocated_sectors:  int  = 0
    pending_sectors:      int  = 0
    uncorrectable_errors: int  = 0

@dataclass
class PartitionInfo:
    """Usage info for a mounted partition."""
    mountpoint: str
    device:     str
    size_gb:    float
    used_pct:   int

@dataclass
class DiskSnapshot:
    """
    Raw snapshot of disk health state.

    Args:
        smartctl_available: True if smartctl is installed.
        smart_results:      SMART assessment per detected disk.
        partitions:         Usage info for mounted partitions.
    """
    smartctl_available: bool               = False
    smart_results:      list[SmartResult]  = field(default_factory=list)
    partitions:         list[PartitionInfo] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "DiskSnapshot":
        """
        Collect disk health state from the live system.

        Returns:
            Populated DiskSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        # --- smartctl ---
        snap.smartctl_available = _command_exists("smartctl")
        if snap.smartctl_available:
            devices = _detect_block_devices()
            for dev in devices:
                snap.smart_results.append(_query_smart(dev))

        # --- partition usage ---
        snap.partitions = _read_partition_usage()

        return snap

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_disk(snapshot: DiskSnapshot, *, t: TranslationFunc | None = None) -> CheckResult:
    """
    Audit disk health and partition usage.

    Scoring:
      - SMART FAILED:                            −3 pts (ALERT)
      - Reallocated or pending sectors > 0:      −1 pt  (WARN)
      - Uncorrectable errors > 0:                −1 pt  (WARN)
      - Partition ≥ _WARN_USAGE_PCT% full:       −1 pt  (WARN)
      - Partition ≥ _INFO_USAGE_PCT% full:       INFO, no deduction
      - smartctl not installed:                  INFO, no deduction

    Args:
        snapshot: DiskSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()
    found_issue = False

    # --- smartctl unavailable ---
    if not snapshot.smartctl_available:
        result.info(
            message=_t("disk.smartctl_missing"),
            detail=_t("disk.smartctl_missing_detail"),
            cmd="sudo apt install smartmontools",
            key="disk.smartctl_missing",
        )

    # --- SMART results per disk ---
    for sr in snapshot.smart_results:
        if sr.virtual:
            result.info(
                message=_t("disk.smart_virtual", device=sr.device),
                key="disk.smart_virtual",
            )
            continue

        if sr.passed is None:
            result.info(
                message=_t("disk.smart_unknown", device=sr.device),
                key="disk.smart_unknown",
            )
            continue

        if not sr.passed:
            result.alert_with_deduction(
                key="disk.smart_failed",
                message=_t("disk.smart_failed", device=sr.device, model=sr.model),
                reason=_t("disk.smart_failed_reason", device=sr.device),
                points=3,
                detail=_t("disk.smart_failed_detail"),
                cmd=f"sudo smartctl -a {shlex.quote(sr.device)}",
                cmd_type="check",
                nature="action",
            )
            found_issue = True
        else:
            result.ok(
                message=_t("disk.smart_ok", device=sr.device, model=sr.model),
                key="disk.smart_ok",
            )

        # Critical attributes
        if sr.reallocated_sectors > 0:
            result.warn_with_deduction(
                key="disk.reallocated_sectors",
                message=_t(
                    "disk.reallocated_sectors",
                    device=sr.device,
                    count=sr.reallocated_sectors,
                ),
                reason=_t("disk.reallocated_sectors_reason", device=sr.device),
                points=1,
                detail=_t("disk.reallocated_sectors_detail"),
                cmd=f"sudo smartctl -a {shlex.quote(sr.device)}",
                cmd_type="check",
                nature="action",
            )
            found_issue = True

        if sr.pending_sectors > 0:
            result.warn_with_deduction(
                key="disk.pending_sectors",
                message=_t(
                    "disk.pending_sectors",
                    device=sr.device,
                    count=sr.pending_sectors,
                ),
                reason=_t("disk.pending_sectors_reason", device=sr.device),
                points=1,
                detail=_t("disk.pending_sectors_detail"),
                cmd=f"sudo smartctl -a {shlex.quote(sr.device)}",
                cmd_type="check",
                nature="action",
            )
            found_issue = True

        if sr.uncorrectable_errors > 0:
            result.warn_with_deduction(
                key="disk.uncorrectable_errors",
                message=_t(
                    "disk.uncorrectable_errors",
                    device=sr.device,
                    count=sr.uncorrectable_errors,
                ),
                reason=_t("disk.uncorrectable_errors_reason", device=sr.device),
                points=1,
                detail=_t("disk.uncorrectable_errors_detail"),
                cmd=f"sudo smartctl -a {shlex.quote(sr.device)}",
                cmd_type="check",
                nature="action",
            )
            found_issue = True

    # --- Partition usage ---
    for part in snapshot.partitions:
        if part.used_pct >= _WARN_USAGE_PCT:
            result.warn_with_deduction(
                key="disk.partition_critical",
                message=_t(
                    "disk.partition_critical",
                    mountpoint=part.mountpoint,
                    pct=part.used_pct,
                ),
                reason=_t("disk.partition_critical_reason", mountpoint=part.mountpoint),
                points=1,
                detail=_t("disk.partition_critical_detail", mountpoint=part.mountpoint),
                cmd=f"du -x -h --max-depth=1 {shlex.quote(part.mountpoint)} 2>/dev/null | sort -rh | head -20",
                cmd_type="check",
                nature="action",
            )
            found_issue = True
        elif part.used_pct >= _INFO_USAGE_PCT:
            result.info(
                message=_t(
                    "disk.partition_warn",
                    mountpoint=part.mountpoint,
                    pct=part.used_pct,
                ),
                key="disk.partition_warn",
            )

    # --- All clear ---
    # Only emit the "all SMART passed" success if at least one real (non-virtual)
    # SMART check actually ran. On VMs / containers where every disk reports
    # "SMART not applicable", claiming "all passed" was misleading (terrain
    # test Kali, 15-05-2026) — there were no SMART reads to pass.
    real_smart_run = any(
        not sr.virtual and sr.passed is not None
        for sr in snapshot.smart_results
    )
    if not found_issue and snapshot.smartctl_available and real_smart_run:
        result.ok(
            message=_t("disk.ok"),
            key="disk.ok",
        )

    # --- Deeper analysis tips (verbose only via cmd field) ---
    real_devices = [sr.device for sr in snapshot.smart_results if not sr.virtual]
    if snapshot.smartctl_available and real_devices:
        first = shlex.quote(real_devices[0])
        cmd_lines = [f"sudo smartctl -a {shlex.quote(dev)}" for dev in real_devices]
        # v0.11.1: the inline ``# ...`` comments are locale-aware — they were
        # previously hardcoded French, which leaked into English audits.
        cmd_lines += [
            f"sudo smartctl -t short {first}  # {_t('disk.smart_cmd.test_short')}",
            f"sudo smartctl -t long {first}   # {_t('disk.smart_cmd.test_long')}",
            f"sudo watch -n 30 smartctl -a {first}  # {_t('disk.smart_cmd.watch')}",
            f"sudo smartctl -X {first}  # {_t('disk.smart_cmd.abort')}",
            f"sudo smartctl -l selftest {first}  # {_t('disk.smart_cmd.history')}",
        ]
        result.info(
            message=_t("disk.smart_tips"),
            detail=_t("disk.smart_tips_detail"),
            cmd="\n".join(cmd_lines),
            cmd_type="check",
            key="disk.smart_tips",
        )

    return result

# ---------------------------------------------------------------------------
# System detection helpers
# ---------------------------------------------------------------------------

def _detect_block_devices() -> list[str]:
    """
    Return list of physical block device paths (e.g. /dev/sda, /dev/nvme0n1).

    Uses lsblk to list non-loop, non-rom, top-level devices only.
    """
    out = _run("lsblk", "-d", "-n", "-o", "NAME,TYPE")
    if not out:
        return []
    devices = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, dev_type = parts[0], parts[1]
        if dev_type in ("disk",):
            devices.append(f"/dev/{name}")
    return devices

def _query_smart(device: str) -> SmartResult:
    """
    Run smartctl -H -A on device and return a SmartResult.

    Handles: normal drives, NVMe, and virtualised drives (no SMART support).
    """
    sr = SmartResult(device=device)

    # Overall health + info: smartctl -iH (info + health in one call)
    health_out = _run("smartctl", "-iH", device)
    if not health_out:
        return sr

    health_lower = health_out.lower()

    # Detect virtualised / unsupported device
    if any(kw in health_lower for kw in (
        "operation not supported",
        "no smartctl support",
        "device does not support",
        "unknown usb bridge",
        "unable to detect device type",
    )):
        sr.virtual = True
        return sr

    # Parse model — try multiple field names in priority order:
    #   "Device Model:"  — SATA/SAS drives
    #   "Model Number:"  — NVMe drives
    #   "Model Family:"  — fallback (generic family name)
    _MODEL_PREFIXES = ("device model", "model number", "model family")
    for line in health_out.splitlines():
        if any(line.lower().startswith(p) for p in _MODEL_PREFIXES):
            sr.model = line.split(":", 1)[-1].strip()
            break

    # SMART health result — match only the specific health-assessment line to
    # avoid false positives from other lines that contain "passed"/"failed".
    for line in health_out.splitlines():
        if "smart overall-health" in line.lower():
            if "PASSED" in line:
                sr.passed = True
            elif "FAILED" in line:
                sr.passed = False
            break
    # else: None (unknown / NVMe without explicit line)

    # Critical attributes: smartctl -A
    attrs_out = _run("smartctl", "-A", device)
    if attrs_out:
        if "nvme" in device.lower():
            # NVMe drives do not expose ATA attributes 5/197/198.
            # Map NVMe-specific counters onto the same fields.
            sr.uncorrectable_errors, sr.pending_sectors = _parse_nvme_attrs(attrs_out)
        else:
            sr.reallocated_sectors = _parse_smart_attr(attrs_out, _ATTR_REALLOCATED_SECTORS)
            sr.pending_sectors     = _parse_smart_attr(attrs_out, _ATTR_PENDING_SECTORS)
            sr.uncorrectable_errors = _parse_smart_attr(attrs_out, _ATTR_UNCORRECTABLE)

    return sr

def _parse_nvme_attrs(attrs_output: str) -> tuple[int, int]:
    """
    Parse NVMe health indicators from `smartctl -A` output.

    NVMe drives do not use ATA attribute IDs. Instead, health data appears as
    labelled key-value pairs:
      Media and Data Integrity Errors:    0   →  maps to uncorrectable_errors
      Error Information Log Entries:      0   →  maps to pending_sectors

    Returns (media_errors, error_log_entries). Both default to 0.
    """
    media_errors = 0
    error_log    = 0
    for line in attrs_output.splitlines():
        lower = line.lower()
        if "media and data integrity errors" in lower:
            try:
                media_errors = int(line.split(":")[-1].strip())
            except ValueError:
                pass
        elif "error information log entries" in lower:
            try:
                error_log = int(line.split(":")[-1].strip())
            except ValueError:
                pass
    return media_errors, error_log

def _parse_smart_attr(attrs_output: str, attr_id: int) -> int:
    """
    Parse a SMART attribute RAW_VALUE from `smartctl -A` output.

    Lines look like:
      5 Reallocated_Sector_Ct   0x0032   100   100   000    Old_age   ...  0
    The RAW_VALUE is the last whitespace-separated token on the line.

    Returns 0 if the attribute is not found or cannot be parsed.
    """
    for line in attrs_output.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            if int(parts[0]) == attr_id:
                # RAW_VALUE is the 10th field (index 9) in standard smartctl -A output.
                # It may have an inline parenthetical like "7(0 200 0)" — strip it.
                raw = parts[9].split("(")[0].strip()
                return int(raw)
        except (ValueError, IndexError):
            pass
    return 0

def _read_partition_usage() -> list[PartitionInfo]:
    """
    Return usage info for mounted partitions via `df -P`.

    Skips pseudo-filesystems (tmpfs, devtmpfs, squashfs, overlay, etc.).
    """
    out = _run("df", "-P", "--block-size=1G")
    if not out:
        return []

    partitions = []
    for line in out.splitlines()[1:]:   # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        device     = parts[0]
        size_gb    = _safe_float(parts[1])
        used_pct_s = parts[4].rstrip("%")
        mountpoint = parts[5]

        # The pseudo-FS list (tmpfs, devtmpfs, squashfs, overlay, proc, sysfs…)
        # is captured by this single check — none of those start with "/dev/".
        if not device.startswith("/dev/"):
            continue

        try:
            used_pct = int(used_pct_s)
        except ValueError:
            continue

        partitions.append(PartitionInfo(
            mountpoint=mountpoint,
            device=device,
            size_gb=size_gb,
            used_pct=used_pct,
        ))

    return partitions

def _safe_float(value: str) -> float:
    """Parse a string to float, return 0.0 on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0
