"""
Memory and swap audit for BOB.

Checks swap usage correlated with available RAM, swappiness tuning,
and SSD wear risk from unnecessary swapping.

The check is split into two parts:
  1. MemorySnapshot.from_system() — collects data from /proc/meminfo,
                                    /proc/sys/vm/swappiness, swapon.
  2. check_memory(snapshot)       — pure logic, returns a CheckResult.

Score impact: deductions route to the "hardening" domain (same family as
rp_filter / ICMP sysctl parameters).

Usage:
    from bob.checks.memory import MemorySnapshot, check_memory

    snapshot = MemorySnapshot.from_system()
    result   = check_memory(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import _identity_t, _run
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# swappiness threshold above which we warn on SSD
_SSD_SWAPPINESS_THRESHOLD: int = 30

# Fraction of RAM that must still be available (0–1) for "unjustified" swap
# to trigger a warning.  0.50 = RAM is more than 50 % free while swap is used.
_RAM_FREE_THRESHOLD: float = 0.50

# Minimum swap usage (bytes) to consider "swap is in use" — avoids noise
# from 1–2 MB of hibernation data or rounding.
_MIN_SWAP_USED_KB: int = 32 * 1024   # 32 MB

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class MemorySnapshot:
    """
    Raw snapshot of memory and swap state.

    Args:
        mem_total_kb:     Total physical RAM in kB (MemTotal).
        mem_available_kb: Available RAM in kB (MemAvailable).
        swap_total_kb:    Total swap space in kB (SwapTotal).
        swap_free_kb:     Free swap space in kB (SwapFree).
        swappiness:       Current vm.swappiness value (0–200).
        swap_on_ssd:      True if any active swap device resides on an SSD.
        swap_devices:     List of active swap device/file paths.
    """
    mem_total_kb:     int       = 0
    mem_available_kb: int       = 0
    swap_total_kb:    int       = 0
    swap_free_kb:     int       = 0
    swappiness:       int       = 60
    swap_on_ssd:      bool      = False
    swap_devices:     list[str] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "MemorySnapshot":
        """
        Collect memory and swap state from the live system.

        Returns:
            Populated MemorySnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        # --- /proc/meminfo ---
        snap.mem_total_kb, snap.mem_available_kb, \
            snap.swap_total_kb, snap.swap_free_kb = _read_meminfo()

        # --- vm.swappiness ---
        snap.swappiness = _read_swappiness()

        # --- active swap devices ---
        snap.swap_devices = _read_swap_devices()

        # --- SSD detection ---
        snap.swap_on_ssd = _detect_swap_on_ssd(snap.swap_devices)

        return snap

# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_memory(
    snapshot: MemorySnapshot,
    *,
    t=None,
    profile_name: str = "server",
) -> CheckResult:
    """
    Audit memory and swap configuration.

    Scoring:
      - Swap on SSD with swappiness > _SSD_SWAPPINESS_THRESHOLD:  −1 pt (WARN)
      - Swap used + RAM > _RAM_FREE_THRESHOLD available:           WARN (no deduction)
      - Swappiness suboptimal (default 60 on server/workstation):  INFO only
      - No swap configured:                                        INFO only

    Args:
        snapshot:     MemorySnapshot from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        profile_name: Active profile. Affects recommended swappiness value
                      shown in finding detail ("server" → 1, "workstation" → 10).

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    swap_used_kb    = max(0, snapshot.swap_total_kb - snapshot.swap_free_kb)
    swap_used_mb    = swap_used_kb // 1024
    swap_total_mb   = snapshot.swap_total_kb // 1024
    mem_total_kb    = snapshot.mem_total_kb or 1   # avoid div/0
    mem_avail_ratio = snapshot.mem_available_kb / mem_total_kb

    # Recommended swappiness by profile:
    #   server      →  1  (minimize swap writes, latency-sensitive workloads)
    #   workstation → 10  (desktop responsiveness benefits from some swap headroom)
    # These are opinionated but widely cited values (Red Hat, Arch wiki, CIS).
    recommended_swappiness = 1 if profile_name not in ("workstation", "desktop") else 10

    # --- No swap ---
    if snapshot.swap_total_kb == 0:
        result.info(
            message=_t("memory.no_swap"),
            key="memory.no_swap",
        )
        return result

    # --- Swap stats (always shown) ---
    swap_pct = int(swap_used_kb * 100 / snapshot.swap_total_kb) if snapshot.swap_total_kb else 0
    result.info(
        message=_t(
            "memory.swap_stats",
            used_mb=swap_used_mb,
            total_mb=swap_total_mb,
            pct=swap_pct,
        ),
        key="memory.swap_stats",
    )

    # --- SSD wear: swap on SSD + high swappiness ---
    if snapshot.swap_on_ssd and snapshot.swappiness > _SSD_SWAPPINESS_THRESHOLD:
        result.warn_with_deduction(
            key="memory.swappiness_ssd_wear",
            message=_t("memory.swappiness_ssd_wear", value=snapshot.swappiness),
            points=1,
            detail=_t(
                "memory.swappiness_ssd_detail",
                recommended=recommended_swappiness,
            ),
            cmd=(
                f"sudo sysctl vm.swappiness={recommended_swappiness} && "
                f"echo 'vm.swappiness={recommended_swappiness}' | "
                f"sudo tee /etc/sysctl.d/99-swappiness.conf"
            ),
        )

    # --- Unjustified swap: RAM still mostly free AND swappiness is above
    # the recommended value AND significant swap is in use.
    # All three conditions are required to avoid false positives: Linux
    # voluntarily swaps cold LRU pages even with free RAM (kswapd aging).
    # Without the swappiness check, a system with swappiness=1 and minimal
    # historical swap use would trigger a spurious warning.
    elif (
        swap_used_kb >= _MIN_SWAP_USED_KB
        and mem_avail_ratio >= _RAM_FREE_THRESHOLD
        and snapshot.swappiness > recommended_swappiness
    ):
        ram_pct_free = int(mem_avail_ratio * 100)
        result.warn(
            message=_t(
                "memory.swappiness_unjustified",
                swap_pct=swap_pct,
                ram_pct=ram_pct_free,
                value=snapshot.swappiness,
            ),
            detail=_t(
                "memory.swappiness_unjustified_detail",
                recommended=recommended_swappiness,
            ),
            cmd=(
                f"sudo sysctl vm.swappiness={recommended_swappiness} && "
                f"echo 'vm.swappiness={recommended_swappiness}' | "
                f"sudo tee /etc/sysctl.d/99-swappiness.conf"
            ),
            key="memory.swappiness_unjustified",
        )

    # --- Suboptimal swappiness (default 60 on a server with RAM to spare) ---
    elif snapshot.swappiness > recommended_swappiness:
        result.info(
            message=_t(
                "memory.swappiness_suboptimal",
                value=snapshot.swappiness,
                recommended=recommended_swappiness,
            ),
            cmd=(
                f"sudo sysctl vm.swappiness={recommended_swappiness} && "
                f"echo 'vm.swappiness={recommended_swappiness}' | "
                f"sudo tee /etc/sysctl.d/99-swappiness.conf"
            ),
            key="memory.swappiness_suboptimal",
        )

    else:
        result.ok(
            message=_t("memory.swappiness_ok", value=snapshot.swappiness),
            key="memory.swappiness_ok",
        )

    return result

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_meminfo() -> tuple[int, int, int, int]:
    """
    Parse /proc/meminfo and return (MemTotal, MemAvailable, SwapTotal, SwapFree)
    in kB.  Returns (0, 0, 0, 0) on read error.
    """
    fields = {
        "MemTotal":     0,
        "MemAvailable": 0,
        "SwapTotal":    0,
        "SwapFree":     0,
    }
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii", errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].rstrip(":")
                if key in fields:
                    try:
                        fields[key] = int(parts[1])
                    except ValueError:
                        pass
    except OSError:
        pass
    return (
        fields["MemTotal"],
        fields["MemAvailable"],
        fields["SwapTotal"],
        fields["SwapFree"],
    )

def _read_swappiness() -> int:
    """Read vm.swappiness from /proc/sys/vm/swappiness. Returns 60 on error."""
    try:
        val = Path("/proc/sys/vm/swappiness").read_text(encoding="ascii", errors="ignore").strip()
        return int(val)
    except (OSError, ValueError):
        return 60

def _read_swap_devices() -> list[str]:
    """
    Return list of active swap device/file paths from `swapon`.
    Returns empty list if swapon is unavailable or no swap is active.

    --show=NAME outputs only the device/file column, making parsing explicit
    and independent of column order or spacing changes between swapon versions.
    """
    out = _run("swapon", "--show=NAME", "--noheadings", "--raw")
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]

def _detect_swap_on_ssd(swap_devices: list[str]) -> bool:
    """
    Return True if any swap device resides on a non-rotational (SSD/NVMe) disk.

    Checks /sys/block/<dev>/queue/rotational:
      0 = SSD/NVMe, 1 = HDD.

    Swap files are skipped (block device detection is unreliable for files).
    """
    for device in swap_devices:
        if not device.startswith("/dev/"):
            # Swap files: resolving the backing block device requires
            # stat + /proc/self/mountinfo cross-reference and is fragile.
            # Skipped for now — SSD detection is best-effort for block devices.
            continue

        dev_name = Path(device).name    # e.g. "sda5", "nvme0n1p3"

        # NVMe partitions: nvme0n1p3 → nvme0n1
        if re.match(r"nvme\d+n\d+p\d+", dev_name):
            block_dev = re.sub(r"p\d+$", "", dev_name)
        else:
            # SATA/SCSI: sda5 → sda; mmcblk0p1 → mmcblk0
            block_dev = re.sub(r"p?\d+$", "", dev_name)

        rotational_path = Path(f"/sys/block/{block_dev}/queue/rotational")
        try:
            if rotational_path.read_text(encoding="ascii", errors="ignore").strip() == "0":
                return True
        except OSError:
            pass

    return False
