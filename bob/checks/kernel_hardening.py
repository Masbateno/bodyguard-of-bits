"""
Kernel hardening check for BOB (CHECK 36).

Audits kernel security parameters that are commonly misconfigured:
  - ASLR          (kernel.randomize_va_space)
  - ptrace scope  (kernel.yama.ptrace_scope)
  - SUID dumpable (fs.suid_dumpable)
  - kptr_restrict (kernel.kptr_restrict)
  - dmesg_restrict (kernel.dmesg_restrict)

The check is split into two parts:
  1. KernelHardeningSnapshot.from_system() — reads /proc/sys values.
  2. check_kernel_hardening(snapshot)       — pure logic, returns CheckResult.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# Helpers (self-contained — no import from hardening.py)
# ---------------------------------------------------------------------------

def _sysctl_int(key: str, default: int) -> int:
    """Read a sysctl value from /proc/sys as int."""
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return int(path.read_text(encoding="ascii", errors="ignore").strip())
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class KernelHardeningSnapshot:
    """
    Raw kernel hardening parameters read from the live system.

    Args:
        aslr:           kernel.randomize_va_space  (0=off, 1=conservative, 2=full)
        ptrace_scope:   kernel.yama.ptrace_scope   (0=classic, 1=restricted, 2=admin, 3=no-attach)
        suid_dumpable:  fs.suid_dumpable            (0=no dump, 1=all, 2=root-only)
        kptr_restrict:  kernel.kptr_restrict        (0=off, 1=restricted, 2=full)
        dmesg_restrict: kernel.dmesg_restrict       (0=open, 1=restricted)
    """
    aslr:           int = 2
    ptrace_scope:   int = 1
    suid_dumpable:  int = 0
    kptr_restrict:  int = 1
    dmesg_restrict: int = 0

    @classmethod
    def from_system(cls) -> "KernelHardeningSnapshot":
        """Read all parameters from /proc/sys. Never raises."""
        return cls(
            aslr=_sysctl_int("kernel.randomize_va_space", default=2),
            ptrace_scope=_sysctl_int("kernel.yama.ptrace_scope", default=1),
            suid_dumpable=_sysctl_int("fs.suid_dumpable", default=0),
            kptr_restrict=_sysctl_int("kernel.kptr_restrict", default=1),
            dmesg_restrict=_sysctl_int("kernel.dmesg_restrict", default=0),
        )


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

_SYSCTL_CONF = "/etc/sysctl.d/99-hardening.conf"


def _fix_cmd(sysctl_key: str, value: int) -> str:
    """Return a sysctl fix command that applies immediately and persists across reboots."""
    param = f"{sysctl_key}={value}"
    return (
        f"sudo sysctl -w {param} && "
        f"echo '{param}' | sudo tee -a {_SYSCTL_CONF}"
    )


def check_kernel_hardening(snapshot: KernelHardeningSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check kernel hardening parameters.

    Deductions (max −3 pts):
      - ASLR disabled (=0):        −1 pt
      - ptrace unrestricted (=0):  −1 pt
      - SUID dumpable (=1):        −1 pt

    INFO-only (no deduction):
      - ASLR conservative (=1)
      - kptr_restrict=0
      - dmesg_restrict=0
      - suid_dumpable=2 (root-only dumps)
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- ASLR ---
    if snapshot.aslr == 2:
        result.ok(
            message=_t("kernel_hardening.aslr_full"),
            key="kernel_hardening.aslr_full",
        )
    elif snapshot.aslr == 1:
        result.info(
            message=_t("kernel_hardening.aslr_conservative"),
            cmd=_fix_cmd("kernel.randomize_va_space", 2),
            key="kernel_hardening.aslr_conservative",
        )
    else:
        result.warn_with_deduction(
            key="kernel_hardening.aslr_disabled",
            message=_t("kernel_hardening.aslr_disabled"),
            points=1,
            cmd=_fix_cmd("kernel.randomize_va_space", 2),
        )

    # --- ptrace scope ---
    if snapshot.ptrace_scope >= 1:
        result.ok(
            message=_t("kernel_hardening.ptrace_ok", scope=snapshot.ptrace_scope),
            key="kernel_hardening.ptrace_ok",
        )
    else:
        result.warn_with_deduction(
            key="kernel_hardening.ptrace_unrestricted",
            message=_t("kernel_hardening.ptrace_unrestricted"),
            points=1,
            cmd=_fix_cmd("kernel.yama.ptrace_scope", 1),
        )

    # --- SUID dumpable ---
    if snapshot.suid_dumpable == 0:
        result.ok(
            message=_t("kernel_hardening.suid_dump_ok"),
            key="kernel_hardening.suid_dump_ok",
        )
    elif snapshot.suid_dumpable == 2:
        result.info(
            message=_t("kernel_hardening.suid_dump_root"),
            detail=_t("kernel_hardening.suid_dump_root_detail"),
            cmd=_fix_cmd("fs.suid_dumpable", 0),
            key="kernel_hardening.suid_dump_root",
        )
    else:
        result.warn_with_deduction(
            key="kernel_hardening.suid_dump_all",
            message=_t("kernel_hardening.suid_dump_all"),
            points=1,
            detail=_t("kernel_hardening.suid_dump_all_detail"),
            cmd=_fix_cmd("fs.suid_dumpable", 0),
        )

    # --- kptr_restrict (INFO only) ---
    if snapshot.kptr_restrict >= 1:
        result.ok(
            message=_t("kernel_hardening.kptr_ok", val=snapshot.kptr_restrict),
            key="kernel_hardening.kptr_ok",
        )
    else:
        result.info(
            message=_t("kernel_hardening.kptr_exposed"),
            detail=_t("kernel_hardening.kptr_exposed_detail"),
            cmd=_fix_cmd("kernel.kptr_restrict", 1),
            key="kernel_hardening.kptr_exposed",
        )

    # --- dmesg_restrict (INFO only) ---
    if snapshot.dmesg_restrict >= 1:
        result.ok(
            message=_t("kernel_hardening.dmesg_ok"),
            key="kernel_hardening.dmesg_ok",
        )
    else:
        result.info(
            message=_t("kernel_hardening.dmesg_exposed"),
            detail=_t("kernel_hardening.dmesg_exposed_detail"),
            cmd=_fix_cmd("kernel.dmesg_restrict", 1),
            key="kernel_hardening.dmesg_exposed",
        )

    return result
