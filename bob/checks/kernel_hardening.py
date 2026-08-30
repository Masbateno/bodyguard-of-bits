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

def _sysctl_int(key: str) -> "int | None":
    """Read a sysctl value from /proc/sys as int, or None if it cannot be read.

    None means "this kernel does not expose the knob", and it is a distinct
    answer from any value. Until v0.15.0 the reader took a hardened *default*
    instead — ptrace_scope fell back to 1, kptr_restrict to 1, ASLR to 2 — so a
    kernel built without Yama, or one where `yama` is absent from the boot
    `lsm=` list, produced an OK finding stating that ptrace was restricted and
    kernel pointers hidden. Neither protection existed. Reporting a missing
    control as an enabled one is the worst answer an auditor can give, and it
    was the *default* answer.
    """
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return int(path.read_text(encoding="ascii", errors="ignore").strip())
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class KernelHardeningSnapshot:
    """
    Raw kernel hardening parameters read from the live system.

    Args:
    Every field is ``None`` when the kernel does not expose that knob — a
    distinct answer from any value, and never a stand-in for one.

    Args:
        aslr:           kernel.randomize_va_space  (0=off, 1=conservative, 2=full)
        ptrace_scope:   kernel.yama.ptrace_scope   (0=classic, 1=restricted, 2=admin, 3=no-attach)
        suid_dumpable:  fs.suid_dumpable            (0=no dump, 1=all, 2=root-only)
        kptr_restrict:  kernel.kptr_restrict        (0=off, 1=restricted, 2=full)
        dmesg_restrict: kernel.dmesg_restrict       (0=open, 1=restricted)
    """
    aslr:           "int | None" = None
    ptrace_scope:   "int | None" = None
    suid_dumpable:  "int | None" = None
    kptr_restrict:  "int | None" = None
    dmesg_restrict: "int | None" = None

    @classmethod
    def from_system(cls) -> "KernelHardeningSnapshot":
        """Read all parameters from /proc/sys. Never raises."""
        return cls(
            aslr=_sysctl_int("kernel.randomize_va_space"),
            ptrace_scope=_sysctl_int("kernel.yama.ptrace_scope"),
            suid_dumpable=_sysctl_int("fs.suid_dumpable"),
            kptr_restrict=_sysctl_int("kernel.kptr_restrict"),
            dmesg_restrict=_sysctl_int("kernel.dmesg_restrict"),
        )


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

_SYSCTL_CONF = "/etc/sysctl.d/99-hardening.conf"

# Field name -> the sysctl an operator would look for, for the "not exposed"
# message. Keeping the mapping here rather than inline keeps the check body
# readable and the names in one place.
_SYSCTL_NAMES = {
    "aslr":           "kernel.randomize_va_space",
    "ptrace_scope":   "kernel.yama.ptrace_scope",
    "suid_dumpable":  "fs.suid_dumpable",
    "kptr_restrict":  "kernel.kptr_restrict",
    "dmesg_restrict": "kernel.dmesg_restrict",
}


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
    # Knobs this kernel does not expose. Reported once, together, as an INFO:
    # an absent control is neither a pass nor a scoreable failure, and saying
    # so is the only honest answer.
    _missing: list[str] = []

    # --- ASLR ---
    if snapshot.aslr is None:
        _missing.append(_SYSCTL_NAMES["aslr"])
    elif snapshot.aslr == 2:
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
            nature="action",
        )

    # --- ptrace scope ---
    if snapshot.ptrace_scope is None:
        _missing.append(_SYSCTL_NAMES["ptrace_scope"])
    elif snapshot.ptrace_scope >= 1:
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
            nature="action",
        )

    # --- SUID dumpable ---
    if snapshot.suid_dumpable is None:
        _missing.append(_SYSCTL_NAMES["suid_dumpable"])
    elif snapshot.suid_dumpable == 0:
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
            nature="action",
        )

    # --- kptr_restrict (INFO only) ---
    if snapshot.kptr_restrict is None:
        _missing.append(_SYSCTL_NAMES["kptr_restrict"])
    elif snapshot.kptr_restrict >= 1:
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
    if snapshot.dmesg_restrict is None:
        _missing.append(_SYSCTL_NAMES["dmesg_restrict"])
    elif snapshot.dmesg_restrict >= 1:
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

    if _missing:
        result.info(
            message=_t("kernel_hardening.params_unavailable",
                       params=", ".join(_missing)),
            detail=_t("kernel_hardening.params_unavailable_detail"),
            key="kernel_hardening.params_unavailable",
        )

    return result
