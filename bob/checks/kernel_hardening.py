"""
Kernel hardening check for BOB (CHECK 36).

Audits kernel security parameters that are commonly misconfigured:
  - ASLR          (kernel.randomize_va_space)
  - ptrace scope  (kernel.yama.ptrace_scope)
  - SUID dumpable (fs.suid_dumpable)
  - kptr_restrict (kernel.kptr_restrict)
  - dmesg_restrict (kernel.dmesg_restrict)
  - v0.24.0 kernel attack surface, INFO-only:
      unprivileged eBPF   (kernel.unprivileged_bpf_disabled)
      perf events         (kernel.perf_event_paranoid)
      user namespaces     (user.max_user_namespaces, plus the Debian
                           kernel.unprivileged_userns_clone and the Ubuntu
                           kernel.apparmor_restrict_unprivileged_userns)

The check is split into two parts:
  1. KernelHardeningSnapshot.from_system() — reads /proc/sys values.
  2. check_kernel_hardening(snapshot)       — pure logic, returns CheckResult.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import (SYSCTL_CONF, TranslationFunc, _identity_t, sysctl_fix,
                             sysctl_fix_cmd)
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
        bpf_unpriv_disabled: kernel.unprivileged_bpf_disabled (0=allowed,
                        1=disabled until reboot, 2=disabled, admin may re-enable)
        perf_paranoid:  kernel.perf_event_paranoid  (-1..2 upstream; 3/4 are
                        Debian/Ubuntu patches that disable perf for users)
        max_userns:     user.max_user_namespaces    (0 = user namespaces off)
        userns_clone:   kernel.unprivileged_userns_clone — Debian/Ubuntu patch
                        only; None elsewhere is normal, not "unreadable"
        userns_apparmor: kernel.apparmor_restrict_unprivileged_userns — Ubuntu
                        23.10+ only; None elsewhere is normal
    """
    aslr:           "int | None" = None
    ptrace_scope:   "int | None" = None
    suid_dumpable:  "int | None" = None
    kptr_restrict:  "int | None" = None
    dmesg_restrict: "int | None" = None
    bpf_unpriv_disabled: "int | None" = None
    perf_paranoid:  "int | None" = None
    max_userns:     "int | None" = None
    userns_clone:   "int | None" = None
    userns_apparmor: "int | None" = None

    @classmethod
    def from_system(cls) -> "KernelHardeningSnapshot":
        """Read all parameters from /proc/sys. Never raises."""
        return cls(
            aslr=_sysctl_int("kernel.randomize_va_space"),
            ptrace_scope=_sysctl_int("kernel.yama.ptrace_scope"),
            suid_dumpable=_sysctl_int("fs.suid_dumpable"),
            kptr_restrict=_sysctl_int("kernel.kptr_restrict"),
            dmesg_restrict=_sysctl_int("kernel.dmesg_restrict"),
            bpf_unpriv_disabled=_sysctl_int("kernel.unprivileged_bpf_disabled"),
            perf_paranoid=_sysctl_int("kernel.perf_event_paranoid"),
            max_userns=_sysctl_int("user.max_user_namespaces"),
            userns_clone=_sysctl_int("kernel.unprivileged_userns_clone"),
            userns_apparmor=_sysctl_int("kernel.apparmor_restrict_unprivileged_userns"),
        )


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

#: Kept as the module's name for the shared constant so existing
#: references and tests keep resolving.
_SYSCTL_CONF = SYSCTL_CONF

# Field name -> the sysctl an operator would look for, for the "not exposed"
# message. Keeping the mapping here rather than inline keeps the check body
# readable and the names in one place.
_SYSCTL_NAMES = {
    "aslr":           "kernel.randomize_va_space",
    "ptrace_scope":   "kernel.yama.ptrace_scope",
    "suid_dumpable":  "fs.suid_dumpable",
    "kptr_restrict":  "kernel.kptr_restrict",
    "dmesg_restrict": "kernel.dmesg_restrict",
    "bpf_unpriv_disabled": "kernel.unprivileged_bpf_disabled",
    "perf_paranoid":  "kernel.perf_event_paranoid",
    "max_userns":     "user.max_user_namespaces",
}


def _fix(sysctl_key: str, value: int) -> dict:
    """Command and native action for one kernel sysctl. See `sysctl_fix`."""
    return sysctl_fix(f"{sysctl_key}={value}")


def _fix_cmd(sysctl_key: str, value: int) -> str:
    """Return a sysctl fix command that applies immediately and persists across reboots.

    The persisting half is shared with `hardening` now: it was written twice,
    and both copies appended unconditionally.
    """
    return sysctl_fix_cmd(f"{sysctl_key}={value}")


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
            **_fix("kernel.randomize_va_space", 2),
            key="kernel_hardening.aslr_conservative",
        )
    else:
        result.warn_with_deduction(
            key="kernel_hardening.aslr_disabled",
            message=_t("kernel_hardening.aslr_disabled"),
            points=1,
            **_fix("kernel.randomize_va_space", 2),
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
            **_fix("kernel.yama.ptrace_scope", 1),
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
            **_fix("fs.suid_dumpable", 0),
            key="kernel_hardening.suid_dump_root",
        )
    else:
        result.warn_with_deduction(
            key="kernel_hardening.suid_dump_all",
            message=_t("kernel_hardening.suid_dump_all"),
            points=1,
            detail=_t("kernel_hardening.suid_dump_all_detail"),
            **_fix("fs.suid_dumpable", 0),
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
            **_fix("kernel.kptr_restrict", 1),
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
            **_fix("kernel.dmesg_restrict", 1),
            key="kernel_hardening.dmesg_exposed",
        )

    # --- Kernel attack surface (v0.24.0, INFO only) --------------------------
    # Each of these opens a large kernel interface to unprivileged users, and
    # each has been the entry point of real local-root exploits. None is
    # scored: the right setting depends on what the host runs.

    # Unprivileged eBPF: the verifier is the barrier, and verifier bugs are a
    # recurring source of LPEs. 1 and 2 both deny it today; 2 is the default
    # since Linux 5.16 on most distributions.
    if snapshot.bpf_unpriv_disabled is None:
        _missing.append(_SYSCTL_NAMES["bpf_unpriv_disabled"])
    elif snapshot.bpf_unpriv_disabled >= 1:
        result.ok(message=_t("kernel_hardening.bpf_unpriv_ok",
                             val=snapshot.bpf_unpriv_disabled),
                  key="kernel_hardening.bpf_unpriv_ok")
    else:
        result.info(
            message=_t("kernel_hardening.bpf_unpriv_enabled"),
            detail=_t("kernel_hardening.bpf_unpriv_enabled_detail"),
            **_fix("kernel.unprivileged_bpf_disabled", 2),
            key="kernel_hardening.bpf_unpriv_enabled",
        )

    # perf events: ≤1 lets users profile the kernel (side channels, a large
    # syscall surface). 2 is the upstream ceiling; Debian/Ubuntu's 3 and 4
    # (perf off for users) only exist with their patch, so the advice is 2.
    if snapshot.perf_paranoid is None:
        _missing.append(_SYSCTL_NAMES["perf_paranoid"])
    elif snapshot.perf_paranoid >= 2:
        result.ok(message=_t("kernel_hardening.perf_ok", val=snapshot.perf_paranoid),
                  key="kernel_hardening.perf_ok")
    else:
        result.info(
            message=_t("kernel_hardening.perf_permissive", val=snapshot.perf_paranoid),
            detail=_t("kernel_hardening.perf_permissive_detail"),
            **_fix("kernel.perf_event_paranoid", 2),
            key="kernel_hardening.perf_permissive",
        )

    # Unprivileged user namespaces: dual-use. They are how browser sandboxes,
    # flatpak and rootless containers work, and how many kernel LPEs reach
    # code that used to need root. Reported as a state, never with a fix to
    # run — turning them off breaks those tools.
    if snapshot.max_userns is None:
        _missing.append(_SYSCTL_NAMES["max_userns"])
    elif snapshot.max_userns == 0:
        result.ok(message=_t("kernel_hardening.userns_restricted",
                             how="user.max_user_namespaces=0"),
                  key="kernel_hardening.userns_restricted")
    elif snapshot.userns_clone == 0:
        result.ok(message=_t("kernel_hardening.userns_restricted",
                             how="kernel.unprivileged_userns_clone=0"),
                  key="kernel_hardening.userns_restricted")
    elif snapshot.userns_apparmor is not None and snapshot.userns_apparmor >= 1:
        result.ok(message=_t("kernel_hardening.userns_restricted",
                             how="kernel.apparmor_restrict_unprivileged_userns=1"),
                  key="kernel_hardening.userns_restricted")
    else:
        result.info(
            message=_t("kernel_hardening.userns_allowed"),
            detail=_t("kernel_hardening.userns_allowed_detail"),
            key="kernel_hardening.userns_allowed",
        )

    if _missing:
        result.info(
            message=_t("kernel_hardening.params_unavailable",
                       params=", ".join(_missing)),
            detail=_t("kernel_hardening.params_unavailable_detail"),
            key="kernel_hardening.params_unavailable",
        )

    return result
