"""
CPU security for BOB — speculative-execution vulnerabilities, the kernel
command-line switches that turn their mitigations off, and the IOMMU.

The kernel already did the hard part: for every hardware vulnerability it
knows (Spectre, Meltdown, MDS, Retbleed, …) it writes one line to
``/sys/devices/system/cpu/vulnerabilities/<name>`` — ``Not affected``,
``Mitigation: …`` or ``Vulnerable…`` — taking the CPU model, the loaded
microcode and the boot options into account. BOB reads that verdict; it does
not second-guess it with its own CPU tables.

This is a different fact from ``firmware``'s microcode check: that one asks
whether the microcode *package* is installed; this one reports what the kernel
measured on the running CPU. A missing package can leave a CPU vulnerable, and
an installed one can still leave it vulnerable (``mitigations=off``, a CPU the
vendor stopped updating).

Findings:
  - any vulnerability reported "Vulnerable"           : WARN −1
  - mitigation-weakening kernel command-line switches  : INFO
  - mitigated, but SMT still exposes it                : INFO (SMT is a trade-off)
  - "Unknown" status (often: decided by the hypervisor) : INFO
  - IOMMU not active (x86 only)                        : INFO
  - no vulnerabilities directory                       : INFO (unknown)
  - everything mitigated / not affected                : OK

Split into:
  1. CpuSecuritySnapshot.from_system() — reads sysfs and /proc/cmdline (never raises).
  2. check_cpu_security(snapshot, t)   — pure classification.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t, read_text_capped
from bob.scoring import CheckResult

_VULN_DIR = Path("/sys/devices/system/cpu/vulnerabilities")
_CMDLINE = Path("/proc/cmdline")
_IOMMU_CLASS = Path("/sys/class/iommu")

#: Boot switches that disable or weaken a mitigation (kernel-parameters.txt).
#: ``mitigations=auto,nosmt`` and ``nosmt`` *strengthen* — not listed.
_WEAKENING = (
    "mitigations=off", "nopti", "pti=off", "nospectre_v1", "nospectre_v2",
    "spectre_v2=off", "spectre_v2_user=off", "spectre_bhi=off",
    "spec_store_bypass_disable=off", "nospec_store_bypass_disable",
    "l1tf=off", "mds=off", "tsx_async_abort=off", "mmio_stale_data=off",
    "retbleed=off", "srbds=off", "gather_data_sampling=off",
    "reg_file_data_sampling=off", "spec_rstack_overflow=off", "tsx=on",
    "kpti=0",
)

_X86 = ("x86_64", "i686", "i586", "i386", "amd64")


@dataclass
class CpuSecuritySnapshot:
    """
    Args:
        statuses:     vulnerability name → the kernel's status line. Empty with
                      ``readable`` False when the directory could not be read.
        readable:     the vulnerabilities directory was listed.
        cmdline_flags: weakening switches found on the kernel command line.
        is_x86:       IOMMU reporting only makes sense where the platform
                      normally has one and the switch to turn it on exists.
        iommu_active: an IOMMU is registered (/sys/class/iommu non-empty);
                      None when that could not be read.
    """
    statuses:      "dict[str, str]" = field(default_factory=dict)
    readable:      bool = False
    #: v0.24.0 — the kernel has no vulnerabilities directory at all (ARMv6 on
    #: the Pi Zero, old kernels). Not BOB's blindness: the kernel reports
    #: nothing, as kernel_hardening treats an absent sysctl. Only a directory
    #: that exists but cannot be listed is "unknown".
    not_reported:  bool = False
    cmdline_flags: "list[str]" = field(default_factory=list)
    is_x86:        bool = False
    iommu_active:  "bool | None" = None

    @classmethod
    def from_system(cls) -> "CpuSecuritySnapshot":
        snap = cls(is_x86=platform.machine().lower() in _X86)
        try:
            names = sorted(os.listdir(_VULN_DIR))
            snap.readable = True
        except FileNotFoundError:
            snap.not_reported = True
            names = []
        except OSError:
            names = []
        for name in names:
            try:
                snap.statuses[name] = read_text_capped(
                    _VULN_DIR / name, encoding="utf-8", errors="replace").strip()
            except OSError:
                snap.statuses[name] = ""      # listed but unreadable → Unknown
        try:
            tokens = read_text_capped(_CMDLINE, encoding="utf-8",
                                      errors="replace").split()
            snap.cmdline_flags = [t for t in tokens if t in _WEAKENING]
        except OSError:
            pass
        try:
            snap.iommu_active = bool(os.listdir(_IOMMU_CLASS))
        except FileNotFoundError:
            snap.iommu_active = False         # class absent: no IOMMU driver bound
        except OSError:
            snap.iommu_active = None
        return snap


def _classify(status: str) -> str:
    """'vulnerable' | 'smt' | 'mitigated' | 'not_affected' | 'unknown'."""
    if status.startswith("Not affected"):
        return "not_affected"
    if status.startswith("Vulnerable"):
        return "vulnerable"
    if status.startswith("Mitigation"):
        return "smt" if "SMT vulnerable" in status else "mitigated"
    return "unknown"


def check_cpu_security(snapshot: CpuSecuritySnapshot,
                       t: "TranslationFunc | None" = None) -> CheckResult:
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.not_reported:
        result.info(message=_t("cpu_security.not_reported"), key="cpu_security.not_reported")
    elif not snapshot.readable:
        result.info(message=_t("cpu_security.unknown"), key="cpu_security.unknown")
    else:
        groups: "dict[str, list[str]]" = {}
        for name, status in snapshot.statuses.items():
            groups.setdefault(_classify(status), []).append(name)

        vulnerable = groups.get("vulnerable", [])
        if vulnerable:
            result.warn_with_deduction(
                key="cpu_security.vulnerable",
                message=_t("cpu_security.vulnerable", count=len(vulnerable),
                           names=", ".join(f"{n} ({snapshot.statuses[n]})"
                                           for n in vulnerable)),
                reason=_t("cpu_security.vulnerable_reason", count=len(vulnerable)),
                points=1,
                detail=_t("cpu_security.vulnerable_detail"),
                nature="action",
                cmd="grep -r . /sys/devices/system/cpu/vulnerabilities/",
                cmd_type="check",
            )
        if groups.get("smt"):
            result.info(message=_t("cpu_security.smt_exposed",
                                   names=", ".join(groups["smt"])),
                        detail=_t("cpu_security.smt_exposed_detail"),
                        key="cpu_security.smt_exposed")
        if groups.get("unknown"):
            result.info(message=_t("cpu_security.status_unknown",
                                   names=", ".join(groups["unknown"])),
                        key="cpu_security.status_unknown")
        if not vulnerable and not groups.get("unknown"):
            result.ok(message=_t("cpu_security.ok",
                                 mitigated=len(groups.get("mitigated", []))
                                 + len(groups.get("smt", [])),
                                 unaffected=len(groups.get("not_affected", []))),
                      key="cpu_security.ok")

    if snapshot.cmdline_flags:
        result.info(message=_t("cpu_security.cmdline_weakened",
                               flags=" ".join(snapshot.cmdline_flags)),
                    detail=_t("cpu_security.cmdline_weakened_detail"),
                    key="cpu_security.cmdline_weakened")

    if snapshot.is_x86:
        if snapshot.iommu_active is True:
            result.ok(message=_t("cpu_security.iommu_active"),
                      key="cpu_security.iommu_active")
        elif snapshot.iommu_active is False:
            result.info(message=_t("cpu_security.iommu_inactive"),
                        detail=_t("cpu_security.iommu_inactive_detail"),
                        key="cpu_security.iommu_inactive")

    return result
