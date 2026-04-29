"""
Kernel module security audit for BOB.

Two sub-checks are performed:

1. **Risky loaded modules** — detects known-dangerous kernel modules currently
   loaded via ``lsmod``.  These are rarely needed and widen the attack surface.

2. **Installed kernel cleanup** — lists installed kernel packages via ``dpkg``
   and flags obsolete ones that can be safely removed, following a
   profile-aware retention policy:
     - server  : keep running kernel + 2 fallbacks (3 total minimum)
     - desktop : keep running kernel + 1 fallback  (2 total minimum)
     - container : section is skipped entirely in runner.py

   A reboot-pending state (running kernel ≠ latest installed) suppresses the
   cleanup command — old kernels must only be removed after the system has
   successfully booted into the latest kernel.

The check is split into two parts:
  1. KernelModulesSnapshot.from_system() — collects raw data.
  2. check_kernel_modules(snapshot)       — pure logic, returns a CheckResult.

Usage:
    from bob.checks.kernel_modules import KernelModulesSnapshot, check_kernel_modules

    snapshot = KernelModulesSnapshot.from_system()
    result   = check_kernel_modules(snapshot, profile_name="server")
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import List, Tuple

from bob.checks._run import _command_exists, _identity_t, _run
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# Modules considered risky on a hardened server
# ---------------------------------------------------------------------------

# Filesystem modules — rarely needed; can be used to mount rogue media
_RISKY_FS: frozenset[str] = frozenset({
    "cramfs",
    "freevxfs",
    "jffs2",
    "hfs",
    "hfsplus",
    "squashfs",
    "udf",
    "usb_storage",   # lsmod uses underscores, not hyphens
})

# Network protocol modules — rarely needed, historically exploited or redundant
_RISKY_NET: frozenset[str] = frozenset({
    "dccp",
    "sctp",
    "rds",
    "tipc",
})

RISKY_MODULES: frozenset[str] = _RISKY_FS | _RISKY_NET

# Kernel version sort key — parses Ubuntu "MAJOR.MINOR.PATCH-ABI[-flavor]"
# and Debian "MAJOR.MINOR.PATCH+debN+N-arch" (separator is + not -)
_KVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)[-+]")

# Retention policy: minimum number of kernels to keep per profile
_RETENTION: dict[str, int] = {
    "server":    3,   # running + 2 fallbacks
    "desktop":   2,   # running + 1 fallback
    "container": 2,   # section is skipped in runner.py, but safe default
}


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class KernelModulesSnapshot:
    """
    Raw snapshot of kernel state relevant to security hardening.

    Args:
        lsmod_available:    True if the ``lsmod`` command exists on this system.
        loaded_modules:     Full set of currently loaded module names (from lsmod).
        dpkg_available:     True if ``dpkg-query`` is available (Debian/Ubuntu only).
        running_kernel:     Version string from ``uname -r`` (e.g. "6.8.0-52-generic").
        installed_kernels:  List of installed kernel version strings from dpkg.
    """
    lsmod_available:    bool       = False
    loaded_modules:     List[str]  = field(default_factory=list)
    dpkg_available:     bool       = False
    running_kernel:     str        = ""
    installed_kernels:  List[str]  = field(default_factory=list)
    apt_update_available: bool     = False
    apt_candidate_kernel: str      = ""
    apt_checked:          bool     = False

    @classmethod
    def from_system(cls) -> "KernelModulesSnapshot":
        """
        Collect kernel module and installed kernel data from the live system.

        Returns:
            Populated KernelModulesSnapshot. Never raises — errors reflected as defaults.
        """
        snap = cls()

        # --- Loaded modules (lsmod) -----------------------------------------
        if _command_exists("lsmod"):
            snap.lsmod_available = True
            out = _run("lsmod", timeout=10)
            if out:
                modules: list[str] = []
                for line in out.splitlines()[1:]:  # skip header row
                    parts = line.split()
                    if parts:
                        modules.append(parts[0].lower())
                snap.loaded_modules = modules

        # --- Running kernel (uname -r) --------------------------------------
        uname_out = _run("uname", "-r", timeout=5)
        if uname_out:
            snap.running_kernel = uname_out.strip()

        # --- Installed kernel packages (dpkg-query) -------------------------
        if _command_exists("dpkg-query"):
            snap.dpkg_available = True
            dpkg_out = _run(
                "dpkg-query", "-f", "${Package}\\n", "-W", "linux-image-[0-9]*",
                timeout=10,
            )
            if dpkg_out:
                snap.installed_kernels = _parse_installed_kernels(dpkg_out)

        # --- Kernel update availability (apt) --------------------------------
        checked, available, candidate = _query_apt_kernel_update()
        snap.apt_checked          = checked
        snap.apt_update_available = available
        snap.apt_candidate_kernel = candidate

        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_kernel_modules(
    snapshot: KernelModulesSnapshot,
    *,
    t=None,
    profile_name: str = "server",
) -> CheckResult:
    """
    Audit loaded kernel modules and installed kernel packages.

    Sub-check 1 — Risky loaded modules:
      - Any risky filesystem module loaded:   WARN  −1 pt
      - Any risky network protocol loaded:    WARN  −1 pt
      - lsmod unavailable:                    INFO only

    Sub-check 2 — Installed kernel cleanup (profile-aware):
      - Reboot pending (running ≠ latest):    INFO  (no command — reboot first)
      - Obsolete kernels present:             INFO  (explicit apt purge command)
      - Within retention policy:              silent

    Args:
        snapshot:     KernelModulesSnapshot from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        profile_name: "server" | "desktop" | "container".

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t or _identity_t
    result = CheckResult()

    # --- Sub-check 1: risky loaded modules ----------------------------------
    if not snapshot.lsmod_available:
        result.info(
            message=_t("kernel_modules.no_lsmod"),
            key="kernel_modules.no_lsmod",
        )
    else:
        loaded: set[str] = set(snapshot.loaded_modules or [])

        risky_fs = sorted(loaded & _RISKY_FS)
        if risky_fs:
            pkgs = ", ".join(risky_fs)
            result.warn(
                message=_t("kernel_modules.risky_fs", modules=pkgs),
                detail=_t("kernel_modules.risky_fs_detail"),
                cmd=_unload_cmd(risky_fs),
                nature="improvement",
                key="kernel_modules.risky_fs",
            )
            result.add_deduction(
                reason=_t("kernel_modules.risky_fs_reason", modules=pkgs),
                points=1,
                context="local",
                key="kernel_modules.risky_fs",
            )

        risky_net = sorted(loaded & _RISKY_NET)
        if risky_net:
            pkgs = ", ".join(risky_net)
            result.warn(
                message=_t("kernel_modules.risky_net", modules=pkgs),
                detail=_t("kernel_modules.risky_net_detail"),
                cmd=_unload_cmd(risky_net),
                nature="improvement",
                key="kernel_modules.risky_net",
            )
            result.add_deduction(
                reason=_t("kernel_modules.risky_net_reason", modules=pkgs),
                points=1,
                context="local",
                key="kernel_modules.risky_net",
            )

        if not result.findings:
            result.ok(
                message=_t("kernel_modules.ok"),
                key="kernel_modules.ok",
            )

    # --- Sub-check 2: installed kernel cleanup ------------------------------
    _check_installed_kernels(snapshot, profile_name, _t, result)

    return result


# ---------------------------------------------------------------------------
# Private helpers — kernel cleanup
# ---------------------------------------------------------------------------

def _query_apt_kernel_update() -> Tuple[bool, bool, str]:
    """
    Check whether a newer kernel is available via apt.

    Primary path  : apt-cache policy linux-image-generic  (Ubuntu, Mint)
    Fallback path : apt list --upgradable                  (Debian, no meta-package)

    Returns (checked, update_available, candidate_version_string).
    `checked=True` means apt was reachable and returned a usable answer.
    Never raises.
    """
    if not _command_exists("apt-cache"):
        return False, False, ""

    def _field(output: str, name: str) -> str:
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{name}:"):
                return stripped.split(":", 1)[1].strip()
        return ""

    # Primary path 1: meta-package (Ubuntu / Mint)
    out = _run("apt-cache", "policy", "linux-image-generic", timeout=15)
    if out:
        installed = _field(out, "Installed")
        candidate = _field(out, "Candidate")
        if installed and installed != "(none)" and candidate and candidate != "(none)":
            update = installed != candidate
            return True, update, (candidate if update else "")

    # Primary path 2: running kernel package (Debian — no meta-package)
    running_kernel = _run("uname", "-r", timeout=5).strip()
    if running_kernel:
        out = _run("apt-cache", "policy", f"linux-image-{running_kernel}", timeout=15)
        if out:
            installed = _field(out, "Installed")
            candidate = _field(out, "Candidate")
            if installed and installed != "(none)" and candidate and candidate != "(none)":
                update = installed != candidate
                return True, update, (candidate if update else "")

    # Fallback: scan upgradable list
    if _command_exists("apt"):
        out = _run("apt", "list", "--upgradable", timeout=20)
        if out:
            for line in out.splitlines():
                # e.g. linux-image-6.8.0-56-generic/noble-updates 6.8.0-56.57 amd64 [upgradable from: ...]
                if re.match(r"^linux-image-\d", line) and "upgradable from" in line:
                    parts = line.split()
                    return True, True, (parts[1] if len(parts) >= 2 else "")
            # apt ran, no linux-image in upgradable → up to date
            return True, False, ""

    return False, False, ""


def _kernel_sort_key(version: str) -> Tuple[int, int, int, int]:
    """Return a sortable tuple from a kernel version string.

    Handles Ubuntu "6.8.0-52-generic" and Debian "6.12.74+deb13+1-amd64".
    """
    m = _KVER_RE.match(version)
    if m:
        rest = version[m.end():]
        abi_m = re.match(r"(\d+)", rest)
        abi = int(abi_m.group(1)) if abi_m else 0
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), abi)
    return (0, 0, 0, 0)


def _parse_installed_kernels(dpkg_output: str) -> List[str]:
    """
    Extract version strings from ``dpkg-query`` output.

    Input lines are package names like "linux-image-6.8.0-52-generic".
    Returns a list of bare version strings: ["6.8.0-52-generic", …].
    """
    versions: list[str] = []
    for line in dpkg_output.splitlines():
        pkg = line.strip()
        if pkg.startswith("linux-image-"):
            version = pkg[len("linux-image-"):]
            if _KVER_RE.match(version):   # only numeric kernel versions
                versions.append(version)
    return versions


def _purge_cmd(versions: list[str]) -> str:
    """Build an ``apt purge`` command for the given kernel version list. Returns '' for empty list."""
    if not versions:
        return ""
    pkgs = [shlex.quote(f"linux-image-{v}") for v in versions]
    return "sudo apt purge " + " ".join(pkgs)


def _strip_unsigned(version: str) -> str:
    """Strip Debian -unsigned suffix so signed/unsigned variants compare equal."""
    return version[:-len("-unsigned")] if version.endswith("-unsigned") else version


def _check_installed_kernels(
    snapshot: KernelModulesSnapshot,
    profile_name: str,
    _t,
    result: CheckResult,
) -> None:
    """
    Append kernel cleanup findings to *result* (in-place).

    Logic:
      - Skip if dpkg unavailable or no installed kernels found.
      - Single kernel or running kernel not in dpkg list: INFO listing only.
      - Reboot pending (running ≠ latest): INFO only, no purge command.
      - Obsolete kernels beyond retention: INFO + explicit apt purge command.
      - Within retention policy: INFO listing of installed kernels.
    """
    if not snapshot.dpkg_available:
        return

    installed = snapshot.installed_kernels
    running   = snapshot.running_kernel

    if not installed or not running:
        return

    # Sort oldest → newest
    kernels = sorted(installed, key=_kernel_sort_key)
    most_recent = kernels[-1]

    # Format installed list with annotations
    reboot_pending = running in kernels and _strip_unsigned(running) != _strip_unsigned(most_recent)
    annotated = []
    for k in kernels:
        if k == running:
            annotated.append(f"{k} (*)")
        elif k == most_recent and reboot_pending:
            annotated.append(f"{k} (latest)")
        else:
            annotated.append(k)
    installed_str = ", ".join(annotated)

    # Kernel update availability (apt)
    if snapshot.apt_update_available and snapshot.apt_candidate_kernel:
        result.info(
            message=_t("kernel_modules.kernels_update_available",
                       candidate=snapshot.apt_candidate_kernel),
            cmd="sudo apt upgrade",
            cmd_type="action",
            key="kernel_modules.kernels_update_available",
        )
    elif snapshot.apt_checked and not snapshot.apt_update_available:
        result.ok(
            message=_t("kernel_modules.kernels_up_to_date", version=most_recent),
            key="kernel_modules.kernels_up_to_date",
        )

    # Single kernel or custom (non-dpkg) kernel — just list, nothing to clean
    if len(kernels) <= 1 or running not in kernels:
        result.info(
            message=_t("kernel_modules.kernels_listed", count=len(kernels), installed=installed_str),
            key="kernel_modules.kernels_listed",
        )
        return

    if reboot_pending:
        result.info(
            message=_t("kernel_modules.kernels_reboot_pending",
                       running=running, recent=most_recent),
            detail=_t("kernel_modules.kernels_reboot_pending_detail",
                      installed=installed_str, recent=most_recent),
            key="kernel_modules.kernels_reboot_pending",
        )
        return

    # Build the keep set: always include running + fill from newest down
    keep_count = _RETENTION.get(profile_name, 3)
    to_keep: set[str] = {running}
    for k in reversed(kernels):
        if len(to_keep) >= keep_count:
            break
        to_keep.add(k)

    to_remove = [k for k in kernels if k not in to_keep]

    if to_remove:
        if running == most_recent:
            _msg = _t("kernel_modules.kernels_obsolete_same",
                      count=len(to_remove), running=running)
        else:
            _msg = _t("kernel_modules.kernels_obsolete",
                      count=len(to_remove), running=running, recent=most_recent)
        result.info(
            message=_msg,
            detail=_t("kernel_modules.kernels_obsolete_detail",
                      installed=installed_str,
                      to_remove=", ".join(to_remove),
                      recent=most_recent),
            cmd=_purge_cmd(to_remove),
            cmd_type="check",
            key="kernel_modules.kernels_obsolete",
        )
    else:
        # Within retention — list kernels, nothing to clean
        result.info(
            message=_t("kernel_modules.kernels_listed", count=len(kernels), installed=installed_str),
            key="kernel_modules.kernels_listed",
        )


# ---------------------------------------------------------------------------
# Private helpers — module unload
# ---------------------------------------------------------------------------

def _unload_cmd(modules: list[str]) -> str:
    """Build a ``modprobe -r`` command for the given module list. Returns '' for empty list."""
    if not modules:
        return ""
    return "sudo modprobe -r " + " ".join(shlex.quote(m) for m in modules)
