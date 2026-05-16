"""
Virtualization security check for BOB.

Detects active hypervisors (libvirt/KVM, VirtualBox, VMware, LXD/LXC)
and Snap network confinement that may create bridge interfaces and
manipulate iptables directly, bypassing UFW rules.

The same risk pattern as Docker: bridge interfaces (virbr0, vboxnet*,
lxdbr0, vmnet*) can insert their own iptables rules, making UFW's
FORWARD policy ineffective for traffic routed through those interfaces.

Split into two parts:
  1. VirtSnapshot.from_system() — collects data via subprocess.
  2. check_virtualization(snapshot, t) — pure logic, returns CheckResult.

Usage:
    from bob.checks.virtualization import VirtSnapshot, check_virtualization

    snapshot = VirtSnapshot.from_system()
    result = check_virtualization(snapshot, t=t)
"""

from __future__ import annotations

import logging
import re
import shlex
import subprocess
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _C_LOCALE_ENV, _command_exists, _identity_t
from bob.scoring import CheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VirtTechnology:
    """A detected virtualisation technology."""
    name:        str   # Human-readable name, e.g. "libvirt/KVM"
    iface:       str   # Bridge interface name, e.g. "virbr0"
    risk_note:   str   # Short explanation of the UFW bypass risk


@dataclass
class VirtSnapshot:
    """
    System-level virtualisation data collected via subprocess.

    Attributes:
        technologies:  List of detected virtualisation technologies.
        snap_net:      List of snap packages with network interfaces.
    """
    technologies: list[VirtTechnology] = field(default_factory=list)
    snap_net:     list[str]            = field(default_factory=list)

    @classmethod
    def from_system(cls) -> VirtSnapshot:
        """
        Collect virtualisation data from the running system.

        Checks for:
          - libvirt/KVM  — virsh or libvirtd + virbr* interfaces
          - VirtualBox   — vboxmanage or vboxdrv + vboxnet* interfaces
          - VMware       — vmware binary + vmnet* interfaces
          - LXD/LXC      — lxd or lxc binary + lxdbr* interfaces
          - Snap network — snaps with active network interfaces
        """
        snap = cls()
        ifaces = _get_network_interfaces()

        # libvirt/KVM
        virbr = [i for i in ifaces if i.startswith("virbr")]
        if _command_exists("virsh") or _command_exists("libvirtd") or virbr:
            snap.technologies.append(VirtTechnology(
                name="libvirt/KVM",
                iface=virbr[0] if virbr else "virbr0",
                risk_note="creates bridge interfaces that may insert iptables rules, bypassing UFW FORWARD policy",
            ))

        # VirtualBox
        vboxnet = [i for i in ifaces if i.startswith("vboxnet")]
        if _command_exists("vboxmanage") or vboxnet:
            snap.technologies.append(VirtTechnology(
                name="VirtualBox",
                iface=vboxnet[0] if vboxnet else "vboxnet0",
                risk_note="creates host-only and bridged interfaces that manipulate iptables directly",
            ))

        # VMware
        vmnet = [i for i in ifaces if i.startswith("vmnet")]
        if _command_exists("vmware") or vmnet:
            snap.technologies.append(VirtTechnology(
                name="VMware",
                iface=vmnet[0] if vmnet else "vmnet1",
                risk_note="creates virtual network interfaces that may bypass UFW via iptables",
            ))

        # LXD / LXC
        lxdbr = [i for i in ifaces if i.startswith("lxdbr") or i.startswith("lxcbr")]
        if _command_exists("lxd") or _command_exists("lxc") or lxdbr:
            snap.technologies.append(VirtTechnology(
                name="LXD/LXC",
                iface=lxdbr[0] if lxdbr else "lxdbr0",
                risk_note="creates bridge interfaces with iptables rules that may bypass UFW",
            ))

        # Snap network packages
        snap.snap_net = _get_snap_network_packages()

        return snap


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_virtualization(snapshot: VirtSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse virtualisation snapshot and return a CheckResult.

    Warns when active hypervisors create bridge interfaces that may
    manipulate iptables directly, bypassing UFW rules — the same
    risk pattern as Docker without daemon.json iptables=false.
    """
    if t is None:
        t = _identity_t

    result = CheckResult()

    if not snapshot.technologies and not snapshot.snap_net:
        result.ok(t("virt.none_detected"), key="virt.none_detected")
        return result

    for tech in snapshot.technologies:
        result.warn(
            t("virt.bypass_risk",
              name=tech.name,
              iface=tech.iface,
              note=tech.risk_note),
            nature="improvement",
            cmd=f"sudo iptables -L FORWARD | grep {shlex.quote(tech.iface)}",
            cmd_type="check",
            key="virt.bypass_risk",
        )

    for snap_pkg in snapshot.snap_net:
        result.warn(
            t("virt.snap_network", pkg=snap_pkg),
            key="virt.snap_network",
        )

    return result


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _get_network_interfaces() -> list[str]:
    """Return list of active network interface names."""
    try:
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=5,
            env=_C_LOCALE_ENV,
        )
        return re.findall(r"^\d+:\s+(\S+):", result.stdout, re.MULTILINE)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return []


def _get_snap_network_packages() -> list[str]:
    """Return snap packages with active network plug connections."""
    try:
        result = subprocess.run(
            ["snap", "connections", "--all"],
            capture_output=True, text=True, timeout=10,
            env=_C_LOCALE_ENV,
        )
        pkgs = []
        for line in result.stdout.splitlines():
            if "network" in line and "-" not in line.split()[-1]:
                parts = line.split()
                if parts:
                    pkg = parts[1].split(":")[0]
                    if pkg not in pkgs and pkg != "snapd":
                        pkgs.append(pkg)
        return pkgs
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return []


