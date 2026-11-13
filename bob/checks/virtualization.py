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

from bob.checks._run import TranslationFunc, _C_LOCALE_ENV, _command_exists, _identity_t, run_result
from bob.checks.firewall_stack import _libvirt_routing
from bob.scoring import CheckResult

#: v0.31.3 — the libvirt forward modes that write firewall rules (NAT, routed).
_LIBVIRT_RULE_MODES = frozenset({"nat", "route"})

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
    #: v0.35.0 — what libvirt's own rules let in, per bridge: bridge →
    #: (subnet, "replies" | "open"); None when not read ({"": "nft"} marks a
    #: libvirt nftables table, not weighed). Measured on Linux Mint 22.3,
    #: libvirt 10.0, UFW active routing deny (a30350): a NAT network's VM
    #: refused a new connection from outside (LIBVIRT_FWI accepts only
    #: RELATED,ESTABLISHED), a routed network's VM answered it — libvirt's
    #: chains sit ahead of UFW's in FORWARD.
    libvirt_inbound: "dict | None" = field(default_factory=dict)
    #: v0.35.0 — True once from_system has read libvirt's rules (an empty
    #: dict then means: listed, nothing admitted towards the VMs).
    libvirt_read:    bool = False
    #: v0.35.0 — where libvirt's rules were read: "iptables" (LIBVIRT_FWI) or
    #: "nftables" (table ip libvirt_network, chain guest_input).
    libvirt_backend: str = ""

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

        # libvirt/KVM — v0.31.3: while one of its networks is NAT or routed, the
        # two modes libvirt writes firewall rules for (libvirt's documentation:
        # "open" adds none), not because virsh, libvirtd or a virbr* interface
        # exists. Measured on Ubuntu Server 26.04 (libvirt 12.0.0): installed,
        # its network destroyed, nothing was inserted and the section still
        # warned; see firewall_stack._libvirt_routing.
        virbr = [i for i in ifaces if i.startswith("virbr")]
        if _libvirt_routing(modes=_LIBVIRT_RULE_MODES):
            snap.technologies.append(VirtTechnology(
                name="libvirt/KVM",
                iface=virbr[0] if virbr else "virbr0",
                risk_note="creates bridge interfaces that may insert iptables rules, bypassing UFW FORWARD policy",
            ))
            snap.libvirt_inbound, snap.libvirt_backend = _libvirt_rules()
            snap.libvirt_read = True

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
        # v0.35.0 — libvirt: what its own rules let in, read, not supposed.
        if tech.name == "libvirt/KVM" and snapshot.libvirt_read:
            inbound = snapshot.libvirt_inbound
            if inbound == {}:
                result.info(t("virt.libvirt_no_inbound"), key="virt.libvirt_no_inbound")
                continue
            if inbound is None or inbound == {"": "nft"}:
                result.info(
                    t("virt.libvirt_rules_unread" if inbound is None else "virt.libvirt_rules_nft"),
                    cmd="sudo nft list ruleset | grep -w virbr0; sudo iptables -S | grep -w virbr0",
                    cmd_type="check",
                    key="virt.libvirt_rules_unread",
                )
                continue
            for iface, (subnet, kind) in sorted(inbound.items()):
                q = shlex.quote(iface)
                nft = snapshot.libvirt_backend == "nftables"
                check = ("sudo nft list chain ip libvirt_network guest_input" if nft
                         else f"sudo iptables -S LIBVIRT_FWI | grep -w {q}")
                if kind == "open":
                    result.warn(
                        t("virt.libvirt_inbound_open_nft" if nft else "virt.libvirt_inbound_open",
                          iface=iface, subnet=subnet or "?"),
                        nature="improvement",
                        cmd=check,
                        cmd_type="check",
                        key="virt.bypass_risk",
                    )
                else:
                    result.info(
                        t("virt.libvirt_replies_only", iface=iface, subnet=subnet or "?"),
                        cmd=check,
                        cmd_type="check",
                        key="virt.libvirt_replies_only",
                    )
            continue
        # v0.31.4 — the check was `iptables -L FORWARD | grep <iface>`, which
        # can find nothing: without -v, iptables -L prints no interface, and
        # libvirt keeps its rules in its own chains (LIBVIRT_FWI/FWO/FWX, that
        # FORWARD jumps to) or in its own nftables table (libvirt_network).
        # Measured on Fedora 44, libvirt 12.0: 0 lines for that command and for
        # `-L FORWARD -v` under both backends; `nft list ruleset` found 38
        # (nftables backend) and 47 (iptables backend), `iptables -S` 0 and 13.
        # `iptables -S` stays for hosts whose iptables is the legacy one, which
        # nft does not list.
        iface = shlex.quote(tech.iface)
        result.warn(
            t("virt.bypass_risk",
              name=tech.name,
              iface=tech.iface,
              note=tech.risk_note),
            nature="improvement",
            cmd=f"sudo nft list ruleset | grep -w {iface}; sudo iptables -S | grep -w {iface}",
            cmd_type="check",
            key="virt.bypass_risk",
        )

    # v0.8.0 drift batch: snap-installed virt tools add bridge interfaces
    # invisible to UFW's FORWARD chain. +1pt per detected snap, capped at
    # 2pts cumulative so a host with multiple snap-virt tools doesn't get
    # disproportionately penalised.
    snap_deductions = 0
    for snap_pkg in snapshot.snap_net:
        if snap_deductions < 2:
            result.warn_with_deduction(
                key="virt.snap_network",
                message=t("virt.snap_network", pkg=snap_pkg),
                points=1,
                nature="improvement",
            )
            snap_deductions += 1
        else:
            result.warn(
                t("virt.snap_network", pkg=snap_pkg),
                key="virt.snap_network",
                nature="improvement",
            )

    return result


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

_FWI_ACCEPT = re.compile(r"^-A LIBVIRT_FWI\b.*-j ACCEPT\b")


def _libvirt_inbound() -> "dict | None":
    """What _libvirt_rules reads, without where it was read."""
    return _libvirt_rules()[0]


def _libvirt_rules() -> "tuple[dict | None, str]":
    """v0.35.0 — per libvirt bridge, what LIBVIRT_FWI admits towards the
    VMs: "replies" when every ACCEPT for it requires RELATED,ESTABLISHED
    (a NAT network), "open" when one admits new connections (a routed
    network, measured reached from outside past UFW). None when the chain
    cannot be listed; {"": "nft"} when libvirt's own nftables table exists
    and its guest_input chain could not be read."""
    res = run_result("iptables", "-S", "LIBVIRT_FWI")
    if not res.ok:
        # Measured on Fedora 44 (libvirt 12.0, nftables backend, firewalld
        # 2.x, a3f0350): the same rules in `table ip libvirt_network`, chain
        # guest_input — the NAT network refused from outside, the routed one
        # reached (firewalld's libvirt-routed-in policy accepts from any zone).
        chain = run_result("nft", "list", "chain", "ip", "libvirt_network", "guest_input")
        if chain.ok:
            return _libvirt_inbound_nft(chain.stdout), "nftables"
        nft = run_result("nft", "list", "table", "ip", "libvirt_network")
        return ({"": "nft"} if nft.ok else None), ""
    out: "dict" = {}
    for line in res.stdout.splitlines():
        if not _FWI_ACCEPT.search(line):
            continue
        m_if = re.search(r"\s-o\s+(\S+)", line)
        if not m_if:
            continue
        m_net = re.search(r"\s-d\s+(\S+)", line)
        kind = "replies" if re.search(r"--ctstate\s+\S*ESTABLISHED", line) else "open"
        prev = out.get(m_if.group(1), ("", "replies"))
        out[m_if.group(1)] = (m_net.group(1) if m_net else prev[0],
                              "open" if "open" in (kind, prev[1]) else "replies")
    return out, "iptables"


def _libvirt_inbound_nft(text: str) -> "dict":
    """v0.35.0 — _libvirt_inbound for libvirt's nftables chain guest_input:
    an ``accept`` with ``oif "<bridge>"`` is "replies" when it requires
    ``ct state established,related``, "open" otherwise."""
    out: "dict" = {}
    for line in text.splitlines():
        if not re.search(r"\baccept\s*$", line.strip()):
            continue
        m_if = re.search(r'\boif\s+"?([^"\s]+)"?', line)
        if not m_if:
            continue
        m_net = re.search(r"\bip\s+daddr\s+(\S+)", line)
        m_ct = re.search(r"\bct\s+state\s+(\{[^}]*\}|\S+)", line)
        states = set(re.findall(r"[a-z]+", m_ct.group(1))) if m_ct else set()
        kind = "replies" if states and states <= {"established", "related"} else "open"
        prev = out.get(m_if.group(1), ("", "replies"))
        out[m_if.group(1)] = (m_net.group(1) if m_net else prev[0],
                              "open" if "open" in (kind, prev[1]) else "replies")
    return out


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


