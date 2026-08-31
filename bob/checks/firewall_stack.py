"""
Firewall stack analysis for BOB.

Detects raw iptables/nftables rules that bypass or conflict with UFW,
and verifies that IP forwarding is only enabled when Docker or VPN is present.

The check is split into two parts:
  1. FirewallStackSnapshot.from_system() — collects raw data via subprocess.
  2. check_firewall_stack(snapshot)       — pure logic, returns a CheckResult.

Usage:
    from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack

    snapshot = FirewallStackSnapshot.from_system()
    result   = check_firewall_stack(snapshot)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

# `iptables -L` opens every chain with this header under LC_ALL=C, rules or no
# rules. Its absence means the listing did not come from iptables.
_IPTABLES_CHAIN_RE = re.compile(r"^Chain\s+\S+", re.MULTILINE)


@dataclass
class FirewallStackSnapshot:
    """
    Raw snapshot of the firewall stack state collected from the system.

    Args:
        input_raw_accepts:   ACCEPT rules in the iptables INPUT chain that do
                             NOT jump to a ufw-* chain (potential bypasses).
        forward_raw_accepts: ACCEPT rules in the iptables FORWARD chain that
                             do NOT jump to a ufw-* chain.
        nftables_active:     True if nftables has non-UFW, non-iptables-compat tables.
        rules_readable:      False when the ruleset could not be listed.
        ip_forward:          True if /proc/sys/net/ipv4/ip_forward == "1".
        docker_present:      True if Docker is installed/running.
        wireguard_present:   True if WireGuard is configured.
        libvirt_present:     True if libvirt/KVM is installed.
    """
    input_raw_accepts:   list[str] = field(default_factory=list)
    forward_raw_accepts: list[str] = field(default_factory=list)
    nftables_active:     bool = False
    # False when the ruleset could not be listed at all — distinct from
    # having listed it and found nothing.
    rules_readable:      bool = True
    ip_forward:          bool = False
    docker_present:      bool = False
    wireguard_present:   bool = False
    libvirt_present:     bool = False

    @classmethod
    def from_system(cls) -> "FirewallStackSnapshot":
        """
        Collect firewall stack state from the live system via subprocess.

        Returns:
            Populated FirewallStackSnapshot. Never raises — errors are
            reflected as empty/False values.
        """
        input_out   = _run("iptables", "-L", "INPUT",   "-n")
        forward_out = _run("iptables", "-L", "FORWARD", "-n")
        input_raw   = _parse_raw_accepts(input_out)
        forward_raw = _parse_raw_accepts(forward_out)

        nft_out         = _run("nft", "list", "ruleset") if _command_exists("nft") else ""
        nftables_active = _has_user_nft_rules(nft_out)

        # Both `iptables -L` and `nft list ruleset` need CAP_NET_ADMIN and write
        # their refusal to stderr, leaving stdout empty — which read as "no
        # rules" and produced an explicit `firewall_drivers.no_issues` OK about
        # a ruleset that was never seen.
        #
        # A working `iptables -L` always prints its chain headers, even with no
        # rules loaded, so an installed binary that does not produce one has
        # not answered — whether it printed nothing, an error, or anything else
        # unparseable. Testing for the header rather than for non-empty output
        # is what separates "the ruleset is clean" from "we did not read it":
        # a command that exits 0 with unusable output would otherwise earn the
        # host an explicit clean bill of health. `nft list ruleset` prints
        # nothing for a genuinely empty ruleset and cannot tell the two apart
        # on its own; iptables can, and both need the same capability, so one
        # answers for both.
        rules_readable = (
            not _command_exists("iptables")
            or bool(_IPTABLES_CHAIN_RE.search(input_out))
        )

        ip_forward = _read_ip_forward()

        docker_present = (
            _command_exists("docker")
            or Path("/var/lib/docker").is_dir()
        )

        wg_dir = Path("/etc/wireguard")
        wireguard_present = (
            _command_exists("wg")
            or (wg_dir.is_dir() and any(wg_dir.glob("*.conf")))
        )

        # libvirt/KVM also requires ip_forward and manages FORWARD rules
        libvirt_present = (
            _command_exists("libvirtd")
            or _command_exists("virtqemud")
            or Path("/var/lib/libvirt").is_dir()
        )

        return cls(
            input_raw_accepts=input_raw,
            forward_raw_accepts=forward_raw,
            nftables_active=nftables_active,
            rules_readable=rules_readable,
            ip_forward=ip_forward,
            docker_present=docker_present,
            wireguard_present=wireguard_present,
            libvirt_present=libvirt_present,
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_firewall_stack(snapshot: FirewallStackSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check for firewall stack conflicts and unexpected configurations.

    Args:
        snapshot: FirewallStackSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    found_issue = False

    # --- Raw ACCEPT rules in INPUT chain ---
    # Rules in INPUT that are not jumping to a ufw-* chain bypass UFW entirely.
    for rule in snapshot.input_raw_accepts:
        result.warn_with_deduction(
            key="firewall_drivers.iptables_bypass",
            message=_t("firewall_drivers.iptables_bypass", rule=rule),
            points=2,
            nature="action",
        )
        found_issue = True

    # --- ACCEPT rules in FORWARD chain ---
    # Docker, WireGuard, and libvirt/KVM legitimately add ACCEPT rules to FORWARD.
    # Only flag them when no such routing daemon is detected.
    if snapshot.forward_raw_accepts:
        if snapshot.docker_present or snapshot.wireguard_present or snapshot.libvirt_present:
            result.info(
                message=_t("firewall_drivers.forward_routing_ok"),
                key="firewall_drivers.forward_routing_ok",
            )
        else:
            for rule in snapshot.forward_raw_accepts:
                result.warn_with_deduction(
                    key="firewall_drivers.iptables_forward_bypass",
                    message=_t("firewall_drivers.iptables_forward_bypass", rule=rule),
                    points=1,
                    nature="action",
                )
            found_issue = True

    # --- nftables parallel to UFW ---
    if snapshot.nftables_active:
        result.warn_with_deduction(
            key="firewall_drivers.nftables_parallel",
            message=_t("firewall_drivers.nftables_parallel"),
            points=1,
            nature="action",
        )
        found_issue = True

    # --- IP forwarding ---
    if snapshot.ip_forward:
        if snapshot.docker_present or snapshot.wireguard_present or snapshot.libvirt_present:
            result.ok(message=_t("firewall_drivers.ip_forward_ok"), key="firewall_drivers.ip_forward_ok")
        else:
            result.warn_with_deduction(
                key="firewall_drivers.ip_forward_enabled",
                message=_t("firewall_drivers.ip_forward_enabled"),
                points=1,
                cmd="sudo sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
                nature="improvement",
            )
            found_issue = True

    if not snapshot.rules_readable:
        # "No issues" would be a claim about a ruleset that was never listed.
        result.info(
            message=_t("firewall_drivers.rules_unreadable"),
            detail=_t("firewall_drivers.rules_unreadable_detail"),
            key="firewall_drivers.rules_unreadable",
        )
    elif not found_issue and not snapshot.forward_raw_accepts:
        result.ok(message=_t("firewall_drivers.no_issues"), key="firewall_drivers.no_issues")

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_raw_accepts(iptables_output: str) -> list[str]:
    """
    Parse `iptables -L <chain> -n` output and return ACCEPT rules that are
    NOT jumping to a ufw-* chain.

    UFW manages its own chains (ufw-before-input, ufw-after-input, etc.).
    A line whose target is literally "ACCEPT" is a raw rule that bypasses
    UFW's rule-processing pipeline.
    """
    results = []
    for line in iptables_output.splitlines():
        # Skip header lines
        if not line or line.startswith("Chain") or line.startswith("target"):
            continue
        tokens = line.split()
        if tokens and tokens[0] == "ACCEPT":
            results.append(line.strip())
    return results


def _has_user_nft_rules(nft_output: str) -> bool:
    """
    Return True if nftables has any table that indicates a parallel firewall.

    Excluded from flagging:
    - Tables starting with "ufw"  → UFW's own nftables backend tables.
    - Standard iptables table names (filter, nat, mangle, raw, security)
      → created by iptables-nft compatibility layer; they ARE the iptables
        rules, not additional rules. Systems using iptables 1.x "(nf_tables)"
        will always have these.

    Only non-standard, non-UFW tables indicate an independently configured
    nftables ruleset running in parallel.
    Empty ruleset → False.
    """
    # Standard table names created by iptables-nft compatibility layer
    _IPTABLES_COMPAT = {"filter", "nat", "mangle", "raw", "security"}

    if not nft_output.strip():
        return False
    for line in nft_output.splitlines():
        m = re.match(r"^table\s+\S+\s+(\S+)", line)
        if m:
            table_name = m.group(1)
            if not table_name.startswith("ufw") and table_name not in _IPTABLES_COMPAT:
                return True
    return False


def _read_ip_forward() -> bool:
    """Return True if IPv4 forwarding is enabled in the kernel."""
    try:
        val = Path("/proc/sys/net/ipv4/ip_forward").read_text(
            encoding="ascii", errors="ignore"
        ).strip()
        return val == "1"
    except OSError:
        return False
