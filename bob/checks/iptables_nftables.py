"""
CHECK 46 — iptables / nftables audit (UFW inactive).

Triggered only when UFW is inactive or not installed.
Detects the active backend (nftables native or iptables), reads the
default INPUT and FORWARD chain policies, and verifies loopback and
conntrack rules are in place when the INPUT policy is restrictive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bob.checks._run import _command_exists, _identity_t, _run
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class IptablesNftSnapshot:
    """
    Raw state of the non-UFW firewall layer.

    Args:
        backend:           "nftables", "iptables", or "none".
        input_policy:      Default INPUT chain policy: "DROP", "REJECT",
                           "ACCEPT", or "unknown".
        forward_policy:    Default FORWARD chain policy (same values).
        has_loopback_rule: True if an explicit loopback ACCEPT rule exists.
        has_conntrack_rule: True if an ESTABLISHED/RELATED ACCEPT rule exists.
        raw_output:        Raw command output, used only for the report.
    """
    backend:            str
    input_policy:       str
    forward_policy:     str
    has_loopback_rule:  bool
    has_conntrack_rule: bool
    raw_output:         str = field(default="", repr=False)
    # True when a backend binary exists but every query came back empty,
    # i.e. the ruleset could not be read rather than being absent.
    query_failed:       bool = False

    @classmethod
    def from_system(cls) -> "IptablesNftSnapshot":
        """Collect live state. Never raises."""
        # --- try nftables first ---
        if _command_exists("nft"):
            raw = _run("nft", "list", "ruleset")
            if raw and "hook input" in raw:
                return cls(
                    backend="nftables",
                    input_policy=_nft_policy(raw, "input"),
                    forward_policy=_nft_policy(raw, "forward"),
                    has_loopback_rule=_nft_has_loopback(raw),
                    has_conntrack_rule=_nft_has_conntrack(raw),
                    raw_output=raw,
                )

        # --- fall back to iptables ---
        if _command_exists("iptables"):
            raw = _run("iptables", "-S")
            if raw:
                return cls(
                    backend="iptables",
                    input_policy=_ipt_policy(raw, "INPUT"),
                    forward_policy=_ipt_policy(raw, "FORWARD"),
                    has_loopback_rule=_ipt_has_loopback(raw),
                    has_conntrack_rule=_ipt_has_conntrack(raw),
                    raw_output=raw,
                )

        # Nothing came back from either backend. That is two different
        # situations, and they used to share one verdict worth −3 points.
        #
        # A working `iptables -S` always prints its policy lines, even on a
        # host with no rules at all:
        #
        #     -P INPUT ACCEPT
        #     -P FORWARD ACCEPT
        #     -P OUTPUT ACCEPT
        #
        # So if the binary is there and the output is empty, the query was
        # refused — measured here, where it writes "Permission denied (you must
        # be root)" to stderr and leaves stdout empty. `nft list ruleset` prints
        # nothing for a genuinely empty ruleset, so nft alone cannot tell the
        # two apart; iptables can, and is present on effectively every host
        # BOB targets, including as the nft-based compatibility wrapper.
        query_failed = _command_exists("iptables")
        return cls(
            backend="none",
            query_failed=query_failed,
            input_policy="unknown",
            forward_policy="unknown",
            has_loopback_rule=False,
            has_conntrack_rule=False,
        )


# ---------------------------------------------------------------------------
# Parsers — nftables
# ---------------------------------------------------------------------------

def _nft_policy(ruleset: str, hook: str) -> str:
    """Return the default policy for a given hook name in nft ruleset output."""
    pattern = re.compile(
        rf"hook\s+{hook}\s+[^;]+;\s*policy\s+(\w+)\s*;",
        re.IGNORECASE,
    )
    m = pattern.search(ruleset)
    if m:
        return m.group(1).upper()
    return "unknown"


def _nft_has_loopback(ruleset: str) -> bool:
    return bool(re.search(r'iif\s+"?lo"?\s+accept', ruleset, re.IGNORECASE))


def _nft_has_conntrack(ruleset: str) -> bool:
    return bool(re.search(
        r"ct\s+state\s+[^\n]*\bestablished\b[^\n]*\baccept\b",
        ruleset, re.IGNORECASE,
    ))


# ---------------------------------------------------------------------------
# Parsers — iptables
# ---------------------------------------------------------------------------

def _ipt_policy(rules: str, chain: str) -> str:
    """Return the default policy for a chain from `iptables -S` output."""
    m = re.search(rf"^-P\s+{chain}\s+(\w+)", rules, re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return "unknown"


def _ipt_has_loopback(rules: str) -> bool:
    return bool(re.search(r"-i\s+lo\b.*-j\s+ACCEPT", rules, re.IGNORECASE))


def _ipt_has_conntrack(rules: str) -> bool:
    return bool(re.search(
        r"(--state|--ctstate)\s+[A-Z,]*ESTABLISHED[^\n]*-j\s+ACCEPT",
        rules, re.IGNORECASE,
    ))


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

def check_iptables_nftables(
    snapshot: IptablesNftSnapshot,
    ufw_installed: bool = False,
    t=None,
) -> CheckResult:
    """
    Audit the non-UFW firewall layer (iptables or nftables).

    Only meaningful when UFW is inactive; caller is responsible for
    gating on fw_status.active.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()


    if snapshot.query_failed and snapshot.backend == "none":
        # A backend binary is installed but its ruleset could not be read. The
        # firewall state is unknown, not absent, and this used to cost 3 points
        # — the largest single deduction in the check.
        result.info(
            message=_t("firewall_iptables.ruleset_unreadable"),
            detail=_t("firewall_iptables.ruleset_unreadable_detail"),
            key="firewall_iptables.ruleset_unreadable",
        )
        return result
    if snapshot.backend == "none":
        result.warn_with_deduction(
            key="firewall_iptables.no_backend",
            message=_t("firewall_iptables.no_backend"),
            points=3,
            nature="action",
            cmd="sudo apt install iptables",
        )
        return result

    backend_label = "nftables" if snapshot.backend == "nftables" else "iptables"
    if ufw_installed:
        result.info(
            message=_t("firewall_iptables.ufw_inactive_context", backend=backend_label),
            key="firewall_iptables.ufw_inactive_context",
        )
    result.info(
        message=_t("firewall_iptables.backend_detected", backend=backend_label),
        key="firewall_iptables.backend_detected",
    )

    # --- INPUT default policy ---
    if snapshot.input_policy == "ACCEPT":
        result.alert_with_deduction(
            key="firewall_iptables.input_accept",
            message=_t("firewall_iptables.input_accept"),
            points=3,
            cmd=(
                "sudo iptables -P INPUT DROP"
                if snapshot.backend == "iptables"
                else 'sudo nft chain inet filter input \'{ policy drop; }\''
            ),
            nature="action",
        )
    elif snapshot.input_policy in ("DROP", "REJECT"):
        result.ok(
            message=_t("firewall_iptables.input_ok", policy=snapshot.input_policy),
            key="firewall_iptables.input_ok",
        )

        # Sub-checks only relevant when INPUT is restrictive
        if not snapshot.has_loopback_rule:
            result.warn_with_deduction(
                key="firewall_iptables.no_loopback",
                message=_t("firewall_iptables.no_loopback"),
                points=1,
                cmd=(
                    "sudo iptables -I INPUT 1 -i lo -j ACCEPT"
                    if snapshot.backend == "iptables"
                    else 'sudo nft insert rule inet filter input iif "lo" accept'
                ),
                nature="action",
            )

        if not snapshot.has_conntrack_rule:
            result.warn_with_deduction(
                key="firewall_iptables.no_conntrack",
                message=_t("firewall_iptables.no_conntrack"),
                points=1,
                cmd=(
                    "sudo iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
                    if snapshot.backend == "iptables"
                    else "sudo nft insert rule inet filter input ct state established,related accept"
                ),
                nature="action",
            )
    else:
        result.info(
            message=_t("firewall_iptables.input_unknown"),
            key="firewall_iptables.input_unknown",
        )

    # --- FORWARD default policy ---
    if snapshot.forward_policy == "ACCEPT":
        result.warn_with_deduction(
            key="firewall_iptables.forward_accept",
            message=_t("firewall_iptables.forward_accept"),
            points=1,
            cmd=(
                "sudo iptables -P FORWARD DROP"
                if snapshot.backend == "iptables"
                else 'sudo nft chain inet filter forward \'{ policy drop; }\''
            ),
            nature="action",
        )
    elif snapshot.forward_policy in ("DROP", "REJECT"):
        result.ok(
            message=_t("firewall_iptables.forward_ok", policy=snapshot.forward_policy),
            key="firewall_iptables.forward_ok",
        )
    elif snapshot.forward_policy == "unknown":
        result.info(
            message=_t("firewall_iptables.forward_unknown"),
            key="firewall_iptables.forward_unknown",
        )

    return result
