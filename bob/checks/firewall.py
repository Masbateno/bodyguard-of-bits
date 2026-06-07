"""
Firewall status check for BOB.

Verifies UFW installation, active state, default incoming policy,
and IPv6 rule consistency.

The check is split into two parts:
  1. FirewallStatus.from_system() — collects raw data via subprocess calls.
  2. check_firewall(status)       — pure logic, returns a CheckResult.

This separation allows full unit testing of all logic without
any subprocess calls.

Usage:
    from bob.checks.firewall import check_firewall, FirewallStatus

    status = FirewallStatus.from_system()
    result = check_firewall(status)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run
from bob.scoring import CheckResult

_OPEN_ANY_RE = re.compile(
    r"Anywhere(?:/\w+)?(?:\s+\(v6\))?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?(?:\s+\(v6\))?\s*$",
    re.IGNORECASE,
)
_ALLOW_IN_RE   = re.compile(r"\bALLOW\s+IN\b", re.IGNORECASE)
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5}/(?:tcp|udp))\b", re.IGNORECASE)
# Matches a protocol-unspecified port in the UFW numbered-status "To" field,
# e.g. "[ 2] 57621   ALLOW IN ...". UFW applies such rules to both TCP and UDP.
_PORT_BARE_RE  = re.compile(r"^\[\s*\d+\]\s+(\d{1,5})\s", re.IGNORECASE)


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class FirewallStatus:
    """
    Raw snapshot of the UFW firewall state collected from the system.

    Args:
        installed:        True if the ufw binary is available.
        active:           True if UFW reports Status: active.
        incoming_policy:  Parsed default incoming policy string.
                          One of: "deny", "allow", "reject", "unknown".
        ufw_output:       Full output of `ufw status verbose` for the report.
        numbered_output:  Full output of `ufw status numbered` (rules list).
        ipv6_ufw_enabled: True if IPV6=yes (or absent) in /etc/default/ufw.
                          Used to suppress false-positive IPv6 coverage warnings.
    """
    installed:        bool
    active:           bool
    incoming_policy:  str
    ufw_output:       str
    numbered_output:  str
    ipv6_ufw_enabled: bool = True
    logging_level:    str  = "unknown"

    @classmethod
    def from_system(cls) -> "FirewallStatus":
        """
        Collect firewall state from the live system via subprocess.

        Returns:
            Populated FirewallStatus. Never raises — errors are reflected
            in the returned state (installed=False, active=False, etc.).
        """
        # Check installation
        installed = _command_exists("ufw")
        if not installed:
            return cls(
                installed=False, active=False,
                incoming_policy="unknown", ufw_output="",
                numbered_output="",
            )

        # Get full status output (verbose for policy, numbered for rules)
        ufw_output     = _run("ufw", "status", "verbose")
        numbered_output = _run("ufw", "status", "numbered")

        # Parse active state
        active = bool(re.search(r"^Status:\s+active", ufw_output, re.MULTILINE))

        # Parse incoming policy
        incoming_policy = "unknown"
        match = re.search(r"Default:\s+(\w+)\s+\(incoming\)", ufw_output)
        if match:
            incoming_policy = match.group(1).lower()

        # Read IPv6 config from /etc/default/ufw (default: enabled)
        ipv6_ufw_enabled = _read_ipv6_config()

        logging_level = _read_logging_level(ufw_output)

        return cls(
            installed=installed,
            active=active,
            incoming_policy=incoming_policy,
            ufw_output=ufw_output,
            numbered_output=numbered_output,
            ipv6_ufw_enabled=ipv6_ufw_enabled,
            logging_level=logging_level,
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_firewall(status: FirewallStatus, t: TranslationFunc | None = None) -> CheckResult:
    """
    Evaluate firewall status and return findings and deductions.

    This function is pure — it never calls the system. All input comes
    from the FirewallStatus snapshot.

    Args:
        status: FirewallStatus collected from the system (or built in tests).
        t:      Translation function t(key) -> str. If None, key names are
                used as-is (useful in tests that don't need translated strings).

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- UFW installed ---
    if not status.installed:
        result.alert(
            message=_t("prerequisites.ufw_missing"),
            nature="action",
            cmd="sudo apt install ufw",
            key="prerequisites.ufw_missing",
        )
        return result  # nothing more to check

    result.ok(message=_t("prerequisites.ufw_installed"), key="prerequisites.ufw_installed")

    # --- UFW active ---
    if not status.active:
        result.alert(
            message=_t("firewall.inactive"),
            nature="action",
            cmd="sudo ufw enable",
            key="firewall.inactive",
        )
        # Request a score cap — processed automatically by ScoreEngine.apply()
        result.set_cap(maximum=3, reason=_t("firewall.inactive"), key="firewall.inactive")
        return result

    result.ok(message=_t("firewall.active"), key="firewall.active")

    # --- Default incoming policy ---
    if status.incoming_policy == "allow":
        result.alert_with_deduction(
            key="firewall.policy_open",
            message=_t("firewall.policy_open"),
            points=3,
            cmd="sudo ufw default deny incoming",
            nature="action",
        )
    elif status.incoming_policy == "deny":
        result.ok(message=_t("firewall.policy_ok"), key="firewall.policy_ok")
    else:
        # v0.8.0 drift batch: unknown firewall policy = unverified posture.
        # +2pts because we cannot prove the system is protected.
        result.warn_with_deduction(
            key="firewall.policy_unknown",
            message=_t("firewall.policy_unknown"),
            points=2,
            nature="improvement",
            cmd="sudo ufw default deny incoming",
        )

    return result


# ---------------------------------------------------------------------------
# UFW rules check
# ---------------------------------------------------------------------------

def check_rules(
    ufw_verbose: str,
    ufw_numbered: str,
    t,
    ipv6_enabled: bool = True,
    listening_ports: "set[str] | None" = None,
) -> "CheckResult":
    """
    Check UFW rules for duplicates, open-any wildcards, IPv6 consistency,
    and orphan rules (ALLOW IN with no listening service).

    Args:
        ufw_verbose:     Output of `ufw status verbose`.
        ufw_numbered:    Output of `ufw status numbered`.
        t:               Translation function.
        ipv6_enabled:    True if IPv6 is enabled in /etc/default/ufw.
        listening_ports: Set of "port/proto" strings (e.g. {"22/tcp", "80/tcp"})
                         from PortsSnapshot. When provided, orphan rules are detected.

    Returns:
        CheckResult with rule-level findings and deductions.
    """
    result = CheckResult()
    lines = [
        ln for ln in ufw_numbered.splitlines()
        if re.match(r"\s*\[\s*\d+\]", ln)
    ]
    _check_duplicates(lines, t, result)
    _check_open_any(lines, t, result)
    _check_ipv6_coverage(lines, t, result, ipv6_enabled)
    if listening_ports is not None:
        _check_orphan_rules(lines, listening_ports, t, result)
    return result


def _check_duplicates(lines: list[str], t, result: CheckResult) -> None:
    """Detect duplicate and proto-redundant UFW rules."""

    def _strip_comment(text: str) -> str:
        return re.sub(r"\s*#.*$", "", text).strip()

    def _rule_without_index(line: str) -> str:
        return re.sub(r"\[\s*\d+\]\s*", "", line).strip()

    proto_less_rules: set[str] = set()
    for line in lines:
        tokens = _strip_comment(_rule_without_index(line)).split()
        if tokens and re.match(r"^\d+$", tokens[0]):
            proto_less_rules.add(" ".join(tokens))

    seen_clean: dict[str, int] = {}
    found_duplicate = False
    for line in lines:
        idx_match  = re.match(r"\[\s*(\d+)\]", line)
        real_index = int(idx_match.group(1)) if idx_match else None
        clean      = " ".join(_strip_comment(_rule_without_index(line)).split())

        is_dup = False
        if clean in seen_clean:
            del_index = real_index if real_index else seen_clean[clean]
            result.alert_with_deduction(
                key="firewall_rules.duplicate_found",
                message=t("firewall_rules.duplicate_found", rule=clean),
                points=1,
                cmd=f"sudo ufw --force delete {del_index}",
                nature="action",
            )
            is_dup = True
            found_duplicate = True
        else:
            tokens = clean.split()
            if tokens:
                m = re.match(r"^(\d+)/(tcp|udp)$", tokens[0])
                if m:
                    proto_less_clean = " ".join([m.group(1)] + tokens[1:])
                    if proto_less_clean in proto_less_rules:
                        result.alert_with_deduction(
                            key="firewall_rules.duplicate_found",
                            message=t("firewall_rules.duplicate_found", rule=clean),
                            points=1,
                            cmd=f"sudo ufw --force delete {real_index}",
                            nature="action",
                        )
                        is_dup = True
                        found_duplicate = True

        if not is_dup and real_index is not None:
            seen_clean[clean] = real_index

    if not found_duplicate:
        result.ok(message=t("firewall_rules.no_duplicates"), key="firewall_rules.no_duplicates")


def _check_open_any(lines: list[str], t, result: CheckResult) -> None:
    """Detect 'Anywhere ALLOW IN Anywhere' wildcard rules."""
    found_open_any = False
    for line in lines:
        if _OPEN_ANY_RE.search(line):
            idx_match  = re.match(r"\[\s*(\d+)\]", line)
            real_index = int(idx_match.group(1)) if idx_match else None
            result.alert(
                message=t("firewall_rules.open_any_found", rule=line.strip()),
                nature="action",
                cmd=f"sudo ufw --force delete {real_index}" if real_index is not None else "",
                key="firewall_rules.open_any_found",
            )
            result.add_deduction(
                reason=t("firewall_rules.open_any_found", rule=""), points=2,
                context="local", key="firewall_rules.open_any_found",
            )
            found_open_any = True

    if not found_open_any:
        result.ok(message=t("firewall_rules.no_open_any"), key="firewall_rules.no_open_any")


def _check_orphan_rules(
    lines: list[str],
    listening_ports: "set[str]",
    t,
    result: "CheckResult",
) -> None:
    """Flag ALLOW IN rules for which no service is currently listening."""
    orphans: set[str] = set()
    for line in lines:
        if not _ALLOW_IN_RE.search(line):
            continue
        if "(v6)" in line:
            continue  # skip IPv6 mirrors — covered by their v4 counterpart
        m = _PORT_PROTO_RE.search(line)
        if not m:
            # Protocol-unspecified rule (e.g. "57621 ALLOW IN ...") — UFW
            # applies it to both TCP and UDP.  Flag as orphan only if neither
            # protocol has a listening service.
            m2 = _PORT_BARE_RE.match(line)
            if not m2:
                continue  # genuine open-any rule, caught by _check_open_any
            port = m2.group(1)
            if f"{port}/tcp" not in listening_ports and f"{port}/udp" not in listening_ports:
                orphans.add(port)
            continue
        port_proto = m.group(1).lower()
        if port_proto not in listening_ports:
            orphans.add(port_proto)

    for port_proto in sorted(orphans):
        result.info(
            message=t("firewall_rules.orphan_rule", port=port_proto),
            cmd=f"sudo ufw delete allow {port_proto}",
            key="firewall_rules.orphan_rule",
        )


def _check_ipv6_coverage(
    lines: list[str],
    t,
    result: CheckResult,
    ipv6_enabled: bool,
) -> None:
    """
    Warn if IPv4 rules exist but no IPv6 rules are present.

    Suppressed when IPv6 is disabled in /etc/default/ufw to avoid
    false positives on systems that intentionally run IPv4-only.
    """
    ipv4_count = sum(1 for ln in lines if "(v6)" not in ln)
    ipv6_count = sum(1 for ln in lines if "(v6)" in ln)

    if ipv4_count > 0 and ipv6_count == 0:
        if ipv6_enabled:
            result.warn_with_deduction(
                key="firewall_rules.ipv6_missing",
                message=t("firewall_rules.ipv6_missing"),
                points=1,
                cmd="sudo sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw && sudo ufw reload",
                nature="improvement",
            )
        # else: IPv6 is disabled in /etc/default/ufw — no warning
    elif ipv4_count > 0:
        result.ok(message=t("firewall_rules.ipv6_ok"), key="firewall_rules.ipv6_ok")


# ---------------------------------------------------------------------------
# UFW logging check
# ---------------------------------------------------------------------------

def check_ufw_logging(status: FirewallStatus, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check that UFW logging is enabled at an appropriate level.

    UFW logging levels: off, low, medium, high, full.
    'off' means blocked packets are never logged — the logs check finds nothing.
    'low' is the minimum recommended level (default on most distros).
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not status.active:
        return result  # firewall inactive — covered by check_firewall

    level = status.logging_level
    if level == "off":
        result.alert_with_deduction(
            key="firewall.logging_off",
            message=_t("firewall.logging_off"),
            points=2,
            cmd="sudo ufw logging low",
            nature="action",
        )
    elif level in ("low", "medium"):
        result.ok(
            message=_t("firewall.logging_ok", level=level),
            key="firewall.logging_ok",
            template_vars={"level": level},  # pilot v0.4.1
        )
    elif level in ("high", "full"):
        result.info(
            message=_t("firewall.logging_verbose", level=level),
            key="firewall.logging_verbose",
            template_vars={"level": level},  # pilot v0.4.1
        )
    else:
        result.info(
            message=_t("firewall.logging_unknown"),
            key="firewall.logging_unknown",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_logging_level(ufw_output: str, ufw_conf: Path = Path("/etc/ufw/ufw.conf")) -> str:
    """
    Extract UFW logging level from `ufw status verbose` output.

    Parses lines like:
      Logging: on (low)
      Logging: off
    Falls back to /etc/ufw/ufw.conf (LOGLEVEL=low).
    Returns one of: off, low, medium, high, full, unknown.
    """
    # Try parsing verbose output first
    m = re.search(r"^Logging:\s+(\S+)(?:\s+\((\S+)\))?", ufw_output, re.MULTILINE | re.IGNORECASE)
    if m:
        state = m.group(1).lower()
        if state == "off":
            return "off"
        level = (m.group(2) or state).lower().rstrip(")")
        if level in ("low", "medium", "high", "full"):
            return level

    # Fallback: read /etc/ufw/ufw.conf
    try:
        content = ufw_conf.read_text(encoding="utf-8", errors="ignore")
        mc = re.search(r"^LOGLEVEL\s*=\s*(\S+)", content, re.MULTILINE | re.IGNORECASE)
        if mc:
            level = mc.group(1).lower().strip('"\'')
            if level in ("off", "low", "medium", "high", "full"):
                return level
    except OSError:
        pass

    return "unknown"


def _read_ipv6_config() -> bool:
    """
    Read /etc/default/ufw to determine if IPv6 is enabled.

    Returns False only when IPV6=no is explicitly set.
    Defaults to True (enabled) if the file is absent or unreadable.
    """
    try:
        content = Path("/etc/default/ufw").read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^IPV6\s*=\s*no\b", content, re.MULTILINE | re.IGNORECASE):
            return False
    except OSError:
        pass
    return True
