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
import shlex
from dataclasses import dataclass
from pathlib import Path

from bob.checks import _ufw
from bob.checks._run import (
    TranslationFunc,
    _MANAGER_ALIASES,
    _command_exists,
    _identity_t,
    _run,
    detect_install_manager,
    install_fix,
)
from bob.scoring import CheckResult
from bob._atomic import read_text_capped

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
        ipv6_ufw_enabled: True if IPV6=yes (or the file is absent) in
                          /etc/default/ufw, None if it could not be read.
                          Used to suppress false-positive IPv6 coverage warnings.
    """
    installed:        bool
    active:           bool
    incoming_policy:  str
    ufw_output:       str
    numbered_output:  str
    ipv6_ufw_enabled: "bool | None" = True
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
# Firewall posture — one answer for every summary that needs one
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FirewallPosture:
    """Which firewall filters inbound traffic, and its default for unmatched packets.

    v0.24.1. The firewall section learnt firewalld (0.20.2) and a raw
    nftables/iptables ruleset (0.23.0), but the summaries built after it —
    attack surface, risk-level floor, implicit-policy note, SSH context —
    still read UFW's own state. A firewalld host was told "default policy is
    ALLOW — no filtering" and an nftables-only host "no active firewall",
    while the section above had credited both. Every one of them now reads
    this object, computed once.

    Args:
        backend: "ufw", "firewalld", "netfilter" (a raw ruleset with a
                 DROP/REJECT inbound policy and no managed front-end), or ""
                 when nothing filters inbound traffic.
        policy:  "deny", "reject", "allow" or "unknown" — "unknown" when the
                 backend's default was not read, never assumed.
    """
    backend: str = ""
    policy:  str = "unknown"

    @property
    def active(self) -> bool:
        return bool(self.backend)


def resolve_firewall_posture(
    status: FirewallStatus,
    firewalld=None,
    netfilter_policy: str | None = None,
) -> FirewallPosture:
    """UFW when active, else firewalld when active, else a filtering raw ruleset.

    *netfilter_policy* is the raw INPUT policy ("DROP"/"REJECT") of a ruleset
    the runner judged protective, ``None`` otherwise.
    """
    if status.active:
        return FirewallPosture("ufw", status.incoming_policy or "unknown")
    if firewalld is not None and firewalld.active:
        return FirewallPosture("firewalld", firewalld.incoming_policy)
    if netfilter_policy in ("DROP", "REJECT"):
        return FirewallPosture("netfilter", "deny" if netfilter_policy == "DROP" else "reject")
    return FirewallPosture()


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def _firewall_install_fix(_t):
    """``(cmd, detail)`` for "no firewall front-end is active".

    Backend-neutral by distribution rather than UFW-specific: ufw is the
    front-end BOB advises on the Debian/Arch/Alpine families, firewalld on the
    RPM family (Fedora/RHEL/openSUSE), each with the enable step that actually
    turns it on. The package layer (``detect_install_manager``) decides; an
    unknown manager still lands in the manual bucket via ``install_fix``.
    """
    base = _MANAGER_ALIASES.get(detect_install_manager(), detect_install_manager())
    if base in ("dnf", "yum", "zypper"):
        return install_fix(_t, None, "firewalld", then="sudo systemctl enable --now firewalld")
    return install_fix(_t, None, "ufw", then="sudo ufw enable")


def _firewalld_close_cmd(zone: str) -> str:
    """Stop the default zone accepting every unmatched packet, keeping SSH.

    ``trusted`` exists to accept everything, so the fix is to stop using it as
    the default, not to rewrite it: ``public`` ships with ssh allowed. Any other
    zone gets the stock target back (reject what no rule allows), with ssh
    added first so a remote operator does not lock themself out.
    """
    if not zone or zone == "trusted":
        return "sudo firewall-cmd --set-default-zone=public"
    z = shlex.quote(zone)
    return (f"sudo firewall-cmd --permanent --zone={z} --add-service=ssh && "
            f"sudo firewall-cmd --permanent --zone={z} --set-target=default && "
            f"sudo firewall-cmd --reload")


def check_firewall(
    status: FirewallStatus,
    firewalld=None,
    netfilter_protective: bool | None = None,
    t: TranslationFunc | None = None,
) -> CheckResult:
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

    # --- Another filter while UFW is not running ---
    # v0.24.1: this used to sit under "UFW not installed" only. Ubuntu ships
    # the ufw package installed and inactive, so an Ubuntu host protected by
    # firewalld or by its own nftables ruleset fell through to "UFW inactive"
    # — an alert and a 3/10 cap on a firewalled machine.
    if not status.active:
        # firewalld is the firewall front-end on the RPM family and openSUSE.
        # When it is active the machine IS firewalled; alerting "UFW not
        # installed" there frames a properly-protected host as unprotected
        # (measured on Fedora 44). Credit firewalld and name what it exposes.
        if firewalld is not None and firewalld.active:
            svc = firewalld.allows_summary()
            result.ok(
                message=_t("firewall.firewalld_active",
                           zone=firewalld.default_zone or "?", services=svc),
                key="firewall.firewalld_active",
            )
            # v0.24.2: a zone whose target is ACCEPT (the `trusted` zone, or a
            # zone set that way) lets every unmatched packet in — UFW's
            # `policy_open`, which costs 3 points there. Here it was an OK and
            # nothing deducted, while the attack surface already said "default
            # policy is ALLOW — no filtering" (measured on Fedora 44).
            if firewalld.incoming_policy == "allow":
                result.alert_with_deduction(
                    key="firewall.firewalld_policy_open",
                    message=_t("firewall.firewalld_policy_open",
                               zone=firewalld.default_zone or "?"),
                    points=3,
                    cmd=_firewalld_close_cmd(firewalld.default_zone),
                    nature="action",
                    template_vars={"zone": firewalld.default_zone or "?"},
                )
            return result
        # No managed front-end (UFW/firewalld). Before demanding one, consult
        # the raw netfilter layer the runner measured: an nftables/iptables
        # ruleset with a default-deny inbound policy IS a firewall, so alerting
        # "no firewall" there would be the mirror of the old UFW-centric
        # over-claim. Credit it as INFO and let the iptables/nftables section
        # carry the detailed verdict. Only a host with no front-end AND no
        # filtering netfilter ruleset is genuinely unprotected.
        if netfilter_protective:
            result.info(
                message=_t("firewall.netfilter_active"),
                key="firewall.netfilter_active",
            )
            return result

    # --- UFW installed ---
    if not status.installed:
        _cmd, _detail = _firewall_install_fix(_t)
        result.alert(
            message=_t("prerequisites.firewall_missing"),
            detail=_detail,
            nature="action",
            cmd=_cmd,
            key="prerequisites.firewall_missing",
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
    app_profiles: "dict[str, list[str]] | None" = None,
    firewalld_active: bool = False,
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
    lines = [ln for ln in ufw_numbered.splitlines() if _ufw.is_rule_line(ln)]
    _check_duplicates(lines, t, result)
    _check_open_any(lines, t, result)
    # The IPv6-coverage and orphan-rule checks reason about *UFW* rules covering
    # listening ports. When firewalld is the active front-end there are no UFW
    # rules to cover anything, so both fired for every listener ("port in IPv6
    # without a matching UFW (v6) rule") — a UFW-framed false positive measured
    # on Fedora 44. firewalld's own coverage is credited by check_firewall.
    if not firewalld_active:
        _check_ipv6_coverage(lines, t, result, ipv6_enabled)
        if listening_ports is not None:
            _check_orphan_rules(lines, listening_ports, t, result, app_profiles)
    return result


def _strip_comment(text: str) -> str:
    """Drop a UFW rule comment (``... # note``) before matching.

    v0.15.0 — ``ufw allow ... comment 'x'`` appends ``# x`` to every line of
    ``ufw status numbered``. ``_check_duplicates`` stripped it; the other
    sub-checks did not, and their patterns are anchored on the end of the line.
    The consequence on ``_check_open_any`` was total: a rule allowing
    everything from anywhere went undetected as soon as it carried a comment —
    an ALERT and a 2-point deduction silently gone, on the single most
    dangerous rule UFW can hold. Commenting firewall rules is good practice,
    so the safer the operator, the likelier the miss.
    """
    return re.sub(r"\s*#.*$", "", text).strip()


def _check_duplicates(lines: list[str], t, result: CheckResult) -> None:
    """Detect duplicate and proto-redundant UFW rules."""

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
        if _OPEN_ANY_RE.search(_strip_comment(line)):
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
    app_profiles: "dict[str, list[str]] | None" = None,
) -> None:
    """Flag ALLOW IN rules for which no service is currently listening."""
    orphans: set[str] = set()
    for line in lines:
        if not _ALLOW_IN_RE.search(line):
            continue
        if "(v6)" in line:
            continue  # skip IPv6 mirrors — covered by their v4 counterpart
        rule = _ufw.parse_rule(line)
        if rule is None or not rule.to_col:
            continue
        # v0.15.1: this used to search the line for a single `<port>/<proto>`,
        # so `6000:6007/tcp` yielded only 6007 and `80,443/tcp` only 443 — two
        # orphan ports reported out of eight. The shared grammar expands ranges,
        # lists and application profiles.
        ranges = _ufw.to_column_ranges(rule.to_col, app_profiles)
        for lo, hi, proto in ranges:
            for port in range(lo, hi + 1):
                if proto is None:
                    # UFW applies a protocol-less rule to both; an orphan only
                    # when neither protocol has a listener.
                    if (f"{port}/tcp" not in listening_ports
                            and f"{port}/udp" not in listening_ports):
                        orphans.add(str(port))
                elif f"{port}/{proto}" not in listening_ports:
                    orphans.add(f"{port}/{proto}")

    for port_proto in sorted(orphans):
        # v0.11.1 F7: a protocol-unspecified rule is stored as a bare port
        # (e.g. "57621"); UFW applies it to both protocols. Display it as
        # ``57621/tcp+udp`` so the finding is consistent with proto-qualified
        # entries (``41681/tcp``) and tells the operator it covers both. The
        # delete command keeps the bare token (the only form UFW accepts).
        display = port_proto if "/" in port_proto else f"{port_proto}/tcp+udp"
        result.info(
            message=t("firewall_rules.orphan_rule", port=display),
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
    false positives on systems that intentionally run IPv4-only, and when that
    file could not be read at all.
    """
    _bodies = [_strip_comment(ln) for ln in lines]
    ipv4_count = sum(1 for ln in _bodies if "(v6)" not in ln)
    ipv6_count = sum(1 for ln in _bodies if "(v6)" in ln)

    if ipv4_count > 0 and ipv6_count == 0:
        if ipv6_enabled:
            result.warn_with_deduction(
                key="firewall_rules.ipv6_missing",
                message=t("firewall_rules.ipv6_missing"),
                points=1,
                cmd=_ipv6_enable_cmd(),
                nature="improvement",
            )
        # else: IPv6 is disabled in /etc/default/ufw, or the file could not
        # be read — either way there is nothing established to warn about. The
        # unreadable case is reported once, by the ipv6 section that owns it.
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
        content = read_text_capped(ufw_conf, encoding="utf-8", errors="ignore")
        mc = re.search(r"^LOGLEVEL\s*=\s*(\S+)", content, re.MULTILINE | re.IGNORECASE)
        if mc:
            level = mc.group(1).lower().strip('"\'')
            if level in ("off", "low", "medium", "high", "full"):
                return level
    except OSError:
        pass

    return "unknown"


def _ipv6_enable_cmd() -> str:
    """The command that enables IPv6 in /etc/default/ufw.

    Matches what ``_read_ipv6_config`` detects — optional spaces around ``=``
    and any case (GNU sed ``-E`` + ``I`` flag, as the v0.19.0 samba fix uses).
    A plain ``s/^IPV6=no/.../`` was a no-op (and so left the finding standing
    forever) on the valid variants ``IPV6 = no`` and ``IPV6=NO``; the whole
    line is rewritten to the canonical form. Kept as a function so the
    fix-roundtrip guard (test_v0200) exercises the shipped command.
    """
    return ("sudo sed -i -E 's/^IPV6[[:space:]]*=[[:space:]]*no\\b.*/IPV6=yes/I' "
            "/etc/default/ufw && sudo ufw reload")


def _read_ipv6_config(path: Path = Path("/etc/default/ufw")) -> "bool | None":
    """
    Read /etc/default/ufw to determine if IPv6 is enabled.

    Returns False only when IPV6=no is explicitly set, True when the file is
    absent (ufw's own default), and None when it exists but could not be read.
    The last case used to answer True as well; see `ipv6._read_ufw_ipv6`, which
    reads the same file and paid for the conflation with a false deduction.

    ``path`` is a seam for the fix-roundtrip guard (test_v0200); production
    always uses the default.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return True
    except OSError:
        return None
    if re.search(r"^IPV6\s*=\s*no\b", content, re.MULTILINE | re.IGNORECASE):
        return False
    return True
