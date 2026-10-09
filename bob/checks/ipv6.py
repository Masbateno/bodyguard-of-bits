"""
IPv6 consistency check for BOB.

Verifies that UFW's IPv6 configuration matches the kernel IPv6 state, and
that every port listening on the IPv6 wildcard address (::) has a corresponding
UFW (v6) rule.

The check is split into two parts:
  1. IPv6Snapshot.from_system()  — collects raw data via subprocess / procfs.
  2. check_ipv6(snapshot)         — pure logic, returns a CheckResult.

Usage:
    from bob.checks.ipv6 import IPv6Snapshot, check_ipv6

    snapshot = IPv6Snapshot.from_system()
    result   = check_ipv6(snapshot)
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from bob.checks import _ufw
from bob.checks._run import TranslationFunc, _identity_t, _run, path_exists, run_result
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class IPv6Snapshot:
    """
    Raw snapshot of IPv6 configuration and listening state.

    Args:
        kernel_ipv6_enabled: True if the kernel IPv6 stack is active
        kernel_ipv6_readable: False when the stack state could not be read
                             (i.e. /proc/sys/net/ipv6/conf/all/disable_ipv6 == 0).
        ufw_ipv6_enabled:    True if UFW is configured to manage IPv6 rules,
                             None if /etc/default/ufw could not be read
                             (IPV6=yes or absent in /etc/default/ufw).
        listeners_readable:  False when `ss` could not be run, so an empty
                             listener list means "not looked at" rather than
                             "nothing listening".
        ipv6_listeners:      Port/proto strings (e.g. "22/tcp") for services
                             that bind to the IPv6 wildcard address (::).
        ufw_v6_covered:      Port/proto strings that have a (v6) UFW rule.
        has_global_ipv6:     True if at least one global-scope IPv6 address is
                             assigned (2000::/3). False when only link-local
                             (fe80::/10), ULA (fc/fd::/7), or loopback (::1)
                             addresses are present — the machine cannot be
                             reached via IPv6 from the internet in that case.
    """
    kernel_ipv6_enabled: bool       = True
    # False only when /proc/sys/net/ipv6 exists but could not be read. An
    # absent tree is a definite "IPv6 is off", not an unknown — see
    # _read_kernel_ipv6.
    kernel_ipv6_readable: bool      = True
    listeners_readable:  bool       = True
    ufw_ipv6_enabled:    "bool | None" = True
    ipv6_listeners:      list[str]  = field(default_factory=list)
    ufw_v6_covered:      list[str]  = field(default_factory=list)
    has_global_ipv6:     bool       = False
    #: v0.24.1 — UFW exists on this host (its binary or /etc/default/ufw). An
    #: absent /etc/default/ufw reads as "IPv6 managed" — ufw's own default —
    #: which is only a fact where ufw is installed. On a host without it (Debian
    #: with nftables, Alpine, Arch) BOB said "UFW IPv6 configuration matches
    #: kernel IPv6 state" and "Port 22/tcp … without a UFW (v6) rule".
    ufw_present:         bool       = True
    #: v0.24.2 — the kernel's IPv6 INPUT policy ("DROP", "ACCEPT"), read only
    #: when UFW is set to IPV6=no; None when not read or unreadable. ufw-init
    #: does not leave IPv6 unmanaged there: it installs DROP on INPUT, FORWARD
    #: and OUTPUT (loopback excepted) whenever ip6tables works. Measured on Mint
    #: 22.3, ufw 0.36.2: UFW active + IPV6=no → a link-local neighbour cannot
    #: reach sshd on [::]:22; UFW inactive → it can.
    ip6_input_policy:    "str | None" = None
    #: v0.24.3 — the rules of that chain (``-A INPUT …`` lines), None when not
    #: read. A DROP policy only decides the packets no rule accepted: ufw-init
    #: leaves just the loopback rule, and that exact shape is the only one BOB
    #: reads as "IPv6 blocked". Any other rule (Docker, libvirt, a hand-written
    #: ACCEPT) may admit a listener, and BOB does not resolve which.
    ip6_input_rules:     "list[str] | None" = None

    @classmethod
    def from_system(cls) -> "IPv6Snapshot":
        """
        Collect IPv6 state from the live system.

        Returns:
            Populated IPv6Snapshot. Never raises — errors reflected as
            safe defaults (kernel IPv6 enabled, UFW IPv6 enabled, empty lists).
        """
        kernel_ipv6_enabled, kernel_ipv6_readable = _read_kernel_ipv6()
        ufw_ipv6_enabled    = _read_ufw_ipv6()
        ufw_present         = (shutil.which("ufw") is not None
                               or path_exists(Path("/etc/default/ufw")))
        has_global_ipv6     = _read_global_ipv6()
        ip6_input_policy, ip6_input_rules = (
            _read_ip6_input_chain() if ufw_ipv6_enabled is False else (None, None))

        ss = run_result("ss", "-tulnp")
        ipv6_listeners = sorted(_extract_ipv6_listeners(ss.stdout))

        ufw_out = _run("ufw", "status", "numbered") or ""
        ufw_v6_covered = sorted(
            _extract_ufw_v6_covered(ufw_out, _ufw.read_app_profiles())
        )

        return cls(
            kernel_ipv6_enabled=kernel_ipv6_enabled,
            kernel_ipv6_readable=kernel_ipv6_readable,
            listeners_readable=ss.ok,
            ufw_ipv6_enabled=ufw_ipv6_enabled,
            ipv6_listeners=ipv6_listeners,
            ufw_v6_covered=ufw_v6_covered,
            has_global_ipv6=has_global_ipv6,
            ufw_present=ufw_present,
            ip6_input_policy=ip6_input_policy,
            ip6_input_rules=ip6_input_rules,
        )


def _read_ip6_input_chain() -> "tuple[str | None, list[str] | None]":
    """(default policy, rules) of the IPv6 INPUT chain; (None, None) if unread."""
    res = run_result("ip6tables", "-S", "INPUT")
    if not res.ok:
        return None, None
    m = re.search(r"^-P INPUT (\w+)", res.stdout, re.M)
    if not m:
        return None, None
    rules = [line.strip() for line in res.stdout.splitlines() if line.startswith("-A INPUT")]
    return m.group(1), rules


#: The rules ufw-init leaves in the IPv6 INPUT chain when IPV6=no.
_UFW_V6_OFF_RULES = frozenset({"-A INPUT -i lo -j ACCEPT"})


def _ipv6_input_closed(snapshot: "IPv6Snapshot") -> bool:
    """IPv6 INPUT drops everything but loopback — and nothing else can let a
    packet through: no rule other than ufw-init's loopback one."""
    return (snapshot.ip6_input_policy == "DROP"
            and snapshot.ip6_input_rules is not None
            and set(snapshot.ip6_input_rules) <= _UFW_V6_OFF_RULES)


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

_MAX_PORT_DEDUCTIONS = 3   # cap per-port deductions to avoid score collapse


def check_ipv6(snapshot: IPv6Snapshot, ufw_active: bool = True, t: TranslationFunc | None = None, firewalld_active: bool = False, netfilter_active: bool = False, firewalld_policy: str = "") -> CheckResult:
    """
    Check IPv6 firewall consistency.

    Args:
        snapshot: IPv6Snapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()
    found_issue = False

    # --- Kernel / UFW mismatch ---
    if not snapshot.kernel_ipv6_readable:
        result.info(
            message=_t("ipv6.kernel_state_unknown"),
            detail=_t("ipv6.kernel_state_unknown_detail"),
            key="ipv6.kernel_state_unknown",
        )

    # v0.24.2: firewalld is the filter and UFW is not running — UFW's IPv6
    # setting describes nothing here (measured on Fedora 44, no ufw package:
    # "UFW IPv6 configuration matches kernel"). firewalld filters IPv6 through
    # the same zone as IPv4, so the zone's default decides both — and a zone
    # whose target is ACCEPT filters neither, which "filtered by firewalld"
    # used to claim anyway.
    if firewalld_active and not ufw_active:
        if firewalld_policy == "allow":
            result.info(message=_t("ipv6.firewalld_v6_open"), key="ipv6.firewalld_v6_open")
        else:
            result.ok(message=_t("ipv6.firewalld_v6"), key="ipv6.firewalld_v6")
        return result

    # v0.24.1: no UFW at all, and firewalld not running — UFW's IPv6 setting
    # describes nothing here, so neither "matches kernel" nor "no UFW (v6) rule"
    # is a statement about this host. Say which filter governs the listeners and
    # claim no more: BOB does not read which address families a raw ruleset's
    # tables cover (inet and ip6 filter IPv6, ip does not).
    if not snapshot.ufw_present and not firewalld_active:
        if snapshot.ipv6_listeners:
            key = "ipv6.netfilter_v6" if netfilter_active else "ipv6.no_firewall_v6"
            result.info(message=_t(key, count=len(snapshot.ipv6_listeners),
                                   ports=", ".join(snapshot.ipv6_listeners)),
                        key=key)
        elif not snapshot.listeners_readable:
            result.info(message=_t("ipv6.listeners_unknown"),
                        detail=_t("ipv6.listeners_unknown_detail"),
                        key="ipv6.listeners_unknown")
        else:
            result.info(message=_t("ipv6.no_ufw_no_listeners"), key="ipv6.no_ufw_no_listeners")
        return result

    # Unknown heads the chain rather than sitting beside it. Falling through
    # reached the final `else`, which states that kernel and UFW agree — one
    # more assertion, where the honest answer is to abstain. The per-port gap
    # check goes with it: coverage cannot be judged against a policy that was
    # never read.
    if snapshot.ufw_ipv6_enabled is None:
        result.info(
            message=_t("ipv6.ufw_config_unreadable"),
            key="ipv6.ufw_config_unreadable",
        )

    elif not snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled:
        # UFW will generate (v6) rules that the kernel ignores — confusing but not a
        # security gap (there is no IPv6 stack to exploit).
        result.info(message=_t("ipv6.ufw_enabled_kernel_disabled"),
                    key="ipv6.ufw_enabled_kernel_disabled")

    elif snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled is False:
        if snapshot.ipv6_listeners:
            listeners_str = ", ".join(snapshot.ipv6_listeners)
            if ufw_active and _ipv6_input_closed(snapshot):
                # v0.24.2: UFW with IPV6=no drops every IPv6 packet — the
                # listeners are unreachable, not exposed. This used to be a
                # WARN −2 for "services exposed without UFW IPv6 rules" (global
                # address) or "reachable from the local network without UFW
                # filtering" (link-local); both are the opposite of measured.
                result.info(
                    message=_t("ipv6.ufw_v6_off_blocked",
                               count=len(snapshot.ipv6_listeners)),
                    detail=_t("ipv6.ufw_v6_off_blocked_detail", ports=listeners_str),
                    key="ipv6.ufw_v6_off_blocked",
                )
            elif snapshot.has_global_ipv6:
                # Real gap: globally-routable IPv6 + listeners + no UFW IPv6 rules.
                # When UFW is completely inactive, downgrade: main issue is UFW being off.
                if ufw_active:
                    result.warn_with_deduction(
                        key="ipv6.ufw_disabled_listeners_present",
                        message=_t("ipv6.ufw_disabled_listeners_present",
                                   count=len(snapshot.ipv6_listeners)),
                        points=2,
                        detail=_t("ipv6.listeners_list", ports=listeners_str),
                        cmd=f"sudo nano /etc/default/ufw  # {_t('ipv6.cmd_comment_enable')}",
                    )
                    found_issue = True
                else:
                    result.info(
                        message=_t("ipv6.ufw_disabled_listeners_present",
                                   count=len(snapshot.ipv6_listeners)),
                        detail=_t("ipv6.listeners_list", ports=listeners_str),
                        key="ipv6.ufw_disabled_listeners_present",
                    )
            elif ufw_active and snapshot.ip6_input_policy == "DROP":
                # v0.24.3: UFW's DROP is in place but the chain holds other
                # rules. Measured on Mint 22.3 (link-local neighbour): ACCEPT 22
                # alone, or with OUTPUT, left :22 unreachable (ICMPv6 is dropped
                # too); with ICMPv6 both ways it answered. Neither "reachable"
                # nor "blocked" is shown — say so.
                result.info(
                    message=_t("ipv6.ufw_v6_off_rules_unresolved",
                               count=len(snapshot.ipv6_listeners)),
                    detail=_t("ipv6.listeners_list", ports=listeners_str),
                    key="ipv6.ufw_v6_off_rules_unresolved",
                )
            else:
                # Link-local / ULA only — machine not reachable via IPv6 from internet.
                result.info(
                    message=_t("ipv6.ufw_disabled_listeners_link_local",
                               count=len(snapshot.ipv6_listeners)),
                    detail=_t("ipv6.listeners_list", ports=listeners_str),
                    key="ipv6.ufw_disabled_listeners_link_local",
                )
        elif not snapshot.listeners_readable:
            # `ss` never answered, so "no IPv6 listeners" would be BOB's
            # ignorance dressed up as reassurance.
            result.info(message=_t("ipv6.listeners_unknown"),
                        detail=_t("ipv6.listeners_unknown_detail"),
                        key="ipv6.listeners_unknown")
        else:
            result.info(message=_t("ipv6.ufw_disabled_no_listeners"),
                        key="ipv6.ufw_disabled_no_listeners")

    else:
        # Both agree — kernel and UFW are in sync on IPv6.
        if snapshot.kernel_ipv6_enabled:
            result.ok(message=_t("ipv6.config_ok"), key="ipv6.config_ok")
        else:
            result.ok(message=_t("ipv6.both_disabled"), key="ipv6.both_disabled")

        # --- Per-port gap check (only when IPv6 is active on both sides) ---
        # firewalld filters IPv6 through the same zone rules as IPv4, so a
        # missing UFW v6 rule is not a gap here — UFW is not the firewall.
        if snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled and firewalld_active:
            result.ok(message=_t("ipv6.firewalld_v6"), key="ipv6.firewalld_v6")
        elif snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled:
            covered_set = set(snapshot.ufw_v6_covered)
            port_deductions = 0
            for port_proto in snapshot.ipv6_listeners:
                if port_proto not in covered_set:
                    result.warn(
                        message=_t("ipv6.port_no_v6_rule", port=port_proto),
                        nature="improvement",
                        cmd=f"sudo ufw allow {port_proto}",
                        key="ipv6.port_no_v6_rule",
                    )
                    if port_deductions < _MAX_PORT_DEDUCTIONS:
                        result.add_deduction(
                            reason=_t("ipv6.port_no_v6_rule", port=port_proto),
                            points=1,
                            context="local",
                            key="ipv6.port_no_v6_rule",
                        )
                        port_deductions += 1
                    found_issue = True

    # The closing OK is a positive claim — "all listeners are covered by UFW
    # (v6) rules" — and it sits outside the branch chain. It is only *truthful*
    # when UFW is actually managing IPv6: with UFW IPv6 disabled the listeners
    # are safe (or not) for other reasons — link-local scope, or the default
    # deny — not because a v6 rule covers them, and the per-branch findings
    # above already say so. Requiring `is True` (not merely `is not None`) stops
    # the contradictory "UFW IPv6 disabled … but covered by UFW (v6) rules" pair
    # on a host with IPV6=no (and the same claim when both sides are disabled).
    if snapshot.ufw_ipv6_enabled is True and not found_issue and not firewalld_active and not (
        not snapshot.kernel_ipv6_enabled and snapshot.ufw_ipv6_enabled
    ):
        if snapshot.ipv6_listeners:
            result.ok(
                message=_t("ipv6.all_ports_covered",
                           count=len(snapshot.ipv6_listeners)),
                key="ipv6.all_ports_covered",
            )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INET6_ADDR_RE = re.compile(r"\binet6\s+([0-9a-f:]+)/", re.IGNORECASE)


def _read_global_ipv6() -> bool:
    """
    Return True if at least one globally-routable IPv6 address is assigned.

    Excludes:
      - ::1              loopback
      - fe80::/10        link-local (not routable beyond the local link)
      - fc00::/7 (fc/fd) unique local (ULA — not routable on the public internet)
    """
    out = _run("ip", "-6", "addr", "show") or ""
    for line in out.splitlines():
        m = _INET6_ADDR_RE.search(line)
        if not m:
            continue
        addr = m.group(1).lower()
        if addr == "::1":
            continue
        if addr.startswith("fe80:"):
            continue
        if addr.startswith("fc") or addr.startswith("fd"):
            continue
        return True
    return False


_IPV6_SYSCTL_DIR  = Path("/proc/sys/net/ipv6")
_IPV6_DISABLE_ALL = _IPV6_SYSCTL_DIR / "conf" / "all" / "disable_ipv6"


def _read_kernel_ipv6() -> "tuple[bool, bool]":
    """Return (ipv6_enabled, readable) for the kernel IPv6 stack.

    The absent file is not an unknown, it is an answer. `/proc/sys/net/ipv6`
    is created when the IPv6 stack registers its sysctls, so booting with
    ``ipv6.disable=1`` — or a kernel built without IPv6 — leaves the whole tree
    missing. Until v0.15.0 the reader returned True on any failure, "assume
    enabled if unreadable", so the file was absent *because* IPv6 was off and
    BOB concluded it was on. With no IPv6 listeners that produced
    ``ipv6.config_ok``: an explicit statement that the IPv6 configuration was
    fine, about a stack that did not exist.

    A read that fails for any other reason is genuinely unknown, and is
    reported as such rather than resolved in either direction.
    """
    try:
        val = _IPV6_DISABLE_ALL.read_text(encoding="ascii", errors="ignore").strip()
        return val != "1", True
    except FileNotFoundError:
        return False, True
    except OSError:
        if not _IPV6_SYSCTL_DIR.is_dir():
            return False, True
        return True, False


def _read_ufw_ipv6() -> "bool | None":
    """
    Return True if UFW is configured to manage IPv6, None if that is unknown.

    An **absent** file answers True: that is ufw's own default, so absence is a
    real state and reading it as "IPv6 managed" is a measurement. An
    **unreadable** one is not that state — it is no answer at all, and the two
    were conflated. On a host whose file says IPV6=no, losing the read invented
    True and every uncovered port became `ipv6.port_no_v6_rule`, a warning with
    a deduction for missing rules under a firewall the operator had
    deliberately told not to manage IPv6.
    """
    try:
        content = Path("/etc/default/ufw").read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return True
    except OSError:
        return None
    if re.search(r"^IPV6\s*=\s*no\b", content, re.MULTILINE | re.IGNORECASE):
        return False
    return True


# Processes that bind to IPv6 for internal/link-local purposes and must never
# receive a "sudo ufw allow" recommendation.  These services handle their own
# access control or are designed exclusively for the local network.
_INTERNAL_PROCESSES: frozenset[str] = frozenset({
    "avahi-daemon",    # mDNS/DNS-SD — local network only
    "systemd-resolve", # internal stub resolver
    "dnsmasq",         # DHCP/DNS — LAN infrastructure
    "containerd",      # container runtime — internal IPC
    "dockerd",         # Docker daemon — internal IPC
})

# Regex to extract the process name from ss -tulnp output.
# Matches: users:(("process-name",pid=N,fd=N))
_SS_PROC_RE = re.compile(r'users:\(\("([^"]+)"')


def _extract_ipv6_listeners(ss_output: str) -> set[str]:
    """
    Parse `ss -tulnp` and return the set of 'port/proto' strings for services
    that bind to the IPv6 wildcard address [::], excluding known internal
    processes that do not require external UFW rules.

    Process filtering: if ss was invoked with -p and a process name is
    present in _INTERNAL_PROCESSES, the port is silently excluded so that
    the IPv6 check never recommends opening it.  Lines without process info
    (e.g. in tests using -tuln output) are included unchanged.

    Example matching line:
        tcp   LISTEN 0  128  [::]:22  [::]:*  users:(("sshd",pid=972,fd=4))
    """
    listeners: set[str] = set()
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        local_addr = parts[4]
        # IPv6 wildcard: [::]:PORT
        m = re.match(r"^\[::]:(\d+)$", local_addr)
        if not m:
            continue
        port_proto = f"{m.group(1)}/{proto}"
        # Filter out known internal processes (only when -p info is present)
        proc_m = _SS_PROC_RE.search(line)
        if proc_m and proc_m.group(1) in _INTERNAL_PROCESSES:
            continue
        listeners.add(port_proto)
    return listeners


def _extract_ufw_v6_covered(
    ufw_numbered: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> set[str]:
    r"""Return the 'port/proto' strings that have a ``(v6)`` UFW rule.

    Delegates the rule grammar to ``bob.checks._ufw``, shared with ``ports`` and
    ``services``. Its own pattern —
    ``\[\s*\d+\]\s+(\d+)(?:/(tcp|udp))?\s+\(v6\)`` — was anchored correctly and
    was examined on that basis in v0.15.0, but anchoring is not completeness: it
    matched a bare port and nothing else, so ``OpenSSH (v6)``, ``6000:6007/tcp
    (v6)`` and ``80,443/tcp (v6)`` all read as *no v6 rule at all*. Measured on
    those three lines it returned an empty set, which means every one of those
    ports raised ``ipv6.port_no_v6_rule`` — a warning with a deduction, on a host
    that had the rules.
    """
    covered: set[str] = set()
    for line in ufw_numbered.splitlines():
        if "(v6)" not in line:
            continue
        rule = _ufw.parse_rule(line)
        if rule is None or not rule.to_col:
            continue
        for lo, hi, proto in _ufw.to_column_ranges(rule.to_col, app_profiles):
            # A rule without an explicit protocol covers both.
            protos = (proto,) if proto else ("tcp", "udp")
            for port in range(lo, hi + 1):
                for pr in protos:
                    covered.add(f"{port}/{pr}")
    return covered
