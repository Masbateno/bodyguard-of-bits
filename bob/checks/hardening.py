"""
System hardening check for BOB.

Detects common hardening gaps via kernel network parameters:
rp_filter, ICMP redirects, log_martians, tcp_syncookies,
accept_source_route, send_redirects, protected_hardlinks/symlinks.

AppArmor is covered by checks/mac_policy.py (CHECK 34).

The check is split into two parts:
  1. HardeningSnapshot.from_system() — collects raw data via /proc/sys.
  2. check_hardening(snapshot)        — pure logic, returns a CheckResult.

Usage:
    from bob.checks.hardening import HardeningSnapshot, check_hardening

    snapshot = HardeningSnapshot.from_system()
    result   = check_hardening(snapshot)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class HardeningSnapshot:
    """
    Raw snapshot of system hardening state collected from the system.

    Args:
        rp_filter:                    Value of net.ipv4.conf.all.rp_filter (0, 1 or 2).
        accept_redirects:             True if net.ipv4.conf.all.accept_redirects == 1.
        log_martians:                 True if net.ipv4.conf.all.log_martians == 1.
        icmp_echo_ignore_broadcasts:  True if net.ipv4.icmp_echo_ignore_broadcasts == 1.
        tcp_syncookies:               Value of net.ipv4.tcp_syncookies (0=off, 1=on, 2=always).
        accept_source_route:          True if net.ipv4.conf.all.accept_source_route == 1.
        accept_redirects_v6:          True if net.ipv6.conf.all.accept_redirects == 1.
        send_redirects:               True if net.ipv4.conf.all.send_redirects == 1.
        protected_hardlinks:          True if fs.protected_hardlinks == 1.
        protected_symlinks:           True if fs.protected_symlinks == 1.
    """
    rp_filter:                   int  = 1
    accept_redirects:            bool = False
    log_martians:                bool = True
    icmp_echo_ignore_broadcasts: bool = True
    tcp_syncookies:              int  = 1
    accept_source_route:         bool = False
    accept_redirects_v6:         bool = False
    send_redirects:              bool = False
    protected_hardlinks:         bool = True
    protected_symlinks:          bool = True

    @classmethod
    def from_system(cls) -> "HardeningSnapshot":
        """
        Collect hardening state from the live system via subprocess.

        Returns:
            Populated HardeningSnapshot. Never raises — errors are
            reflected as safe/default values.
        """
        # --- kernel sysctl parameters ---
        rp_filter                   = _read_sysctl_int("net.ipv4.conf.all.rp_filter",    default=1)
        accept_redirects            = _read_sysctl_bool("net.ipv4.conf.all.accept_redirects", default=False)
        log_martians                = _read_sysctl_bool("net.ipv4.conf.all.log_martians",     default=True)
        icmp_echo_ignore_broadcasts = _read_sysctl_bool("net.ipv4.icmp_echo_ignore_broadcasts", default=True)
        tcp_syncookies              = _read_sysctl_int("net.ipv4.tcp_syncookies",             default=1)
        accept_source_route         = _read_sysctl_bool("net.ipv4.conf.all.accept_source_route", default=False)
        accept_redirects_v6         = _read_sysctl_bool("net.ipv6.conf.all.accept_redirects",    default=False)
        send_redirects              = _read_sysctl_bool("net.ipv4.conf.all.send_redirects",      default=False)
        protected_hardlinks         = _read_sysctl_bool("fs.protected_hardlinks",                default=True)
        protected_symlinks          = _read_sysctl_bool("fs.protected_symlinks",                 default=True)

        return cls(
            rp_filter=rp_filter,
            accept_redirects=accept_redirects,
            log_martians=log_martians,
            icmp_echo_ignore_broadcasts=icmp_echo_ignore_broadcasts,
            tcp_syncookies=tcp_syncookies,
            accept_source_route=accept_source_route,
            accept_redirects_v6=accept_redirects_v6,
            send_redirects=send_redirects,
            protected_hardlinks=protected_hardlinks,
            protected_symlinks=protected_symlinks,
        )


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_hardening(snapshot: HardeningSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Check system hardening configuration.

    Args:
        snapshot: HardeningSnapshot from the system (or built in tests).
        t:        Translation function. Defaults to key pass-through.

    Returns:
        CheckResult with findings and any score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- rp_filter (reverse path filtering) ---
    # 0 = disabled (insecure), 1 = strict mode (best), 2 = loose mode (weaker)
    if snapshot.rp_filter == 1:
        result.ok(message=_t("hardening.rp_filter_ok"),
                  key="hardening.rp_filter_ok")
    elif snapshot.rp_filter == 2:
        result.info(message=_t("hardening.rp_filter_loose"),
                    key="hardening.rp_filter_loose")
    else:
        result.warn(
            message=_t("hardening.rp_filter_disabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.conf.all.rp_filter=1 && echo 'net.ipv4.conf.all.rp_filter=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.rp_filter_disabled",
        )
        result.add_deduction(
            reason=_t("hardening.rp_filter_disabled"),
            points=1,
            context="local",
            key="hardening.rp_filter_disabled",
        )
    # --- ICMP redirects ---
    if not snapshot.accept_redirects:
        result.ok(message=_t("hardening.redirects_ok"),
                  key="hardening.redirects_ok")
    else:
        result.warn(
            message=_t("hardening.redirects_enabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 && echo 'net.ipv4.conf.all.accept_redirects=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.redirects_enabled",
        )
        result.add_deduction(
            reason=_t("hardening.redirects_enabled"),
            points=1,
            context="local",
            key="hardening.redirects_enabled",
        )
    # --- log_martians ---
    if snapshot.log_martians:
        result.ok(message=_t("hardening.log_martians_ok"),
                  key="hardening.log_martians_ok")
    else:
        result.info(
            message=_t("hardening.log_martians_disabled"),
            detail=_t("hardening.log_martians_disabled_detail"),
            cmd="sudo sysctl -w net.ipv4.conf.all.log_martians=1 && echo 'net.ipv4.conf.all.log_martians=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.log_martians_disabled",
        )

    # --- ICMP broadcast echo ---
    if snapshot.icmp_echo_ignore_broadcasts:
        result.ok(message=_t("hardening.icmp_broadcast_ok"),
                  key="hardening.icmp_broadcast_ok")
    else:
        result.info(
            message=_t("hardening.icmp_broadcast_enabled"),
            key="hardening.icmp_broadcast_enabled",
        )

    # --- tcp_syncookies (SYN flood protection) ---
    if snapshot.tcp_syncookies >= 1:
        result.ok(
            message=_t("hardening.tcp_syncookies_ok", value=snapshot.tcp_syncookies),
            key="hardening.tcp_syncookies_ok",
            template_vars={"value": snapshot.tcp_syncookies},  # pilot v0.4.1
        )
    else:
        result.warn(
            message=_t("hardening.tcp_syncookies_disabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.tcp_syncookies_disabled",
        )
        result.add_deduction(
            reason=_t("hardening.tcp_syncookies_disabled"),
            points=1,
            context="local",
            key="hardening.tcp_syncookies_disabled",
        )
    # --- accept_source_route (IP source routing) ---
    if not snapshot.accept_source_route:
        result.ok(
            message=_t("hardening.accept_source_route_ok"),
            key="hardening.accept_source_route_ok",
        )
    else:
        result.warn(
            message=_t("hardening.accept_source_route_enabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.conf.all.accept_source_route=0 && echo 'net.ipv4.conf.all.accept_source_route=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.accept_source_route_enabled",
        )
        result.add_deduction(
            reason=_t("hardening.accept_source_route_enabled"),
            points=1,
            context="local",
            key="hardening.accept_source_route_enabled",
        )
    # --- IPv6 ICMP redirects ---
    if not snapshot.accept_redirects_v6:
        result.ok(
            message=_t("hardening.accept_redirects_v6_ok"),
            key="hardening.accept_redirects_v6_ok",
        )
    else:
        result.warn(
            message=_t("hardening.accept_redirects_v6_enabled"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv6.conf.all.accept_redirects=0 && echo 'net.ipv6.conf.all.accept_redirects=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.accept_redirects_v6_enabled",
        )
        result.add_deduction(
            reason=_t("hardening.accept_redirects_v6_enabled"),
            points=1,
            context="local",
            key="hardening.accept_redirects_v6_enabled",
        )
    # --- send_redirects ---
    if not snapshot.send_redirects:
        result.ok(
            message=_t("hardening.send_redirects_ok"),
            key="hardening.send_redirects_ok",
        )
    else:
        result.warn(
            message=_t("hardening.send_redirects_enabled"),
            detail=_t("hardening.send_redirects_detail"),
            nature="improvement",
            cmd="sudo sysctl -w net.ipv4.conf.all.send_redirects=0 && echo 'net.ipv4.conf.all.send_redirects=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.send_redirects_enabled",
        )
        result.add_deduction(
            reason=_t("hardening.send_redirects_enabled"),
            points=1,
            context="local",
            key="hardening.send_redirects_enabled",
        )
    # --- fs.protected_hardlinks ---
    if snapshot.protected_hardlinks:
        result.ok(
            message=_t("hardening.protected_hardlinks_ok"),
            key="hardening.protected_hardlinks_ok",
        )
    else:
        result.warn(
            message=_t("hardening.protected_hardlinks_disabled"),
            nature="improvement",
            cmd="sudo sysctl -w fs.protected_hardlinks=1 && echo 'fs.protected_hardlinks=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.protected_hardlinks_disabled",
        )
        result.add_deduction(
            reason=_t("hardening.protected_hardlinks_disabled"),
            points=1,
            context="local",
            key="hardening.protected_hardlinks_disabled",
        )
    # --- fs.protected_symlinks ---
    if snapshot.protected_symlinks:
        result.ok(
            message=_t("hardening.protected_symlinks_ok"),
            key="hardening.protected_symlinks_ok",
        )
    else:
        result.warn(
            message=_t("hardening.protected_symlinks_disabled"),
            nature="improvement",
            cmd="sudo sysctl -w fs.protected_symlinks=1 && echo 'fs.protected_symlinks=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            key="hardening.protected_symlinks_disabled",
        )
        result.add_deduction(
            reason=_t("hardening.protected_symlinks_disabled"),
            points=1,
            context="local",
            key="hardening.protected_symlinks_disabled",
        )
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_sysctl_int(key: str, default: int) -> int:
    """Read a sysctl value as int via /proc/sys."""
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return int(path.read_text(encoding="ascii", errors="ignore").strip())
    except (OSError, ValueError):
        return default


def _read_sysctl_bool(key: str, default: bool) -> bool:
    """Read a sysctl value and return True if it equals "1"."""
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        val = path.read_text(encoding="ascii", errors="ignore").strip()
        return val == "1"
    except OSError:
        return default
