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
    # None on every field means "this kernel does not expose the knob" — never
    # a stand-in for a value. The JSON output mirrors that as null.
    rp_filter:                   "int | None"  = None
    accept_redirects:            "bool | None" = None
    log_martians:                "bool | None" = None
    icmp_echo_ignore_broadcasts: "bool | None" = None
    tcp_syncookies:              "int | None"  = None
    accept_source_route:         "bool | None" = None
    accept_redirects_v6:         "bool | None" = None
    send_redirects:              "bool | None" = None
    protected_hardlinks:         "bool | None" = None
    protected_symlinks:          "bool | None" = None

    @classmethod
    def from_system(cls) -> "HardeningSnapshot":
        """
        Collect hardening state from the live system via subprocess.

        Returns:
            Populated HardeningSnapshot. Never raises — errors are
            reflected as safe/default values.
        """
        # --- kernel sysctl parameters ---
        rp_filter                   = _read_sysctl_int("net.ipv4.conf.all.rp_filter")
        accept_redirects            = _read_sysctl_bool("net.ipv4.conf.all.accept_redirects")
        log_martians                = _read_sysctl_bool("net.ipv4.conf.all.log_martians")
        icmp_echo_ignore_broadcasts = _read_sysctl_bool("net.ipv4.icmp_echo_ignore_broadcasts")
        tcp_syncookies              = _read_sysctl_int("net.ipv4.tcp_syncookies")
        accept_source_route         = _read_sysctl_bool("net.ipv4.conf.all.accept_source_route")
        accept_redirects_v6         = _read_sysctl_bool("net.ipv6.conf.all.accept_redirects")
        send_redirects              = _read_sysctl_bool("net.ipv4.conf.all.send_redirects")
        protected_hardlinks         = _read_sysctl_bool("fs.protected_hardlinks")
        protected_symlinks          = _read_sysctl_bool("fs.protected_symlinks")

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
    # Knobs this kernel does not expose. Reported once, together, as an INFO:
    # an absent parameter is neither a pass nor a scoreable failure.
    _missing: list[str] = []

    # --- rp_filter (reverse path filtering) ---
    # 0 = disabled (insecure), 1 = strict mode (best), 2 = loose mode (weaker)
    if snapshot.rp_filter is None:
        _missing.append(_SYSCTL_NAMES["rp_filter"])
    elif snapshot.rp_filter == 1:
        result.ok(message=_t("hardening.rp_filter_ok"),
                  key="hardening.rp_filter_ok")
    elif snapshot.rp_filter == 2:
        result.info(message=_t("hardening.rp_filter_loose"),
                    key="hardening.rp_filter_loose")
    else:
        result.warn_with_deduction(
            key="hardening.rp_filter_disabled",
            message=_t("hardening.rp_filter_disabled"),
            points=1,
            cmd="sudo sysctl -w net.ipv4.conf.all.rp_filter=1 && echo 'net.ipv4.conf.all.rp_filter=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- ICMP redirects ---
    if snapshot.accept_redirects is None:
        _missing.append(_SYSCTL_NAMES["accept_redirects"])
    elif not snapshot.accept_redirects:
        result.ok(message=_t("hardening.redirects_ok"),
                  key="hardening.redirects_ok")
    else:
        result.warn_with_deduction(
            key="hardening.redirects_enabled",
            message=_t("hardening.redirects_enabled"),
            points=1,
            cmd="sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 && echo 'net.ipv4.conf.all.accept_redirects=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- log_martians ---
    if snapshot.log_martians is None:
        _missing.append(_SYSCTL_NAMES["log_martians"])
    elif snapshot.log_martians:
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
    if snapshot.icmp_echo_ignore_broadcasts is None:
        _missing.append(_SYSCTL_NAMES["icmp_echo_ignore_broadcasts"])
    elif snapshot.icmp_echo_ignore_broadcasts:
        result.ok(message=_t("hardening.icmp_broadcast_ok"),
                  key="hardening.icmp_broadcast_ok")
    else:
        result.info(
            message=_t("hardening.icmp_broadcast_enabled"),
            key="hardening.icmp_broadcast_enabled",
        )

    # --- tcp_syncookies (SYN flood protection) ---
    if snapshot.tcp_syncookies is None:
        _missing.append(_SYSCTL_NAMES["tcp_syncookies"])
    elif snapshot.tcp_syncookies >= 1:
        result.ok(
            message=_t("hardening.tcp_syncookies_ok", value=snapshot.tcp_syncookies),
            key="hardening.tcp_syncookies_ok",
            template_vars={"value": snapshot.tcp_syncookies},  # pilot v0.4.1
        )
    else:
        result.warn_with_deduction(
            key="hardening.tcp_syncookies_disabled",
            message=_t("hardening.tcp_syncookies_disabled"),
            points=1,
            cmd="sudo sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- accept_source_route (IP source routing) ---
    if snapshot.accept_source_route is None:
        _missing.append(_SYSCTL_NAMES["accept_source_route"])
    elif not snapshot.accept_source_route:
        result.ok(
            message=_t("hardening.accept_source_route_ok"),
            key="hardening.accept_source_route_ok",
        )
    else:
        result.warn_with_deduction(
            key="hardening.accept_source_route_enabled",
            message=_t("hardening.accept_source_route_enabled"),
            points=1,
            cmd="sudo sysctl -w net.ipv4.conf.all.accept_source_route=0 && echo 'net.ipv4.conf.all.accept_source_route=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- IPv6 ICMP redirects ---
    if snapshot.accept_redirects_v6 is None:
        _missing.append(_SYSCTL_NAMES["accept_redirects_v6"])
    elif not snapshot.accept_redirects_v6:
        result.ok(
            message=_t("hardening.accept_redirects_v6_ok"),
            key="hardening.accept_redirects_v6_ok",
        )
    else:
        result.warn_with_deduction(
            key="hardening.accept_redirects_v6_enabled",
            message=_t("hardening.accept_redirects_v6_enabled"),
            points=1,
            cmd="sudo sysctl -w net.ipv6.conf.all.accept_redirects=0 && echo 'net.ipv6.conf.all.accept_redirects=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- send_redirects ---
    if snapshot.send_redirects is None:
        _missing.append(_SYSCTL_NAMES["send_redirects"])
    elif not snapshot.send_redirects:
        result.ok(
            message=_t("hardening.send_redirects_ok"),
            key="hardening.send_redirects_ok",
        )
    else:
        result.warn_with_deduction(
            key="hardening.send_redirects_enabled",
            message=_t("hardening.send_redirects_enabled"),
            points=1,
            detail=_t("hardening.send_redirects_detail"),
            cmd="sudo sysctl -w net.ipv4.conf.all.send_redirects=0 && echo 'net.ipv4.conf.all.send_redirects=0' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- fs.protected_hardlinks ---
    if snapshot.protected_hardlinks is None:
        _missing.append(_SYSCTL_NAMES["protected_hardlinks"])
    elif snapshot.protected_hardlinks:
        result.ok(
            message=_t("hardening.protected_hardlinks_ok"),
            key="hardening.protected_hardlinks_ok",
        )
    else:
        result.warn_with_deduction(
            key="hardening.protected_hardlinks_disabled",
            message=_t("hardening.protected_hardlinks_disabled"),
            points=1,
            cmd="sudo sysctl -w fs.protected_hardlinks=1 && echo 'fs.protected_hardlinks=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    # --- fs.protected_symlinks ---
    if snapshot.protected_symlinks is None:
        _missing.append(_SYSCTL_NAMES["protected_symlinks"])
    elif snapshot.protected_symlinks:
        result.ok(
            message=_t("hardening.protected_symlinks_ok"),
            key="hardening.protected_symlinks_ok",
        )
    else:
        result.warn_with_deduction(
            key="hardening.protected_symlinks_disabled",
            message=_t("hardening.protected_symlinks_disabled"),
            points=1,
            cmd="sudo sysctl -w fs.protected_symlinks=1 && echo 'fs.protected_symlinks=1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            nature="action",
        )
    if _missing:
        result.info(
            message=_t("hardening.params_unavailable", params=", ".join(_missing)),
            detail=_t("hardening.params_unavailable_detail"),
            key="hardening.params_unavailable",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Field name -> the sysctl an operator would look for, used by the single
# "not exposed by this kernel" finding.
_SYSCTL_NAMES = {
    'rp_filter'                   : 'net.ipv4.conf.all.rp_filter',
    'accept_redirects'            : 'net.ipv4.conf.all.accept_redirects',
    'log_martians'                : 'net.ipv4.conf.all.log_martians',
    'icmp_echo_ignore_broadcasts' : 'net.ipv4.icmp_echo_ignore_broadcasts',
    'tcp_syncookies'              : 'net.ipv4.tcp_syncookies',
    'accept_source_route'         : 'net.ipv4.conf.all.accept_source_route',
    'accept_redirects_v6'         : 'net.ipv6.conf.all.accept_redirects',
    'send_redirects'              : 'net.ipv4.conf.all.send_redirects',
    'protected_hardlinks'         : 'fs.protected_hardlinks',
    'protected_symlinks'          : 'fs.protected_symlinks',
}

def _read_sysctl_int(key: str) -> "int | None":
    """Read a sysctl value as int via /proc/sys, or None if it cannot be read.

    See ``_read_sysctl_bool`` for why there is no default.
    """
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return int(path.read_text(encoding="ascii", errors="ignore").strip())
    except (OSError, ValueError):
        return None


def _read_sysctl_bool(key: str) -> "bool | None":
    """Read a sysctl value as a flag, or None if it cannot be read.

    Until v0.15.0 both readers took a ``default`` used on any read failure, and
    every one of the ten call sites passed the *hardened* value. So an
    unreadable /proc/sys produced a perfectly hardened network stack — this is
    the SYSTEM HARDENING section, and it would report ten passes for ten
    parameters it had not read. The realistic trigger is not exotic: boot with
    ``ipv6.disable=1`` and ``/proc/sys/net/ipv6`` does not exist at all, so
    ``net.ipv6.conf.all.accept_redirects`` was answered from the default alone.

    None means "not read", which is a distinct answer from any value.
    """
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        val = path.read_text(encoding="ascii", errors="ignore").strip()
        return val == "1"
    except OSError:
        return None
