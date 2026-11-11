"""
System hardening check for BOB.

Detects common hardening gaps via kernel network parameters:
rp_filter, ICMP redirects, log_martians, tcp_syncookies,
accept_source_route, send_redirects, protected_hardlinks/symlinks/fifos/regular
(fifos/regular since v0.24.0).

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

from dataclasses import dataclass, field
from pathlib import Path

from bob.checks._run import (TranslationFunc, _identity_t, read_sysctl_boot_files, report_boot_drift, sysctl_fix,
                             sysctl_fix_ifaces, sysctl_iface_key, sysctl_relpath)
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

@dataclass
class HardeningSnapshot:
    """
    Raw snapshot of system hardening state collected from the system.

    Args:
        rp_filter:                    Effective reverse-path posture (0, 1 or 2) —
                                      the weakest non-loopback interface, since
                                      the kernel applies max(conf/all, conf/<if>).
        accept_redirects:             True if net.ipv4.conf.all.accept_redirects == 1.
        log_martians:                 True if net.ipv4.conf.all.log_martians == 1.
        icmp_echo_ignore_broadcasts:  True if net.ipv4.icmp_echo_ignore_broadcasts == 1.
        tcp_syncookies:               Value of net.ipv4.tcp_syncookies (0=off, 1=on, 2=always).
        accept_source_route:          True if net.ipv4.conf.all.accept_source_route == 1.
        accept_redirects_v6:          True if net.ipv6.conf.all.accept_redirects == 1.
        send_redirects:               True if net.ipv4.conf.all.send_redirects == 1.
        protected_hardlinks:          True if fs.protected_hardlinks == 1.
        protected_symlinks:           True if fs.protected_symlinks == 1.
        protected_fifos:              fs.protected_fifos as int (0/1/2) or None.
        protected_regular:            fs.protected_regular as int (0/1/2) or None.
    """
    # None on every field means "this kernel does not expose the knob" — never
    # a stand-in for a value. The JSON output mirrors that as null.
    rp_filter:                   "int | None"  = None
    # v0.18.1 — context for the effective posture above. ``rp_filter_all`` is
    # conf/all alone (what BOB read before, and what confused it); ``rp_filter_iface``
    # names the interface whose effective value is the weakest, "" when the
    # posture came from the conf/all + conf/default fallback.
    rp_filter_all:               "int | None"  = None
    rp_filter_iface:             str           = ""
    accept_redirects:            "bool | None" = None
    log_martians:                "bool | None" = None
    #: v0.31.0 — where each per-interface knob is in effect, as the kernel
    #: combines conf/all with the interface's own value (``_effective_where``):
    #: interface names, and "default" for interfaces created from now on.
    #: ``log_martians_off`` lists where martians are *not* logged.
    accept_redirects_where:      list = field(default_factory=list)
    log_martians_off:            list = field(default_factory=list)
    accept_source_route_where:   list = field(default_factory=list)
    accept_redirects_v6_where:   list = field(default_factory=list)
    send_redirects_where:        list = field(default_factory=list)
    #: v0.31.4 — among send_redirects_where, the interfaces whose own
    #: ``forwarding`` is 1: the only ones a redirect can leave from
    #: (``_forwarding_among``). [] = none forwards; None = not read.
    send_redirects_forwarding:   "list | None" = None
    icmp_echo_ignore_broadcasts: "bool | None" = None
    tcp_syncookies:              "int | None"  = None
    accept_source_route:         "bool | None" = None
    accept_redirects_v6:         "bool | None" = None
    send_redirects:              "bool | None" = None
    protected_hardlinks:         "bool | None" = None
    protected_symlinks:          "bool | None" = None
    protected_fifos:             "int | None" = None
    protected_regular:           "int | None" = None
    #: v0.24.4 — the sysctl files applied at boot (``read_sysctl_boot_files``),
    #: so a fix persists where its value survives the next reboot.
    boot_sysctl: list = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "HardeningSnapshot":
        """
        Collect hardening state from the live system via subprocess.

        Returns:
            Populated HardeningSnapshot. Never raises — errors are
            reflected as safe/default values.
        """
        # --- kernel sysctl parameters ---
        rp_filter, rp_filter_all, rp_filter_iface = _effective_rp_filter()
        # v0.31.0 — per interface, as the kernel decides (``_effective_where``).
        accept_redirects_by = _effective_by_iface("accept_redirects", "redirects")
        log_martians_by     = _effective_by_iface("log_martians", "or")
        accept_source_route_by = _effective_by_iface("accept_source_route", "and")
        accept_redirects_v6_by = _effective_by_iface("accept_redirects", "v6", family="ipv6")
        send_redirects_by   = _effective_by_iface("send_redirects", "or")
        accept_redirects            = _any_on(accept_redirects_by)
        log_martians                = _all_on(log_martians_by)
        icmp_echo_ignore_broadcasts = _read_sysctl_bool("net.ipv4.icmp_echo_ignore_broadcasts")
        tcp_syncookies              = _read_sysctl_int("net.ipv4.tcp_syncookies")
        accept_source_route         = _any_on(accept_source_route_by)
        accept_redirects_v6         = _any_on(accept_redirects_v6_by)
        send_redirects              = _any_on(send_redirects_by)
        protected_hardlinks         = _read_sysctl_bool("fs.protected_hardlinks")
        protected_symlinks          = _read_sysctl_bool("fs.protected_symlinks")
        # fifos/regular are 0/1/2 (2 strengthens 1), so read them as ints — the
        # bool reader treats only "1" as set and would misread "2" as disabled.
        protected_fifos             = _read_sysctl_int("fs.protected_fifos")
        protected_regular           = _read_sysctl_int("fs.protected_regular")

        return cls(
            boot_sysctl=read_sysctl_boot_files(),
            rp_filter=rp_filter,
            rp_filter_all=rp_filter_all,
            rp_filter_iface=rp_filter_iface,
            accept_redirects=accept_redirects,
            log_martians=log_martians,
            accept_redirects_where=_on(accept_redirects_by),
            log_martians_off=_off(log_martians_by),
            accept_source_route_where=_on(accept_source_route_by),
            accept_redirects_v6_where=_on(accept_redirects_v6_by),
            send_redirects_where=_on(send_redirects_by),
            send_redirects_forwarding=(None if send_redirects_by is None
                                       else _forwarding_among(_on(send_redirects_by))),
            icmp_echo_ignore_broadcasts=icmp_echo_ignore_broadcasts,
            tcp_syncookies=tcp_syncookies,
            accept_source_route=accept_source_route,
            accept_redirects_v6=accept_redirects_v6,
            send_redirects=send_redirects,
            protected_hardlinks=protected_hardlinks,
            protected_symlinks=protected_symlinks,
            protected_fifos=protected_fifos,
            protected_regular=protected_regular,
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
        result.info(
            message=_t("hardening.rp_filter_loose"),
            detail=_rp_filter_context(snapshot, _t),
            key="hardening.rp_filter_loose")
    else:
        # Genuinely off: the weakest interface's max(conf/all, conf/<if>) is 0,
        # so conf/all is 0 and no interface lifts it. Setting conf/all = 1
        # forces effective >= 1 everywhere it is currently 0, which is exactly
        # this case.
        result.warn_with_deduction(
            key="hardening.rp_filter_disabled",
            message=_t("hardening.rp_filter_disabled"),
            detail=_rp_filter_context(snapshot, _t),
            points=1,
            **sysctl_fix("net.ipv4.conf.all.rp_filter=1", boot=snapshot.boot_sysctl),
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
            detail=_where(_t, "hardening.where_redirects", snapshot.accept_redirects_where),
            points=1,
            **sysctl_fix_ifaces("net.ipv4.conf", "accept_redirects", "0", snapshot.accept_redirects_where,
                                boot=snapshot.boot_sysctl),
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
            detail=" ".join(x for x in (_t("hardening.log_martians_disabled_detail"),
                                        _where(_t, "hardening.where_off_or", snapshot.log_martians_off)) if x),
            **sysctl_fix("net.ipv4.conf.all.log_martians=1", boot=snapshot.boot_sysctl),
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
            **sysctl_fix("net.ipv4.tcp_syncookies=1", boot=snapshot.boot_sysctl),
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
            detail=_where(_t, "hardening.where_and", snapshot.accept_source_route_where),
            points=1,
            **sysctl_fix("net.ipv4.conf.all.accept_source_route=0", boot=snapshot.boot_sysctl),
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
            detail=_where(_t, "hardening.where_v6", snapshot.accept_redirects_v6_where),
            points=1,
            **sysctl_fix_ifaces("net.ipv6.conf", "accept_redirects", "0", snapshot.accept_redirects_v6_where,
                                boot=snapshot.boot_sysctl),
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
        detail = " ".join(x for x in (_t("hardening.send_redirects_detail"),
                                      _send_redirects_case(_t, snapshot.send_redirects_forwarding),
                                      _where(_t, "hardening.where_or", snapshot.send_redirects_where)) if x)
        fix = sysctl_fix_ifaces("net.ipv4.conf", "send_redirects", "0", snapshot.send_redirects_where,
                                boot=snapshot.boot_sysctl)
        if snapshot.send_redirects_forwarding == []:
            # v0.32.0 — no interface forwards (by its own forwarding value,
            # and "default" for interfaces created from now on): the kernel
            # sends no redirect today. Measured on Linux 7.0 in network
            # namespaces (0.31.4): forwarding off and send_redirects at 1, 0
            # redirects. Said, not scored — the point stays where an interface
            # forwards, or where forwarding could not be read (None). The fix
            # is still shown.
            result.info(
                key="hardening.send_redirects_enabled",
                message=_t("hardening.send_redirects_enabled"),
                detail=detail,
                **fix,
            )
        else:
            result.warn_with_deduction(
                key="hardening.send_redirects_enabled",
                message=_t("hardening.send_redirects_enabled"),
                points=1,
                detail=detail,
                **fix,
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
            **sysctl_fix("fs.protected_hardlinks=1", boot=snapshot.boot_sysctl),
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
            **sysctl_fix("fs.protected_symlinks=1", boot=snapshot.boot_sysctl),
            nature="action",
        )
    # --- fs.protected_fifos (0/1/2; >=1 is protective, 2 strengthens 1) ---
    if snapshot.protected_fifos is None:
        _missing.append(_SYSCTL_NAMES["protected_fifos"])
    elif snapshot.protected_fifos >= 1:
        result.ok(
            message=_t("hardening.protected_fifos_ok", level=snapshot.protected_fifos),
            key="hardening.protected_fifos_ok",
            template_vars={"level": snapshot.protected_fifos},
        )
    else:
        result.warn_with_deduction(
            key="hardening.protected_fifos_disabled",
            message=_t("hardening.protected_fifos_disabled"),
            points=1,
            **sysctl_fix("fs.protected_fifos=2", boot=snapshot.boot_sysctl),
            nature="action",
        )
    # --- fs.protected_regular (0/1/2; >=1 is protective, 2 strengthens 1) ---
    if snapshot.protected_regular is None:
        _missing.append(_SYSCTL_NAMES["protected_regular"])
    elif snapshot.protected_regular >= 1:
        result.ok(
            message=_t("hardening.protected_regular_ok", level=snapshot.protected_regular),
            key="hardening.protected_regular_ok",
            template_vars={"level": snapshot.protected_regular},
        )
    else:
        result.warn_with_deduction(
            key="hardening.protected_regular_disabled",
            message=_t("hardening.protected_regular_disabled"),
            points=1,
            **sysctl_fix("fs.protected_regular=2", boot=snapshot.boot_sysctl),
            nature="action",
        )
    if _missing:
        result.info(
            message=_t("hardening.params_unavailable", params=", ".join(_missing)),
            detail=_t("hardening.params_unavailable_detail"),
            key="hardening.params_unavailable",
        )

    report_boot_drift(result, _t, "hardening.reverts_at_boot", {
        "net.ipv4.conf.all.rp_filter": snapshot.rp_filter_all,
        "net.ipv4.conf.all.accept_redirects": snapshot.accept_redirects,
        "net.ipv4.conf.all.log_martians": snapshot.log_martians,
        "net.ipv4.icmp_echo_ignore_broadcasts": snapshot.icmp_echo_ignore_broadcasts,
        "net.ipv4.tcp_syncookies": snapshot.tcp_syncookies,
        "net.ipv4.conf.all.accept_source_route": snapshot.accept_source_route,
        "net.ipv6.conf.all.accept_redirects": snapshot.accept_redirects_v6,
        "net.ipv4.conf.all.send_redirects": snapshot.send_redirects,
        "fs.protected_hardlinks": snapshot.protected_hardlinks,
        "fs.protected_symlinks": snapshot.protected_symlinks,
        "fs.protected_fifos": snapshot.protected_fifos,
        "fs.protected_regular": snapshot.protected_regular,
    }, snapshot.boot_sysctl)
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
    'protected_fifos'             : 'fs.protected_fifos',
    'protected_regular'           : 'fs.protected_regular',
}

#: Security ranking of the three rp_filter values: strict (1) is stronger than
#: loose (2), which is stronger than off (0). NOT the integer order — this is
#: why "the weakest interface" cannot be a plain min() of the values.
_RP_RANK = {1: 2, 2: 1, 0: 0}

#: conf/ entries that are not traffic-carrying interfaces: ``all`` is the knob
#: max()-ed into every interface, ``default`` is the template for future ones,
#: and ``lo`` (loopback) cannot receive a spoofed packet from the network.
_RP_NOT_AN_INTERFACE = frozenset({"all", "default", "lo"})
_SYS_NET = Path("/sys/class/net")


def _l2_port(name: str) -> bool:
    """v0.31.1 — an interface whose frames its bridge or bond takes before its
    own IP stack sees them: a bridge port (``brport/``) or a bond slave
    (``bonding_slave/``). Its own conf/<name> values decide nothing.

    Measured on Kali in network namespaces (7 November 2026,
    bridgeport-redirect-0311.txt), an ICMPv6 redirect sent through the port:
    the port at 1, its bridge or bond at 0 — refused, while 0.31.0 reported
    "IPv6 redirects accepted" (−1; seen on a Mint desktop, enp10s0 a port of
    br0); the bridge or bond at 1 — accepted. A VRF member keeps its own IP
    stack (its value at 1: accepted) and is still weighed. An interface whose
    markers cannot be read is weighed, as before.
    """
    for marker in ("brport", "bonding_slave"):
        try:
            if (_SYS_NET / name / marker).is_dir():
                return True
        except OSError:
            continue
    return False

_IPV4_CONF = Path("/proc/sys/net/ipv4/conf")


def _where(_t, key: str, names: list) -> str:
    """v0.31.0 — the interfaces a knob is in effect on, and the kernel's rule
    for it; "default" read as the template new interfaces inherit. Empty when
    there is no list (a snapshot built without one)."""
    if not names:
        return ""
    label = _t("hardening.where_default")
    return _t(key, where=", ".join(label if n == "default" else n for n in names))


def _send_redirects_case(_t, forwarding: "list | None") -> str:
    """v0.31.4 — whether a redirect can leave this host today: the interfaces
    that forward, or none. Empty when forwarding was not read."""
    if forwarding:
        return _where(_t, "hardening.send_redirects_forwarding", forwarding)
    if forwarding == []:
        return _t("hardening.send_redirects_idle")
    return ""


def _rp_filter_context(snapshot: "HardeningSnapshot", _t) -> str:
    """One line saying what was read where, so conf/all = 0 is not mistaken
    for the verdict. Empty when there is nothing to disambiguate."""
    if snapshot.rp_filter_iface and snapshot.rp_filter_all is not None:
        return _t(
            "hardening.rp_filter_context",
            iface=snapshot.rp_filter_iface,
            iface_effective=snapshot.rp_filter,
            all_value=snapshot.rp_filter_all,
        )
    return ""


def _effective_rp_filter() -> "tuple[int | None, int | None, str]":
    """The reverse-path posture the kernel actually enforces.

    For a packet arriving on interface X the kernel uses
    ``max(conf/all/rp_filter, conf/X/rp_filter)`` — reading conf/all alone (as
    BOB did through v0.18.0) reports "disabled" on the whole systemd family,
    which ships ``conf/all = 0`` while ``conf/default = 2`` gives every real
    interface an effective 2. Measured on a Raspberry Pi Zero W: all=0,
    wlan0=2, so wlan0 filters in loose mode and BOB warned it did not.

    Returns ``(posture, all_value, iface)``: the weakest posture across
    non-loopback interfaces by security rank, the raw conf/all, and the
    interface that set it. Falls back to ``max(all, default)`` with iface ""
    when no real interface can be read, and ``(None, None, "")`` when conf/all
    itself is unreadable (an ipv6.disable-style absent tree).
    """
    all_val = _read_sysctl_int("net.ipv4.conf.all.rp_filter")
    if all_val is None:
        return None, None, ""

    weakest: "int | None" = None
    weakest_iface = ""
    try:
        ifaces = sorted(d.name for d in _IPV4_CONF.iterdir()
                        if d.name not in _RP_NOT_AN_INTERFACE and not _l2_port(d.name))
    except OSError:
        ifaces = []
    for name in ifaces:
        iface_val = _read_sysctl_int(sysctl_iface_key("net.ipv4.conf", name, "rp_filter"))
        if iface_val is None:
            continue
        effective = max(all_val, iface_val)
        if weakest is None or _RP_RANK[effective] < _RP_RANK[weakest]:
            weakest, weakest_iface = effective, name

    if weakest is not None:
        return weakest, all_val, weakest_iface

    # No readable interface: use the template that a new one would inherit.
    default_val = _read_sysctl_int("net.ipv4.conf.default.rp_filter")
    if default_val is None:
        return all_val, all_val, ""
    return max(all_val, default_val), all_val, ""


_IPV6_CONF = Path("/proc/sys/net/ipv6/conf")


def _effective_by_iface(knob: str, rule: str, family: str = "ipv4") -> "dict[str, bool] | None":
    """v0.31.0 — whether *knob* is in effect on each interface (lo aside), and
    on "default" (what an interface created from now on inherits), as the
    kernel combines conf/all with the interface's own value. BOB read conf/all
    alone; measured on Ubuntu 26.04 (6 November 2026), BOB's fix for
    send_redirects set conf/all to 0 and said fixed while enp3s0 kept 1.

    The rules, from the kernel (include/linux/inetdevice.h and
    net/ipv6/route.c, Linux 6.18):

    - "or": conf/all OR the interface (send_redirects: IN_DEV_TX_REDIRECTS;
      log_martians: IN_DEV_LOG_MARTIANS);
    - "and": conf/all AND the interface (accept_source_route:
      IN_DEV_SOURCE_ROUTE);
    - "redirects": IPv4 accept_redirects, AND on an interface that forwards,
      OR on one that does not (IN_DEV_RX_REDIRECTS);
    - "v6": IPv6 accept_redirects, the interface's own value, and none on an
      interface that forwards (rt6_do_redirect); conf/all is not read.

    None when the knob cannot be read at all (an absent /proc/sys/net/ipv6
    under ipv6.disable=1, an unreadable conf/all). An interface that cannot be
    read — gone while BOB read it — is left out, as ``_effective_rp_filter``
    does.
    """
    base = _IPV6_CONF if family == "ipv6" else _IPV4_CONF
    prefix = "net.ipv6.conf" if family == "ipv6" else "net.ipv4.conf"

    def read(name: str, k: str) -> "bool | None":
        return _read_sysctl_bool(sysctl_iface_key(prefix, name, k))

    all_on = read("all", knob)
    if all_on is None:
        return None
    try:
        names = sorted(d.name for d in base.iterdir()
                       if d.name not in _RP_NOT_AN_INTERFACE and not _l2_port(d.name))
    except OSError:
        names = []
    effective: "dict[str, bool]" = {}
    for name in names + ["default"]:
        own = read(name, knob)
        if own is None:
            continue
        if rule == "or":
            effective[name] = all_on or own
        elif rule == "and":
            effective[name] = all_on and own
        else:
            forwards = read(name, "forwarding")
            if forwards is None:
                continue
            if rule == "redirects":
                effective[name] = (all_on and own) if forwards else (all_on or own)
            else:
                effective[name] = own and not forwards
    return effective


def _forwarding_among(names: list) -> "list | None":
    """v0.31.4 — the interfaces among *names* whose own ``forwarding`` is 1;
    "default" stands for interfaces created from now on.

    The kernel sends an ICMP redirect only for a packet it forwards back out
    the interface it came in on, and forwards only when that interface's own
    value is 1 — conf/all does not decide. Measured on Linux 7.0 in network
    namespaces (9 November 2026): all 0 and eth0 1 sent 4 redirects for 5
    pings; all 1 and eth0 0 forwarded nothing and sent none.

    None when one of the values cannot be read: the case is then not stated.
    """
    out = []
    for name in names:
        forwards = _read_sysctl_bool(sysctl_iface_key("net.ipv4.conf", name, "forwarding"))
        if forwards is None:
            return None
        if forwards:
            out.append(name)
    return out


def _on(by: "dict[str, bool] | None") -> list:
    return [n for n, on in (by or {}).items() if on]


def _off(by: "dict[str, bool] | None") -> list:
    return [n for n, on in (by or {}).items() if not on]


def _any_on(by: "dict[str, bool] | None") -> "bool | None":
    return None if by is None else bool(_on(by))


def _all_on(by: "dict[str, bool] | None") -> "bool | None":
    return None if by is None else not _off(by)


def _read_sysctl_int(key: str) -> "int | None":
    """Read a sysctl value as int via /proc/sys, or None if it cannot be read.

    See ``_read_sysctl_bool`` for why there is no default.
    """
    path = Path("/proc/sys") / sysctl_relpath(key)
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
    path = Path("/proc/sys") / sysctl_relpath(key)
    try:
        val = path.read_text(encoding="ascii", errors="ignore").strip()
        return val == "1"
    except OSError:
        return None
