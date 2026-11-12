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

from bob.checks._run import TranslationFunc, _command_exists, _identity_t, _run, kubelet_running, path_exists, sysctl_fix
from bob.scoring import CheckResult


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

# `iptables -L` opens every chain with this header under LC_ALL=C, rules or no
# rules. Its absence means the listing did not come from iptables.
_IPTABLES_CHAIN_RE = re.compile(r"^Chain\s+\S+", re.MULTILINE)

#: v0.31.3 — where the system libvirt keeps the state of its active networks,
#: and the forward modes that route through the host (a ``<forward>`` with no
#: mode is NAT). Measured on Ubuntu Server 26.04, libvirt 12.0.0: the network
#: ``default`` active wrote ``default.xml`` there (``<forward mode='nat'>``,
#: bridge virbr0) and set ip_forward; ``virsh net-destroy default`` removed it
#: and the bridge (a ``default.pid`` stayed); an isolated network wrote one
#: with no ``<forward>``; stopping every libvirt daemon left the network, its
#: file, its bridge and its dnsmasq in place.
_LIBVIRT_NETWORK_STATE = Path("/run/libvirt/network")
_SYS_CLASS_NET = Path("/sys/class/net")
_LIBVIRT_ROUTING_MODES = frozenset({"nat", "route", "open"})


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
        docker_present:      True while a dockerd process runs (v0.32.0;
                             it was: docker or /var/lib/docker present).
        wireguard_present:   True while a WireGuard interface exists (v0.32.0;
                             it was: wg or /etc/wireguard/*.conf present).
        libvirt_present:     True while a libvirt network routes through the host
                             (v0.31.3; it was: libvirt installed). See _libvirt_routing.
        kubernetes_running:  True if a kubelet runs (kubelet, MicroK8s'
                             kubelite, k3s) — pod networking needs forwarding.
    """
    input_raw_accepts:   list[str] = field(default_factory=list)
    #: v0.26.0 — the rules of the raw, mangle and nat tables that set a
    #: packet mark (all of them run before the filter INPUT chain), ``-S`` form.
    mark_setters:        list[str] = field(default_factory=list)
    #: v0.26.0 — every ``-A INPUT`` rule of the filter table, in order, each
    #: jump to a user chain followed inline: a mark set there counts only for
    #: the rules below it.
    input_rules:         list[str] = field(default_factory=list)
    forward_raw_accepts: list[str] = field(default_factory=list)
    nftables_active:     bool = False
    # False when the ruleset could not be listed at all — distinct from
    # having listed it and found nothing.
    rules_readable:      bool = True
    ip_forward:          bool = False
    docker_present:      bool = False
    wireguard_present:   bool = False
    libvirt_present:     bool = False
    kubernetes_running:  bool = False
    #: v0.33.0 — the ``-A FORWARD … -j ACCEPT`` lines in ``-S`` form (``-L``
    #: prints neither interfaces nor ``-i``/``-o``), to tell whose a rule is;
    #: the WireGuard interfaces by name; MicroK8s' own process running.
    forward_accepts_s:   list[str] = field(default_factory=list)
    wireguard_ifaces:    list[str] = field(default_factory=list)
    microk8s_running:    bool = False
    #: v0.33.0 — the interfaces that exist (/sys/class/net); None when they
    #: could not be listed. A rule naming one BOB cannot attribute is unknown;
    #: one naming an interface that does not exist is a stale rule.
    host_ifaces:         "list[str] | None" = None
    #: v0.34.0 — IPv4 datagrams the kernel forwarded since boot
    #: (/proc/net/snmp, ``Ip: ForwDatagrams``) and the seconds since boot;
    #: None when unread. Measured in network namespaces (wgfwd): a WireGuard
    #: client with ip_forward=1 and traffic in its tunnel stays at 0, a
    #: WireGuard gateway routing its client to a LAN counts each datagram.
    forwarded_v4:        "int | None" = None
    uptime_s:            "float | None" = None

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
        # v0.26.0 — the INPUT rules are read in `-S` form: `-L -n` drops the
        # interface, so `-i lo -j ACCEPT` printed exactly as an accept-all
        # (measured in a network namespace with ufw 0.36).
        input_s     = _run("iptables", "-S", "INPUT")
        input_raw   = _parse_raw_accepts_s(input_s)
        # v0.26.0 — what a mark rule accepts depends on who sets the mark:
        # measured with ufw 0.36 active, a mangle PREROUTING MARK on new
        # 8099 packets opened 8099 through `-m mark --mark … -j ACCEPT`.
        input_rules = (_input_path(_run("iptables", "-S"))
                       or [ln.strip() for ln in input_s.splitlines() if ln.startswith("-A ")])
        forward_raw = _parse_raw_accepts(forward_out)

        nft_out         = _run("nft", "list", "ruleset") if _command_exists("nft") else ""
        # v0.27.0 — and native nftables marks too: measured in a network
        # namespace, `meta mark set …` in an inet prerouting chain opened 8099
        # through the same accept, and BOB, reading iptables only, called it
        # conditional.
        mark_setters = _mark_setters(*(_run("iptables", "-t", table, "-S")
                                       for table in ("raw", "mangle", "nat")),
                                     extra=_nft_mark_setters(nft_out))
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

        # v0.32.0 — Docker and WireGuard while they run, not because they are
        # installed (libvirt went the same way in v0.31.3). Measured on Ubuntu
        # Server 26.04 (11 November 2026, route0320): with Docker stopped,
        # docker0, its 15 DOCKER rules and /var/lib/docker stayed, and only the
        # dockerd process was gone; WireGuard configured (wg, /etc/wireguard/
        # *.conf) had no interface until wg-quick brought one up.
        docker_present = _dockerd_runs()
        wireguard_ifaces = _wireguard_ifaces()
        wireguard_present = bool(wireguard_ifaces)

        # libvirt/KVM also requires ip_forward and manages FORWARD rules —
        # v0.31.3: while one of its networks routes, not because it is installed.
        libvirt_present = _libvirt_routing()

        return cls(
            input_raw_accepts=input_raw,
            mark_setters=mark_setters,
            input_rules=input_rules,
            forward_raw_accepts=forward_raw,
            nftables_active=nftables_active,
            rules_readable=rules_readable,
            ip_forward=ip_forward,
            docker_present=docker_present,
            wireguard_present=wireguard_present,
            libvirt_present=libvirt_present,
            kubernetes_running=kubelet_running(),
            forward_accepts_s=_parse_raw_accepts_s(_run("iptables", "-S", "FORWARD")),
            wireguard_ifaces=wireguard_ifaces,
            microk8s_running=_process_runs("kubelite"),
            host_ifaces=_host_ifaces(),
            forwarded_v4=_forwarded_v4(),
            uptime_s=_uptime_s(),
        )


def _libvirt_routing(modes: frozenset = _LIBVIRT_ROUTING_MODES) -> bool:
    """v0.31.3 — a libvirt network that routes through the host is active: its
    state file names a NAT, route or open forward and its bridge exists.

    0.31.2 counted libvirt as a routing daemon as soon as ``libvirtd``,
    ``virtqemud`` or /var/lib/libvirt existed: installed, not routing. With
    ip_forward on, that turned `firewall_drivers.ip_forward_enabled` (WARN −1)
    into "IP forwarding enabled — routing daemon detected" (OK). Measured on
    Ubuntu Server 26.04 (libvirt 12.0.0, the network destroyed, ip_forward 1).
    A state file BOB cannot read is an active network of unknown mode: counted
    (most are NAT). A directory BOB cannot list: what 0.31.2 read. *modes*: the
    forward modes that count (the virtualisation section asks for the two
    libvirt writes firewall rules for).
    """
    try:
        states = [p for p in _LIBVIRT_NETWORK_STATE.iterdir() if p.name.endswith(".xml")]
    except FileNotFoundError:
        return False
    except OSError:
        return (_command_exists("libvirtd") or _command_exists("virtqemud")
                or Path("/var/lib/libvirt").is_dir())
    import xml.etree.ElementTree as ET
    for state in states:
        try:
            root = ET.fromstring(state.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return True
        except ET.ParseError:
            continue
        forward = root.find(".//forward")
        bridge = root.find(".//bridge")
        if forward is None or bridge is None:
            continue
        name = bridge.get("name") or ""
        if (forward.get("mode") or "nat") in modes and name and path_exists(_SYS_CLASS_NET / name):
            return True
    return False


_PROC = Path("/proc")
_SYS_NET = Path("/sys/class/net")


def _host_ifaces() -> "list[str] | None":
    """v0.33.0 — the network interfaces that exist; None when unlisted."""
    try:
        return sorted(i.name for i in _SYS_NET.iterdir())
    except OSError:
        return None


def _dockerd_runs() -> bool:
    """v0.32.0 — a process named ``dockerd`` runs (measured: Docker 29.1.3's
    daemon; none once the docker service and socket are stopped)."""
    return _process_runs("dockerd")


def _process_runs(name: str) -> bool:
    """A process whose ``comm`` is *name* runs."""
    try:
        pids = [d for d in _PROC.iterdir() if d.name.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            if (pid / "comm").read_text(errors="replace").strip() == name:
                return True
        except OSError:
            continue
    return False


def _wireguard_interface() -> bool:
    """v0.32.0 — a WireGuard interface exists (``_wireguard_ifaces``)."""
    return bool(_wireguard_ifaces())


def _wireguard_ifaces() -> "list[str]":
    """v0.32.0 — the interfaces the kernel calls WireGuard devices: their
    ``uevent`` says ``DEVTYPE=wireguard`` (measured, wg-quick on Ubuntu 26.04;
    a tun device has no DEVTYPE, and both have type 65534). v0.33.0 — by name."""
    try:
        ifaces = sorted(_SYS_NET.iterdir())
    except OSError:
        return []
    found = []
    for iface in ifaces:
        try:
            if "DEVTYPE=wireguard" in (iface / "uevent").read_text(errors="replace").split():
                found.append(iface.name)
        except OSError:
            continue
    return found


#: v0.33.0 — the interfaces each routing mechanism creates, as prefixes (an
#: iptables ``-i docker+`` is a prefix too). Docker: docker0 and its br-<id>
#: networks; libvirt: virbrN; the Kubernetes CNIs (names from their
#: projects, not all measured: they only excuse, they never charge).
_DOCKER_IFACES = ("docker", "br-")
_LIBVIRT_IFACES = ("virbr",)
_CNI_IFACES = ("cali", "flannel", "cni", "vxlan.calico", "cilium", "kube-bridge", "weave", "tunl")
#: v0.33.0 — the comment MicroK8s writes on its FORWARD rules (measured on
#: MicroK8s 1.35.6, Ubuntu Server 26.04: two rules, -s/-d of the pod network).
_MICROK8S_COMMENT = "generated for MicroK8s pods"
_IFACE_ARG = re.compile(r"(!\s+)?-[io]\s+(\S+)")


def _active_ifaces(snapshot: "FirewallStackSnapshot") -> "tuple[str, ...]":
    """Interface prefixes of the routing mechanisms that run now."""
    out: "list[str]" = []
    if snapshot.docker_present:
        out += _DOCKER_IFACES
    out += snapshot.wireguard_ifaces
    if snapshot.libvirt_present:
        out += _LIBVIRT_IFACES
    if snapshot.kubernetes_running:
        out += _CNI_IFACES
    return tuple(out)


def _owned(name: str, active: "tuple[str, ...]") -> bool:
    """Whether the interface *name* of a rule belongs to a running mechanism
    (*active*: prefixes, or WireGuard's exact names). iptables reads a
    trailing ``+`` as every interface starting with what precedes it."""
    if name.endswith("+"):
        stem = name[:-1]
        return any(a.startswith(stem) or stem.startswith(a) for a in active)
    return name.startswith(active)


def _named_ifaces(rule: str) -> "list[str]":
    """The interfaces a FORWARD rule names positively (``-i``/``-o``, not
    negated), ``lo`` aside."""
    return [m.group(2) for m in _IFACE_ARG.finditer(rule)
            if not m.group(1) and m.group(2) != "lo"]


def _exists(name: str, ifaces: "list[str]") -> bool:
    """Whether the interface *name* of a rule exists (``x+``: one starting with x)."""
    if name.endswith("+"):
        return any(i.startswith(name[:-1]) for i in ifaces)
    return name in ifaces


def _forward_orphans(snapshot: "FirewallStackSnapshot") -> "list[str]":
    """v0.33.0 — the FORWARD ACCEPT rules no running mechanism can own, while
    something routes: one that names an interface that does not exist and
    that no running mechanism owns — a stale rule (measured, fwd0320
    case 6: ``-i bobwg0`` with WireGuard down and Docker up, excused by
    0.32.0); one that carries MicroK8s' comment while MicroK8s does not run.

    After review: a rule naming only existing interfaces BOB cannot attribute
    (LXD's lxdbr0, a network plugin BOB does not list) is unknown, not proof of
    a bypass — excused, as a rule naming no interface is. So is every rule
    when the interfaces could not be listed."""
    active = _active_ifaces(snapshot)
    ifaces = snapshot.host_ifaces
    orphans = []
    for rule in snapshot.forward_accepts_s:
        named = _named_ifaces(rule)
        if named:
            # After review: each interface is judged on its own — one a running
            # mechanism owns does not excuse another that does not exist
            # (`-i unknown0 -o docker0` would bypass UFW once unknown0 exists).
            if ifaces is not None and any(not _exists(n, ifaces) and not _owned(n, active) for n in named):
                orphans.append(rule)
            continue
        if _MICROK8S_COMMENT in rule and not snapshot.microk8s_running:
            orphans.append(rule)
    return orphans


def _routing_daemon(snapshot: "FirewallStackSnapshot") -> bool:
    """Something that legitimately routes and writes FORWARD rules."""
    return (snapshot.docker_present or snapshot.wireguard_present
            or snapshot.libvirt_present or snapshot.kubernetes_running)


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_firewall_stack(snapshot: FirewallStackSnapshot, t: TranslationFunc | None = None,
                         ufw_active: bool = True) -> CheckResult:
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
    # Rules in INPUT that are not jumping to a ufw-* chain bypass UFW.
    # v0.26.0: only while UFW is active — with UFW off there is nothing to
    # bypass: those rules are the host's ruleset, which the iptables/nftables
    # section judges (an accept-all costs 3 there, so this −2 was counted twice
    # for one rule; measured on k3s). And only rules that can let a new
    # connection in: a port rule opened 8099 past an active ufw, a mark rule
    # opened nothing, -i lo reaches only the loopback (network namespace, ufw 0.36).
    for rule in (snapshot.input_raw_accepts if ufw_active else []):
        reach = _accept_reach(rule, snapshot.mark_setters + _input_setters_above(snapshot.input_rules, rule))
        if reach == "loopback":
            continue
        if reach == "conditional":
            result.info(
                key="firewall_drivers.iptables_accept_conditional",
                message=_t("firewall_drivers.iptables_accept_conditional", rule=rule),
                template_vars={"rule": rule},
            )
            continue
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
    # v0.26.0: like INPUT, only beside an active UFW — measured on Alpine with
    # awall, its own FORWARD rules cost 1 each as "bypassing UFW".
    if snapshot.forward_raw_accepts and ufw_active:
        if _routing_daemon(snapshot):
            result.info(
                message=_t("firewall_drivers.forward_routing_ok"),
                key="firewall_drivers.forward_routing_ok",
            )
            # v0.33.0 — but not the rules no running mechanism can own.
            for rule in _forward_orphans(snapshot):
                result.warn_with_deduction(
                    key="firewall_drivers.iptables_forward_bypass",
                    message=_t("firewall_drivers.iptables_forward_stale" if _named_ifaces(rule)
                               else "firewall_drivers.iptables_forward_orphan", rule=rule),
                    points=1,
                    nature="action",
                )
                found_issue = True
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
    # v0.26.0: only beside an active UFW; with UFW off the nftables ruleset is
    # the firewall, judged by the iptables/nftables section.
    if snapshot.nftables_active and ufw_active:
        result.warn_with_deduction(
            key="firewall_drivers.nftables_parallel",
            message=_t("firewall_drivers.nftables_parallel"),
            points=1,
            nature="action",
        )
        found_issue = True

    # --- IP forwarding ---
    if snapshot.ip_forward:
        # v0.34.0 — WireGuard alone excuses forwarding, but a client routes
        # for no one: when it is the only mechanism and the kernel has
        # forwarded nothing since boot, say so (INFO, no point, no fix — a
        # counter is not a reason to switch routing off unattended).
        wireguard_only = (snapshot.wireguard_present and not snapshot.docker_present
                          and not snapshot.libvirt_present and not snapshot.kubernetes_running)
        if (wireguard_only and snapshot.forwarded_v4 == 0
                and snapshot.uptime_s is not None):
            result.info(
                message=_t("firewall_drivers.ip_forward_wireguard_idle",
                           ifaces=", ".join(snapshot.wireguard_ifaces) or "wg",
                           since=_since_boot(snapshot.uptime_s, _t)),
                detail=_t("firewall_drivers.ip_forward_wireguard_idle_detail"),
                key="firewall_drivers.ip_forward_wireguard_idle",
            )
        elif _routing_daemon(snapshot):
            result.ok(message=_t("firewall_drivers.ip_forward_ok"), key="firewall_drivers.ip_forward_ok")
        else:
            result.warn_with_deduction(
                key="firewall_drivers.ip_forward_enabled",
                message=_t("firewall_drivers.ip_forward_enabled"),
                points=1,
                **sysctl_fix("net.ipv4.ip_forward=0"),
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
    elif not found_issue and not (snapshot.forward_raw_accepts and ufw_active):
        result.ok(message=_t("firewall_drivers.no_issues"), key="firewall_drivers.no_issues")

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_raw_accepts_s(iptables_s_output: str) -> list[str]:
    """The ``-A INPUT … -j ACCEPT`` lines of ``iptables -S INPUT``."""
    return [ln.strip() for ln in iptables_s_output.splitlines()
            if ln.startswith("-A ") and re.search(r"(^|\s)-j ACCEPT(\s|$)", ln)]


#: What a raw INPUT ACCEPT rule can let in on its own (v0.26.0), measured with
#: ufw 0.36 active in a network namespace: a ``--dport 8099`` rule opened 8099
#: from outside; a ``-m mark`` rule opened nothing (it accepts what another
#: rule marked — kube-router's network-policy rule is one); ``-i lo`` admits
#: only the loopback.
_LOOPBACK = re.compile(r"(^|\s)-i lo(\s|$)")
_MARK_ONLY = re.compile(r"^-A \S+(?: -m comment --comment (?:\"[^\"]*\"|\S+))?"
                        r" -m mark --mark \S+(?: -m comment --comment (?:\"[^\"]*\"|\S+))? -j ACCEPT$")
_STATE_ONLY = re.compile(r"^-A \S+(?: -m comment --comment (?:\"[^\"]*\"|\S+))?"
                         r" -m (?:conntrack --ctstate|state --state) (?:RELATED|ESTABLISHED)(?:,(?:RELATED|ESTABLISHED))?"
                         r"(?: -m comment --comment (?:\"[^\"]*\"|\S+))? -j ACCEPT$")


_MARK_MATCH = re.compile(r" -m mark --mark (0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?")
_MARK_SET = re.compile(r"-j (?:MARK|CONNMARK) --set-x?mark (0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?")


_JUMP = re.compile(r"\s-[jg]\s+(\S+)")
_CONNMARK_COPY = re.compile(r"-j CONNMARK --(restore|save)-mark(?:\s+--nfmask\s+(\S+))?(?:\s+--ctmask\s+(\S+))?")
#: v0.26.0, after review — HMARK sets offset + (hash % mod); measured with ufw
#: 0.36 active: `-j HMARK --hmark-mod 1 --hmark-offset 0x20000` in mangle
#: PREROUTING opened 8099 through a mark rule BOB called conditional.
_HMARK = re.compile(r"-j HMARK\b.*?--hmark-mod\s+(\d+).*?--hmark-offset\s+(\S+)")
#: TPROXY sets the mark as MARK --set-xmark does (``--tproxy-mark value/mask``).
_TPROXY_MARK = re.compile(r"-j TPROXY\b.*?--tproxy-mark\s+(0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?")
#: An HMARK spread this wide cannot be listed: the mark it sets is not established.
_HMARK_MAX_MOD = 256


def _is_mark_op(rule: str) -> bool:
    return bool(_MARK_SET.search(rule) or _CONNMARK_COPY.search(rule)
                or _HMARK.search(rule) or _TPROXY_MARK.search(rule))


def _mark_setters(*outputs: str, extra: "dict[str, list[str]] | None" = None) -> list[str]:
    """The rules of *outputs* (``iptables -t raw|mangle|nat -S``, in that
    order) that touch a mark on the inbound path, in the order a new inbound
    packet meets them: every table's PREROUTING, then every table's INPUT,
    each chain's jumps followed inline (v0.26.0, measured with ufw 0.36 active:
    a MARK in mangle OUTPUT or POSTROUTING left 8099 closed, in a user chain
    jumped from mangle PREROUTING it opened 8099, jumped from OUTPUT only it
    did not)."""
    tables = []
    for out in outputs:
        chains: dict[str, list] = {}
        for ln in out.splitlines():
            if ln.startswith("-A "):
                chains.setdefault(ln.split()[1], []).append(ln.strip())
        tables.append(chains)

    def expand(chains, chain, seen):
        if chain in seen:
            return []
        seen = seen | {chain}
        ordered = []
        for rule in chains.get(chain, []):
            ordered.append(rule)
            m = _JUMP.search(rule)
            if m and m.group(1) in chains:
                ordered += expand(chains, m.group(1), seen)
        return ordered

    sequence = []
    for hook in ("PREROUTING", "INPUT"):
        sequence += [r for chains in tables for r in expand(chains, hook, frozenset())]
        sequence += (extra or {}).get(hook, [])      # v0.27.0: native nftables, same hook
    return [r for r in sequence if _is_mark_op(r)]


#: nft's named priorities (nft(8)).
_NFT_PRIORITY = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}
_NUM = r"(0x[0-9a-fA-F]+|\d+)"
#: A mark BOB cannot follow (a map, jhash, numgen…): HMARK past _HMARK_MAX_MOD,
#: which _mark_reachable reads as "not established", never "conditional".
_MARK_UNKNOWN = "-j HMARK --hmark-mod 65536 --hmark-offset 0x0"


def _nft_mark_statement(rule: str) -> "str | None":
    """One native nft rule's mark operation, in the iptables form
    :func:`_mark_reachable` follows — or None when it sets no mark (v0.27.0)."""
    full = 0xFFFFFFFF
    # nft prints the operators as | and & (measured: "meta mark set meta mark
    # | 0x00020000" for an input of "mark or 0x20000"); both spellings read.
    m = re.search(rf"\bmeta mark set (?:meta )?mark (?:or|\|) {_NUM}\b", rule)
    if m:
        v = int(m.group(1), 0)
        return f"-j MARK --set-xmark {v:#x}/{v:#x}"
    m = re.search(rf"\bmeta mark set (?:meta )?mark (?:and|&) {_NUM}\b", rule)
    if m:
        return f"-j MARK --set-xmark 0x0/{~int(m.group(1), 0) & full:#x}"
    if re.search(r"\bmeta mark set ct mark\b", rule):
        return "-j CONNMARK --restore-mark"
    if re.search(r"\bct mark set (?:meta )?mark\b(?! (?:or|and|\||&))", rule):
        return "-j CONNMARK --save-mark"
    m = re.search(rf"\bct mark set ct mark (?:or|\|) {_NUM}\b", rule)
    if m:
        v = int(m.group(1), 0)
        return f"-j CONNMARK --set-xmark {v:#x}/{v:#x}"
    m = re.search(rf"\bmeta mark set {_NUM}(?:\s|$)", rule)
    if m:
        return f"-j MARK --set-xmark {int(m.group(1), 0):#x}/{full:#x}"
    m = re.search(rf"\bct mark set {_NUM}(?:\s|$)", rule)
    if m:
        return f"-j CONNMARK --set-xmark {int(m.group(1), 0):#x}/{full:#x}"
    if re.search(r"\b(?:meta |ct )?mark set\b", rule):
        return _MARK_UNKNOWN
    return None


#: v0.28.0 — a jump or goto to a regular chain, also inside a verdict map
#: (``tcp dport vmap { 8099 : jump mk }``).
_NFT_CHAIN_CALL = re.compile(r"\b(?:jump|goto)\s+([\w.-]+)")


def _nft_mark_setters(ruleset: str) -> "dict[str, list[str]]":
    """The mark operations of native nftables chains on the inbound path, by
    hook: every prerouting base chain, and input ones before the filter
    (v0.27.0). Tables iptables-nft keeps (ip/ip6 raw, mangle, nat, filter
    with its upper-case chains) are already read through iptables -S.

    v0.28.0 — a jump or goto from such a chain to a regular chain of the same
    table is followed inline, nested ones too (measured in a network
    namespace with the INPUT mark-accept rule: a mark set in a chain reached
    by jump, goto, two jumps or a vmap jump from prerouting opened 8099, which
    BOB called conditional; the same chain never jumped to, or jumped to from
    an output chain only, left it closed)."""
    out: "dict[str, list[str]]" = {"PREROUTING": [], "INPUT": []}
    tables: "dict[tuple, dict[str, list[str]]]" = {}
    hooks: "list[tuple[tuple, str, str]]" = []     # (table, chain, hook), in order
    table = chain = None
    for line in ruleset.splitlines():
        text = line.strip()
        m = re.match(r"table\s+(\w+)\s+(\S+)\s*\{", text)
        if m:
            table, chain = (m.group(1), m.group(2)), None
            tables.setdefault(table, {})
            continue
        m = re.match(r"chain\s+(\S+)\s*\{", text)
        if m and table:
            chain = m.group(1)
            tables[table].setdefault(chain, [])
            continue
        if text == "}":
            # The end of a chain. Outside one it may close a set, a map or a
            # flowtable as well as the table: the table changes at the next
            # "table" line (v0.28.0, measured: a named set declared before
            # the prerouting chain reset the table here, the chain was never
            # read, and 8099, opened by its mark, read "conditional").
            chain = None
            continue
        if chain is None or table is None:
            continue
        hm = re.search(r"\bhook\s+(\w+)\s+priority\s+(\S+?);", text)
        if hm:
            prio = hm.group(2)
            value = _NFT_PRIORITY.get(prio.split("+")[0].split("-")[0], None) if not re.fullmatch(r"-?\d+", prio) else int(prio)
            managed = table[0] in ("ip", "ip6") and table[1] in ("raw", "mangle", "nat", "filter", "security") \
                and chain.isupper()
            if managed:
                pass
            elif hm.group(1) == "prerouting":
                hooks.append((table, chain, "PREROUTING"))
            elif hm.group(1) == "input" and (value is None or value <= 0):
                # At the filter's own priority the order against iptables'
                # INPUT is not established: such a mark reads "not established".
                hooks.append((table, chain, "INPUT" if value is None or value < 0 else "INPUT_UNORDERED"))
            continue
        if text:
            tables[table][chain].append(text)

    def expand(chains: "dict[str, list[str]]", name: str, seen: frozenset) -> "list[str]":
        ordered: "list[str]" = []
        for rule in chains.get(name, []):
            ordered.append(rule)
            for target in _NFT_CHAIN_CALL.findall(rule):
                if target in chains and target not in seen:
                    ordered += expand(chains, target, seen | {target})
        return ordered

    for tbl, name, hook in dict.fromkeys(hooks):      # a chain listed twice is read once
        for rule in expand(tables[tbl], name, frozenset({name})):
            op = _nft_mark_statement(rule)
            if op:
                out["INPUT" if hook == "INPUT_UNORDERED" else hook].append(
                    _MARK_UNKNOWN if hook == "INPUT_UNORDERED" else op)
    return out


def _input_path(filter_s: str) -> list[str]:
    """The filter table's INPUT rules in the order a packet meets them, each
    jump to a user chain followed inline (v0.26.0, measured with ufw 0.36
    active: a MARK in a user chain jumped from INPUT above the mark rule
    opened 8099, nested one chain deeper too; jumped below it, nothing)."""
    chains: dict[str, list] = {}
    for ln in filter_s.splitlines():
        if ln.startswith("-A "):
            chains.setdefault(ln.split()[1], []).append(ln.strip())

    def expand(chain, seen):
        ordered = []
        for rule in chains.get(chain, []):
            ordered.append(rule)
            m = _JUMP.search(rule)
            if m and m.group(1) in chains and m.group(1) not in seen:
                ordered += expand(m.group(1), seen | {m.group(1)})
        return ordered

    return expand("INPUT", frozenset({"INPUT"}))


def _input_setters_above(input_rules: list, rule: str) -> list:
    """The mark-touching rules of filter INPUT above *rule* (v0.26.0, measured
    with ufw 0.36 active: a MARK above the mark rule opened 8099, the same MARK
    below it did not)."""
    above = input_rules[:input_rules.index(rule)] if rule in input_rules else []
    return [ln for ln in above if _is_mark_op(ln)]


def _num(text: "str | None", default: int = 0xFFFFFFFF) -> int:
    return int(text, 0) if text else default


def _mark_reachable(rule: str, setters) -> bool:
    """Whether a new packet can carry the mark *rule* accepts, following
    *setters* in order: a MARK sets the packet's mark, a CONNMARK set the
    connection's, and only a restore copies the connection's bits to the
    packet, as far as its masks let it (v0.26.0, measured with ufw 0.36
    active: CONNMARK --set-xmark alone, or restored with masks that miss the
    bits, or restored before it is set, left 8099 closed; set then restored,
    8099 opened). Values and masks compared, so kube-proxy's 0x4000 does not
    feed a match on 0x20000. Unmarked packets carry 0."""
    m = _MARK_MATCH.search(rule)
    if not m:
        return True
    value, mask = int(m.group(1), 0), _num(m.group(2))
    nf, ct = {0}, {0}
    for setter in setters:
        copy = _CONNMARK_COPY.search(setter)
        hmark = _HMARK.search(setter)
        tproxy = _TPROXY_MARK.search(setter)
        if hmark:
            mod, offset = int(hmark.group(1)), int(hmark.group(2), 0)
            if mod > _HMARK_MAX_MOD:
                return True       # not established: never called conditional
            nf |= {offset + i for i in range(max(mod, 1))}
        elif tproxy:
            v, mk = int(tproxy.group(1), 0), _num(tproxy.group(2))
            nf |= {(x & ~mk) ^ v for x in nf}
        elif copy:
            nfmask, ctmask = _num(copy.group(2)), _num(copy.group(3))
            if copy.group(1) == "restore":
                nf |= {(n & ~nfmask) ^ (c & ctmask) for n in nf for c in ct}
            else:
                ct |= {(c & ~ctmask) ^ (n & nfmask) for c in ct for n in nf}
        else:
            s = _MARK_SET.search(setter)
            v, mk = int(s.group(1), 0), _num(s.group(2))
            target = ct if "-j CONNMARK" in setter else nf
            target |= {(x & ~mk) ^ v for x in target}
        if len(nf) > 256 or len(ct) > 256:
            return True           # too many paths to follow: not established either way
    return any((n & mask) == (value & mask) for n in nf)


def _accept_reach(rule: str, mark_setters=()) -> str:
    """``"loopback"``, ``"conditional"`` (mark or established state only — no
    new connection on its own) or ``"admits"``. A mark rule admits when a new
    packet can carry that mark (:func:`_mark_reachable`)."""
    if _LOOPBACK.search(rule):
        return "loopback"
    if _MARK_ONLY.match(rule):
        return "admits" if _mark_reachable(rule, mark_setters) else "conditional"
    if _STATE_ONLY.match(rule):
        return "conditional"
    return "admits"


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
    - The "firewalld" table        → firewalld's own nftables backend (Fedora,
      RHEL, openSUSE). It IS the firewall, not a rogue ruleset beside one;
      flagging it framed a firewalld host as "nftables in parallel with UFW"
      (measured on Fedora 44). firewalld itself is credited by the firewall
      checks via FirewalldStatus.
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
            if (not table_name.startswith("ufw")
                    and table_name != "firewalld"
                    and table_name not in _IPTABLES_COMPAT):
                return True
    return False


_PROC_SNMP = Path("/proc/net/snmp")
_PROC_UPTIME = Path("/proc/uptime")


def _forwarded_v4() -> "int | None":
    """v0.34.0 — ``Ip: ForwDatagrams`` of /proc/net/snmp (a header line
    names the fields, the next line holds the values); None when unread."""
    try:
        lines = [ln.split() for ln in _PROC_SNMP.read_text(encoding="ascii", errors="ignore").splitlines()
                 if ln.startswith("Ip:")]
        names, values = lines[0], lines[1]
        return int(values[names.index("ForwDatagrams")])
    except (OSError, IndexError, ValueError):
        return None


def _uptime_s() -> "float | None":
    """Seconds since boot (/proc/uptime); None when unread."""
    try:
        return float(_PROC_UPTIME.read_text(encoding="ascii", errors="ignore").split()[0])
    except (OSError, IndexError, ValueError):
        return None


def _since_boot(seconds: float, _t) -> str:
    """``3 day(s)`` or ``5 h`` — how long the counter has been counting."""
    days = int(seconds // 86400)
    if days:
        return _t("firewall_drivers.since_boot_days", days=days)
    return _t("firewall_drivers.since_boot_hours", hours=max(1, int(seconds // 3600)))


def _read_ip_forward() -> bool:
    """Return True if IPv4 forwarding is enabled in the kernel."""
    try:
        val = Path("/proc/sys/net/ipv4/ip_forward").read_text(
            encoding="ascii", errors="ignore"
        ).strip()
        return val == "1"
    except OSError:
        return False
