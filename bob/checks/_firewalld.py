"""firewalld detection, shared by the firewall checks.

firewalld is the default firewall front-end on the RPM family (Fedora, RHEL,
CentOS, Rocky, Alma) and on openSUSE. It manages nftables (a `table inet
firewalld`) and works by *zones*: the base chain policy stays ACCEPT while the
zone chains jump to an explicit drop/reject at the end. A firewall auditor that
reads the raw base policy therefore sees "INPUT ACCEPT" and calls a properly
firewalled host wide-open — the exact false positive this module exists to stop.

Before v0.20.2 BOB had no firewalld awareness at all (measured on a real Fedora
44 server): it alerted "UFW not installed", read the base nft policy as "wide
open", and framed firewalld's own nft table as "nftables in parallel with UFW".
This snapshot lets the three firewall checks recognise firewalld and credit it.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass, field

from pathlib import Path

from bob.checks._run import _command_exists, path_exists, run_result

# A rich rule that grants access carries an explicit ``accept`` verb; ``reject``
# and ``drop`` rules deny and must not be shown as things the zone "allows".
_RICH_PORT = re.compile(r'port port="?(?P<port>\d+(?:-\d+)?)"?\s+protocol="?(?P<proto>\w+)"?')
_RICH_SERVICE = re.compile(r'service name="?(?P<name>[\w.+-]+)"?')
_TARGET_LINE = re.compile(r"^\s*target:\s*(\S+)", re.MULTILINE)
_INGRESS_LINE = re.compile(r"^\s*ingress-priority:\s*(-?\d+)\s*$", re.MULTILINE)

#: v0.24.1 — what a zone does with a packet no rule matched, in the words the
#: rest of BOB uses for an inbound default policy. ``default`` rejects (and lets
#: ICMP through); ``ACCEPT`` lets everything in — the ``trusted`` zone's target.
_TARGET_POLICY = {"default": "reject", "%%REJECT%%": "reject", "REJECT": "reject",
                  "DROP": "deny", "ACCEPT": "allow"}

#: v0.24.3 — what turns a rich rule into one that matches only some packets.
#: A rule carrying none of these matches every packet that reaches it (a
#: *catch-all*): firewalld's own ``libvirt`` and ``nm-shared`` zones pair target
#: ACCEPT with ``rule priority="32767" reject`` — ACCEPT then only concerns
#: forwarded traffic. Measured on Fedora 44 with enp3s0 in nm-shared: port 22
#: (listed) answers, 9090 does not. ``family`` is not among them: it limits
#: the rule to one address family, where it still matches every packet —
#: measured on Fedora 44, ``rule family="ipv4" priority="-100" accept`` opened
#: 8080 over IPv4 through FedoraServer (target default) while BOB said reject.
_RICH_SELECTORS = frozenset({
    "source", "destination", "service", "port", "protocol",
    "icmp-block", "icmp-type", "icmp-block-inversion", "masquerade",
    "forward-port", "source-port", "tcp-mss-clamp",
})
#: Words that log, audit or rate-limit without selecting packets. Measured on
#: Fedora 44: ``rule priority="100" log prefix="…" level="info" accept``,
#: ``… audit accept`` and ``… accept limit value="10/m"`` each made 8080
#: reachable through a filtering zone — they are catch-all accepts.
_RICH_QUALIFIERS = frozenset({
    "log", "nflog", "audit", "prefix", "level", "group", "queue-size",
    "limit", "value", "burst", "type",
})
_CATCH_ALL_POLICY = {"accept": "allow", "reject": "reject", "drop": "deny"}
#: v0.24.3 — firewalld judges each address family on its own.
FAMILIES = ("ipv4", "ipv6")
_OPENNESS = ("allow", "unknown", "reject", "deny")


def most_open(policies) -> str:
    """The most open of *policies* ("allow" before "unknown" before "reject"
    before "deny"), or "unknown" when there is none."""
    policies = set(policies)
    return next((p for p in _OPENNESS if p in policies), "unknown")


def _catch_all(rule: str, family: str) -> "tuple[int, str] | None":
    """``(priority, verdict)`` when *rule* matches every packet of *family* and
    decides it; None when it selects packets, belongs to the other family or
    decides nothing (``mark``). A word BOB does not know yields the verdict
    "unknown" — never guessed either way."""
    try:
        tokens = shlex.split(rule)
    except ValueError:
        return None
    if not tokens or tokens[0] != "rule":
        return None
    prio, action, limited, unknown = 0, None, False, False
    for tok in tokens[1:]:
        word, _, val = tok.partition("=")
        if word in _RICH_SELECTORS:
            return None
        if word == "family":
            if val != family:
                return None
        elif word == "priority":
            try:
                prio = int(val)
            except ValueError:
                return None
        elif word in _CATCH_ALL_POLICY:
            action = word
        elif word == "limit" and action is not None:
            limited = True  # the action's own rate limit
        elif word not in _RICH_QUALIFIERS:
            unknown = True
    if action is None:
        return None
    if limited and action != "accept":
        # A rate-limited reject or drop applies only while its limit matches;
        # past it, evaluation goes on, so it cannot show the port closed. A
        # rate-limited accept still lets traffic in (measured: 8080 answered).
        return None
    return prio, "unknown" if unknown else _CATCH_ALL_POLICY[action]


def _rules_decide(rich_rules, family: str) -> "str | None":
    """The verdict of the catch-all rule of *family* with the lowest priority
    number, or None when no rule matches every packet of that family."""
    found = [c for c in (_catch_all(r, family) for r in rich_rules) if c is not None]
    if not found:
        return None
    first = min(prio for prio, _ in found)
    verdicts = {v for prio, v in found if prio == first}
    # firewalld does not define the order of rules sharing a priority, so
    # opposite catch-all actions there leave the outcome unknown.
    return verdicts.pop() if len(verdicts) == 1 else "unknown"


def open_rules(rich_rules) -> "tuple[str, ...]":
    """The catch-all rules that accept, in either family — what a fix must
    remove."""
    return tuple(r for r in rich_rules
                 if any((_catch_all(r, f) or (0, ""))[1] == "allow" for f in FAMILIES))


#: v0.26.0 — a rich rule whose action refuses: ``… reject``, ``… reject
#: type="…"``, ``… drop``.
_REFUSING = re.compile(r'\s(?:reject(?:\s+type="[^"]*")?|drop)\s*$')


def refusing_rules(rich_rules) -> tuple:
    """The rich rules of a zone that drop or reject what they match (v0.26.0).

    Measured on Debian 13 (firewalld 2.3.1): a zone at target ACCEPT bound to
    192.168.1.10/32 with ``rule family="ipv4" port port="8099" protocol="tcp"
    reject`` refused 8099 to that host and let 8097 in — BOB said "every port
    is open to those addresses"."""
    return tuple(r for r in rich_rules if _REFUSING.search(r.strip()))


def zone_policy(target: str, rich_rules: "list[str]") -> str:
    """A zone's effective inbound default on its own: its target, unless a
    catch-all rich rule decides first — the most open of the two families."""
    return most_open(_rules_decide(rich_rules, f) or _TARGET_POLICY.get(target, "unknown")
                     for f in FAMILIES)


@dataclass(frozen=True)
class Verdict:
    """What happens to an inbound packet no service or port matched, and what
    decided it (v0.24.3) — the fix acts on that, not on a guess."""
    policy:  str                 # "allow" / "reject" / "deny" / "unknown"
    holder:  object = None       # the ZoneBinding or HostPolicy that decided
    by_rule: bool = False        # a catch-all rich rule, not the target


@dataclass(frozen=True)
class ZoneBinding:
    """An active zone and the interfaces it filters (v0.24.3).

    Zones holding a physical interface are judged as the host's inbound
    policy, and so is a zone whose sources cover a whole address family. A
    zone bound by narrower *sources* applies to those addresses only. Which
    zone classifies a packet follows ``ingress-priority`` (lower first), and at
    equal priority a source zone comes before an interface's — measured on
    Fedora 44: with 192.168.1.10/32 in ``trusted`` (both priorities 0), 8080
    answered 192.168.1.10, with 192.168.1.250/32 it did not; with 0.0.0.0/0 in
    ``trusted`` at +100 and FedoraServer at -100 or 0, 8080 was refused. A zone
    holding only virtual interfaces (docker0, virbr0) carries container or VM
    traffic.
    """
    name:       str
    interfaces: tuple = ()
    physical:   tuple = ()
    target:     str = ""
    rich_rules: tuple = ()
    sources:    tuple = ()
    #: ``ingress-priority:`` of ``--list-all``; a firewalld that lists none
    #: predates the setting and classifies every zone equally (0).
    ingress_priority: int = 0

    @property
    def policy(self) -> str:
        return zone_policy(self.target, list(self.rich_rules))

    @property
    def all_sources(self) -> tuple:
        """The sources of each address family they cover whole, together:
        ``0.0.0.0/0`` alone, or ``0.0.0.0/1`` + ``128.0.0.0/1`` (measured on
        Fedora 44: the pair opened 8080 to every IPv4 client, either half
        alone only to its half). MAC and ipset sources are not addresses BOB
        can add up and never count."""
        by_family: dict[int, list] = {}
        for src in self.sources:
            try:
                net = ipaddress.ip_network(src, strict=False)
            except ValueError:
                continue
            by_family.setdefault(net.version, []).append((src, net))
        whole = []
        for nets in by_family.values():
            if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(n for _, n in nets)):
                whole.extend(src for src, _ in nets)
        return tuple(whole)

    @property
    def covered_families(self) -> frozenset:
        """"ipv4" / "ipv6" for each family :attr:`all_sources` covers."""
        return frozenset("ipv4" if ipaddress.ip_network(s, strict=False).version == 4 else "ipv6"
                         for s in self.all_sources)


#: v0.26.0 — address ranges that are not publicly routable (IANA
#: special-purpose registries, RFC 6890 and successors): what "public" excludes
#: when BOB says how much of the public space a set of sources reaches.
#: An approximation: the main ranges, not the whole IANA registry (IPv6:
#: 2001::/23 and other special-purpose prefixes inside 2000::/3 count as public).
_NOT_PUBLIC = {
    4: tuple(ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")),
    # IPv6: only global unicast (2000::/3) is public; the documentation range is not.
    # v0.26.0: the complement of 2000::/3 — "::/1" held 2000::/3 itself, and
    # e000::/3 was missing, so the public space read as e000::/3.
    # 3fff::/20 is documentation too (RFC 9637).
    6: tuple(ipaddress.ip_network(n) for n in ("::/3", "4000::/2", "8000::/1", "2001:db8::/32",
                                                "3fff::/20")),
}


def _overlap(a, b) -> int:
    """Addresses two CIDR networks share (one contains the other, or none)."""
    if a.version != b.version:
        return 0
    if a.subnet_of(b):
        return a.num_addresses
    if b.subnet_of(a):
        return b.num_addresses
    return 0


def _subtract(nets, cut) -> list:
    """*nets* without the addresses of *cut* (CIDR networks are nested or disjoint)."""
    out = list(nets)
    for c in cut:
        nxt = []
        for n in out:
            if n.version != c.version or not n.overlaps(c):
                nxt.append(n)
            elif c.subnet_of(n) and c != n:
                nxt.extend(n.address_exclude(c))
            # n inside c: taken whole
        out = nxt
    return out


#: v0.26.0 — decided after review: open source zones that take at least this
#: share of a family's public addresses open the host to nearly all of the
#: internet, and keep the ALERT; a /24 kept out of two pooled halves (measured
#: on Debian 13) made the domain rise from 7/10 to 10/10.
NEAR_ALL_PUBLIC = 99


def _nearly_all(public: int, public_space: int) -> bool:
    """Whether *public* reaches :data:`NEAR_ALL_PUBLIC` % of *public_space*."""
    return public * 100 >= public_space * NEAR_ALL_PUBLIC


def _public_share(nets, version) -> "tuple[int, int]":
    """(public addresses *nets* hold, public addresses of the family)."""
    space = 2 ** (32 if version == 4 else 128)
    not_public = list(ipaddress.collapse_addresses(_NOT_PUBLIC[version]))
    public_space = space - sum(p.num_addresses for p in not_public)
    union = list(ipaddress.collapse_addresses(nets))
    total = sum(n.num_addresses for n in union)
    return total - sum(_overlap(u, p) for u in union for p in not_public), public_space


def source_dispatch(zones, open_names) -> "dict[int, dict]":
    """What each address family's source zones take, in firewalld's order
    (v0.26.0).

    Measured on Debian 13 (firewalld 2.3.1), zones bobA (0.0.0.0/1) and bobB
    (128.0.0.0/1) with target ACCEPT, and a DROP zone keeping ssh bound to the
    probing host's /32: between source zones, the lowest ``ingress-priority``
    classifies a packet first, then the zone name; the first source that
    matches wins, not the narrowest. Named ``aaacarve`` (or ``zzzcarve`` at
    priority -10) the DROP zone closed 8099 to that host; named ``zzzcarve``
    (or ``aaacarve`` at +10) it did not. 0.24.3 counted the declared sources and
    alerted "every client" in both cases.

    Per IP version: ``open`` — the networks *open_names* zones really take;
    ``zones`` — each such zone with its sources; ``taken`` — the sources of
    other zones classified first that the open zones' sources would hold.
    MAC and ipset sources are not addresses and take nothing here.
    """
    ordered = sorted(zones, key=lambda z: (z.ingress_priority, z.name))
    out: dict[int, dict] = {}
    claimed: dict[int, list] = {}
    pending: dict[int, list] = {}
    for zone in ordered:
        for src in zone.sources:
            try:
                net = ipaddress.ip_network(src, strict=False)
            except ValueError:
                continue
            v = net.version
            entry = out.setdefault(v, {"open": [], "zones": {}, "taken": []})
            if zone.name in open_names:
                got = _subtract([net], claimed.get(v, []))
                if got:
                    entry["open"].extend(got)
                    entry["zones"].setdefault(zone.name, (zone, []))[1].append(src)
                for other, osrc, onet in pending.get(v, []):
                    if onet.overlaps(net) and (other.name, osrc) not in entry["taken"]:
                        entry["taken"].append((other.name, osrc))
            else:
                pending.setdefault(v, []).append((zone, src, net))
            claimed.setdefault(v, []).append(net)
    return out


def source_coverage(zones, closed=()) -> "list[tuple[str, tuple, float, float]]":
    """``(family, zone names, share of the family's space, share of its public
    space)`` for each family two or more open *zones* reach together, short of
    every public address (v0.26.0) — what they really take, after the sources
    of the *closed* zones firewalld classifies first.

    Measured on openSUSE Leap 16: zones bound to 0.0.0.0/2 and 64.0.0.0/3 with
    target ACCEPT each showed an INFO, and nothing said that together they let
    every packet in from 37.5 % of IPv4. Shares are exact sums of collapsed
    CIDR networks; MAC and ipset sources are not addresses and do not count.
    """
    dispatch = source_dispatch(list(zones) + list(closed), {z.name for z in zones})
    out = []
    for version, entry in sorted(dispatch.items()):
        names = tuple(sorted(entry["zones"]))
        if (len(names) < 2 and not entry["taken"]) or not entry["open"]:
            continue
        public, public_space = _public_share(entry["open"], version)
        if _nearly_all(public, public_space):
            continue  # nearly every public address: pooled_sources and its alert say it
        space = 2 ** (32 if version == 4 else 128)
        total = sum(n.num_addresses for n in ipaddress.collapse_addresses(entry["open"]))
        out.append(("ipv4" if version == 4 else "ipv6", names,
                    100.0 * total / space, 100.0 * public / public_space))
    return out


@dataclass(frozen=True)
class HostPolicy:
    """An active firewalld *policy* whose egress is the host (v0.24.3).

    Policies sit beside zones (ingress zones → egress zones), ordered by
    priority. Measured on Fedora 44 (FedoraServer, enp3s0, 8080 unlisted):
    negative-priority policies run before the zone's rules, positive ones after
    them but *before the zone's target* — a policy ACCEPT at +100 opened 8080
    under target %%REJECT%%, a policy DROP at +100 closed it under target
    ACCEPT, and a zone's catch-all reject beat a policy ACCEPT at +100.
    ``CONTINUE`` decides nothing and hands the packet on. ``priority`` is None
    when it could not be read.
    """
    name:       str
    ingress:    tuple = ()
    target:     str = ""
    rich_rules: tuple = ()
    priority:   "int | None" = -1

    def decide(self, family: str) -> "Verdict | None":
        rule = _rules_decide(self.rich_rules, family)
        if rule is not None:
            return Verdict(rule, self, by_rule=True)
        if self.target == "CONTINUE":
            return None
        return Verdict(_TARGET_POLICY.get(self.target, "unknown"), self)

    @property
    def policy(self) -> str:
        decided = [d.policy for d in (self.decide(f) for f in FAMILIES) if d is not None]
        return most_open(decided) if decided else "continue"


def _first_decision(policies, family: str) -> "Verdict | None":
    """Policies of one priority: the one that decides, "unknown" when two
    disagree (firewalld does not order them), None when all continue."""
    decided = [d for d in (p.decide(family) for p in policies) if d is not None]
    if not decided:
        return None
    if len({d.policy for d in decided}) > 1:
        return Verdict("unknown")
    return decided[0]


def zone_verdict(zone: ZoneBinding, host_policies, family: str = "ipv4") -> Verdict:
    """The verdict for a packet reaching the host through *zone*, in the order
    firewalld applies it (measured, see :class:`HostPolicy`): policies of
    negative priority, the zone's catch-all rules, policies of positive
    priority, then the zone's target."""
    applicable = [p for p in host_policies if "ANY" in p.ingress or zone.name in p.ingress]
    unordered = [p for p in applicable if p.priority is None]
    ordered = [p for p in applicable if p.priority is not None]
    if _first_decision(unordered, family) is not None:
        return Verdict("unknown")  # a deciding policy BOB cannot place
    priorities = sorted({p.priority for p in ordered})
    for prio in [x for x in priorities if x < 0]:
        decided = _first_decision([p for p in ordered if p.priority == prio], family)
        if decided is not None:
            return decided
    rule = _rules_decide(zone.rich_rules, family)
    if rule is not None:
        return Verdict(rule, zone, by_rule=True)
    for prio in [x for x in priorities if x >= 0]:
        decided = _first_decision([p for p in ordered if p.priority == prio], family)
        if decided is not None:
            return decided
    return Verdict(_TARGET_POLICY.get(zone.target, "unknown"), zone)


def strict_forward_ports(chain: "str | None" = None) -> "bool | None":
    """firewalld's ``StrictForwardPorts`` as the running firewalld applies it
    (v0.26.0, firewalld 2.3+): True when its forward chain sends DNAT'd packets
    to ``filter_FORWARD_dnat``, False when it accepts them, None when the
    chain was not read (iptables backend, an older firewalld, no nft).

    Measured on Debian 13 (firewalld 2.3.1, Docker 26.1.5): with ``no`` a port
    Docker published answered from the LAN — ``ct status dnat accept``; with
    ``yes`` it was rejected — ``ct status dnat jump filter_FORWARD_dnat``,
    ``reject with icmpx admin-prohibited``. Not the file: set to ``yes`` without
    a reload, /etc/firewalld/firewalld.conf said yes while the loaded chain
    still accepted (measured, both ways)."""
    if chain is None:
        chain = run_result("nft", "list", "chain", "inet", "firewalld", "filter_FORWARD").stdout
    if re.search(r"\bct status dnat jump filter_FORWARD_dnat\b", chain):
        return True
    if re.search(r"\bct status dnat accept\b", chain):
        return False
    return None


_FWD_PORT = re.compile(r"\bport=(\d+)(?:-(\d+))?:proto=(\w+)")
_FWD_RICH = re.compile(r'forward-port port="(\d+)(?:-(\d+))?" protocol="(\w+)"')


def forwarded_ports(listing: "str | None" = None) -> "frozenset | None":
    """``(first, last, proto)`` of every forward-port of every zone
    (``firewall-cmd --list-all-zones``), rich-rule forward-ports included;
    None when the zones could not be listed (v0.26.0).

    Under StrictForwardPorts=yes, firewalld 2.3.1 accepts DNAT'd traffic to a
    port Docker publishes when a zone also forwards that port, whatever the
    ingress zone or destination (firewalld issue #1536, confirmed upstream; not
    reproduced here) — such a port is not taken as rejected."""
    if listing is None:
        res = run_result("firewall-cmd", "--list-all-zones")
        if not res.ok:
            return None
        listing = res.stdout
    found = set()
    for rx in (_FWD_PORT, _FWD_RICH):
        for m in rx.finditer(listing):
            first = int(m.group(1))
            found.add((first, int(m.group(2) or first), m.group(3).lower()))
    return frozenset(found)


def port_forwarded(forwarded, port: int, proto: str) -> bool:
    """Whether *port*/*proto* falls in one of *forwarded*'s ranges."""
    return any(first <= port <= last and p == proto.lower() for first, last, p in forwarded)


def source_families(zone: ZoneBinding) -> tuple:
    """The families a source zone receives traffic of: those of its address
    sources; both when it also holds a MAC or ipset source, or none at all
    (v0.26.0 — a zone of IPv4 sources with ``rule family="ipv4" reject`` was
    reported open through an IPv6 half no packet reaches)."""
    fams = set()
    for src in zone.sources:
        try:
            fams.add("ipv4" if ipaddress.ip_network(src, strict=False).version == 4 else "ipv6")
        except ValueError:
            return FAMILIES
    return tuple(f for f in FAMILIES if f in fams) or FAMILIES


def families_of(zone: ZoneBinding) -> tuple:
    """The families a judged zone decides for: both when it holds an interface
    (or stands for the default zone), else those its sources cover whole —
    0.0.0.0/0 opens IPv4 and leaves IPv6 to the interface's zone."""
    if zone.physical or not zone.sources:
        return FAMILIES
    return tuple(f for f in FAMILIES if f in zone.covered_families)


def best_verdict(zone: ZoneBinding, host_policies, families=FAMILIES) -> Verdict:
    """The most open verdict *zone* reaches over *families*."""
    verdicts = [zone_verdict(zone, host_policies, f) for f in families]
    rank = {p: i for i, p in enumerate(_OPENNESS)}
    return min(verdicts, key=lambda v: rank.get(v.policy, 1)) if verdicts else Verdict("unknown")


def _rich_rule_grant(rule: str) -> str | None:
    """Return a short descriptor of what an ``accept`` rich rule opens, else None.

    Only rules whose action is ``accept`` grant access; ``reject``/``drop`` rules
    are denials and return None so they never inflate the "zone allows" line.
    A port rule yields ``"5432/tcp (rich)"``, a service rule ``"https (rich)"``,
    and anything else that still accepts yields a generic ``"rich rule"``.
    """
    r = rule.strip()
    if not re.search(r'\baccept\b', r):
        return None
    m = _RICH_PORT.search(r)
    if m:
        return f"{m.group('port')}/{m.group('proto')} (rich)"
    m = _RICH_SERVICE.search(r)
    if m:
        return f"{m.group('name')} (rich)"
    return "rich rule"


@dataclass
class FirewalldStatus:
    """What firewalld is doing, as far as ``firewall-cmd`` will say.

    Args:
        active:        True if ``firewall-cmd --state`` reports it running.
        installed:     True if ``firewall-cmd`` is present (running or not).
        default_zone:  The default zone name (e.g. "FedoraServer", "public"), or "".
        services:      Named services allowed in the default zone (e.g. ssh, cockpit).
        ports:         Raw port rules allowed in the default zone (e.g. "8080/tcp").
        rich_rules:    Raw rich-rule strings from ``--list-rich-rules`` (one per rule).
        forward_ports: Raw forward-port rules from ``--list-forward-ports``.
        sources:       Source addresses bound to the default zone (``--list-sources``).
        target:        The default zone's runtime target (``target:`` line of
                       ``--list-all``): "default", "%%REJECT%%", "DROP" or
                       "ACCEPT"; "" when it could not be read.
        readable:      False when firewall-cmd is present but could not be queried
                       (a refusal is not "no firewall").
    """
    active:        bool = False
    #: v0.25.1 — firewall-cmd is present, running or not. Measured on openSUSE
    #: Leap 16 with firewalld stopped: the alert said "neither UFW nor firewalld
    #: is installed" and the fix began by installing it.
    installed:     bool = False
    default_zone:  str = ""
    services:      list[str] = field(default_factory=list)
    ports:         list[str] = field(default_factory=list)
    rich_rules:    list[str] = field(default_factory=list)
    forward_ports: list[str] = field(default_factory=list)
    sources:       list[str] = field(default_factory=list)
    target:        str = ""
    readable:      bool = True
    #: v0.24.3 — the active zones that hold a physical interface. Empty when
    #: none does (then the default zone stands for the host, as before).
    bindings:      list = field(default_factory=list)
    #: v0.24.3 — active policies whose egress includes HOST.
    host_policies: list = field(default_factory=list)
    #: v0.24.3 — False when firewall-cmd would not list the active zones or
    #: policies. Unread is not "none": which zone holds the interfaces, or
    #: which policy decides first, is then unknown, and so is the verdict.
    zones_read:    bool = True

    @property
    def judged_zones(self) -> "list[ZoneBinding]":
        """The zones that filter the host's inbound traffic: those holding a
        physical interface, or the default zone alone when none does."""
        by_iface = [b for b in self.bindings if b.physical]
        judged = by_iface + [b for b in self.bindings
                             if b.all_sources and not b.physical and self._classifies(b)
                             and self._still_takes_every_public(b)]
        if judged:
            return judged
        return [ZoneBinding(name=self.default_zone, target=self.target,
                            rich_rules=tuple(self.rich_rules))]

    def _still_takes_every_public(self, zone: "ZoneBinding") -> bool:
        """v0.26.0 — an accepting zone bound to a whole family is the host's
        inbound policy while the accepting zones still take every public
        address of that family, in firewalld's order (:func:`source_dispatch`,
        measured on Debian 13): a zone classified first that keeps a public
        range makes it one source zone among others. A filtering zone stays."""
        if best_verdict(zone, self.host_policies, source_families(zone)).policy != "allow":
            return True
        src_zones = [b for b in self.bindings if b.sources and not b.physical and self._classifies(b)]
        open_names = {b.name for b in src_zones if best_verdict(b, self.host_policies, source_families(b)).policy == "allow"}
        dispatch = source_dispatch(src_zones, open_names)
        for family in zone.covered_families:
            version = 4 if family == "ipv4" else 6
            entry = dispatch.get(version)
            if not entry or not entry["open"]:
                return False
            public, public_space = _public_share(entry["open"], version)
            if not _nearly_all(public, public_space):
                return False
        return True

    def taken_from(self, zone: "ZoneBinding") -> tuple:
        """``(zone, source)`` of the zones firewalld classifies before the
        accepting *zone* that keep some of its sources (v0.26.0)."""
        src_zones = [b for b in self.bindings if b.sources and not b.physical and self._classifies(b)]
        open_names = {b.name for b in src_zones if best_verdict(b, self.host_policies, source_families(b)).policy == "allow"}
        own = []
        for src in zone.sources:
            try:
                own.append(ipaddress.ip_network(src, strict=False))
            except ValueError:
                continue
        out = []
        for entry in source_dispatch(src_zones, open_names).values():
            for name, src in entry["taken"]:
                net = ipaddress.ip_network(src, strict=False)
                if any(net.overlaps(o) for o in own if o.version == net.version) and (name, src) not in out:
                    out.append((name, src))
        return tuple(out)

    def _classifies(self, source_zone: "ZoneBinding") -> bool:
        """A source zone takes the packets of some interface: its ingress
        priority is lower than, or equal to, that interface's zone (measured
        both ways on Fedora 44)."""
        refs = [b for b in self.bindings if b.physical] or \
               [b for b in self.bindings if b.name == self.default_zone] or \
               [ZoneBinding(name=self.default_zone)]
        return any(source_zone.ingress_priority <= r.ingress_priority for r in refs)

    def verdicts(self) -> "list[tuple[ZoneBinding, Verdict]]":
        """Each judged zone with the most open verdict firewalld reaches for
        it, over the families it decides for."""
        return [(z, best_verdict(z, self.host_policies, families_of(z))) for z in self.judged_zones]

    def family_policy(self, family: str) -> str:
        """The inbound default for one address family — what the IPv6 section
        needs: 0.0.0.0/0 in trusted, or ``rule family="ipv4" … accept``,
        opens IPv4 and says nothing about IPv6."""
        if not self.zones_read:
            return "unknown"
        policies = [zone_verdict(z, self.host_policies, family).policy
                    for z in self.judged_zones if family in families_of(z)]
        if family in self._pooled()[1]:
            policies.append("allow")
        return most_open(policies)

    @property
    def open_sources(self) -> "list[tuple[ZoneBinding, Verdict]]":
        """Zones bound to narrower sources that let every packet from them in:
        an exposure limited to those addresses, not the host's default."""
        if not self.zones_read:
            return []
        judged = {z.name for z in self.judged_zones}
        return [(b, v) for b in self.bindings
                if b.sources and not b.physical and b.name not in judged and self._classifies(b)
                for v in [best_verdict(b, self.host_policies, source_families(b))] if v.policy == "allow"]

    @property
    def pooled_sources(self) -> "list[tuple[ZoneBinding, tuple]]":
        """Narrower source zones that accept everything and whose sources,
        together, cover a whole address family — 0.0.0.0/1 in one zone and
        128.0.0.0/1 in another let every IPv4 client in as surely as
        0.0.0.0/0 in one. Each zone with the sources of that family."""
        return self._pooled()[0]

    @property
    def pooled_scope(self) -> "tuple[bool, tuple]":
        """(the pooled sources take a whole family, the sources other zones
        classified first take from them as ``(zone, source)``) — v0.26.0."""
        _pooled, _families, whole, taken, _share = self._pooled()
        return whole, taken

    @property
    def pooled_public_share(self) -> float:
        """The share of public addresses the pooled zones take (the lowest
        over the families pooled), 100.0 when all of them — v0.26.0."""
        return self._pooled()[4]

    def _pooled(self) -> "tuple[list, frozenset, bool, tuple, float]":
        """:attr:`pooled_sources`, the families they cover, whether they take a
        whole family, and what zones classified first take from them.

        v0.26.0 — what the open zones really take, in firewalld's order
        (:func:`source_dispatch`); decided: they pool when that covers every
        public address of the family, not only when the declared sources add up
        to all of it (measured on Debian 13: a DROP zone classified first kept
        its /32 out of a pooled 0.0.0.0/1 + 128.0.0.0/1)."""
        open_names = {z.name for z, _ in self.open_sources}
        source_zones = [b for b in self.bindings if b.sources and not b.physical and self._classifies(b)]
        pooled: dict[str, tuple] = {}
        families = set()
        whole = True
        taken: list = []
        share = 100.0
        for version, entry in source_dispatch(source_zones, open_names).items():
            if not entry["open"]:
                continue
            public, public_space = _public_share(entry["open"], version)
            if not _nearly_all(public, public_space):
                continue
            families.add("ipv4" if version == 4 else "ipv6")
            share = min(share, 100.0 * public / public_space)
            whole = whole and any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(entry["open"]))
            taken.extend(t for t in entry["taken"] if t not in taken)
            for name, (zone, srcs) in entry["zones"].items():
                pooled.setdefault(name, (zone, []))[1].extend(srcs)
        # Shown in the order the zones were read, as before 0.26.0.
        listed = [(zone, tuple(pooled[zone.name][1])) for zone, _ in self.open_sources
                  if zone.name in pooled]
        return listed, frozenset(families), whole and bool(families), tuple(taken), share

    @property
    def open_verdict(self) -> "tuple[ZoneBinding, Verdict] | None":
        """The first judged zone through which every unmatched packet gets in,
        with what let it in — None when none, or when the zones were unread."""
        if not self.zones_read:
            return None
        return next(((z, v) for z, v in self.verdicts() if v.policy == "allow"), None)

    @property
    def incoming_policy(self) -> str:
        """The inbound default as "reject"/"deny"/"allow", or "unknown" when it
        was not read — never guessed from a zone name. v0.24.3: the zones that
        actually hold an interface decide, not the default zone alone (Fedora 44:
        enp3s0 bound to ``trusted`` under a filtering default zone was an OK),
        each through the policies into HOST, and the most open of them is the
        host's."""
        return most_open(self.family_policy(f) for f in FAMILIES)

    def allows_summary(self) -> str:
        """Everything the default zone permits, as one human-readable line.

        Named services and raw ports first, then any port/service opened by an
        ``accept`` rich rule (so a port reachable only through a rich rule is no
        longer invisible — the gap this method closes), then forward-ports.
        Returns ``"—"`` when nothing is permitted.
        """
        parts: list[str] = list(self.services) + list(self.ports)
        for rule in self.rich_rules:
            grant = _rich_rule_grant(rule)
            if grant:
                parts.append(grant)
        for fp in self.forward_ports:
            parts.append(f"forward {fp}")
        return ", ".join(parts) or "—"

    @classmethod
    def from_system(cls) -> "FirewalldStatus":
        """Collect firewalld state via ``firewall-cmd``. Never raises."""
        if not _command_exists("firewall-cmd"):
            # No client → firewalld is not the front-end here. Not an error.
            return cls(active=False, readable=True)

        state = run_result("firewall-cmd", "--state")
        # `--state` prints "running"/"not running" and, when not running, also
        # exits non-zero (252). Trust the word, and treat a refusal (no output
        # anywhere, a failure) as unreadable rather than "not running".
        text = (state.stdout or "").strip().lower()
        if "running" in text and "not running" not in text:
            zone = run_result("firewall-cmd", "--get-default-zone").stdout.strip()
            services = run_result("firewall-cmd", "--list-services").stdout.split()
            ports = run_result("firewall-cmd", "--list-ports").stdout.split()
            # Rich rules and forward-ports print one entry per line, so split on
            # newlines (a bare .split() would shred each rule into tokens).
            rich = [ln.strip() for ln in
                    run_result("firewall-cmd", "--list-rich-rules").stdout.splitlines()
                    if ln.strip()]
            fwd = [ln.strip() for ln in
                   run_result("firewall-cmd", "--list-forward-ports").stdout.splitlines()
                   if ln.strip()]
            sources = run_result("firewall-cmd", "--list-sources").stdout.split()
            # Runtime target of the default zone. ``--get-target`` only answers
            # with ``--permanent`` (the saved config, which may differ from what
            # is loaded); ``--list-all`` describes the running zone.
            m = _TARGET_LINE.search(run_result("firewall-cmd", "--list-all").stdout or "")
            bindings, policies = _read_bindings(), _read_host_policies()
            return cls(active=True, installed=True, default_zone=zone,
                       services=services, ports=ports,
                       rich_rules=rich, forward_ports=fwd, sources=sources,
                       target=m.group(1) if m else "",
                       readable=True, bindings=bindings or [],
                       host_policies=policies or [],
                       zones_read=bindings is not None and policies is not None)
        # v0.26.0 — firewalld 2.1.2 (openSUSE Leap 16) prints "not running" on
        # *stderr*, stdout empty, exit 252 (firewall-cmd's NOT_RUNNING): read
        # as unreadable, a stopped firewalld lost its "no firewall" alert once
        # unreadable stopped meaning "installed but not running" (measured).
        if "not running" in (state.stderr or "").lower() or state.code == 252:
            return cls(active=False, installed=True, readable=True)
        if not text and not state.ok:
            # firewall-cmd present but said nothing and failed — refused, not off.
            return cls(active=False, installed=True, readable=False)
        return cls(active=False, installed=True, readable=True)


def _parse_active_zones(text: str) -> "dict[str, list[str]]":
    """``--get-active-zones`` → {zone: interfaces}. A zone line is unindented
    (``FedoraServer (default)``); its ``interfaces:`` line follows, indented."""
    zones: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            current = line.split()[0]
            zones.setdefault(current, [])
        elif current and line.strip().startswith("interfaces:"):
            zones[current] = line.split(":", 1)[1].split()
    return zones


def _parse_active_sources(text: str) -> "dict[str, list[str]]":
    """``--get-active-zones`` → {zone: sources}, from the indented
    ``sources:`` line (measured on Fedora 44: ``trusted`` / ``  sources: 0.0.0.0/0``)."""
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            current = line.split()[0]
        elif current and line.strip().startswith("sources:"):
            out[current] = line.split(":", 1)[1].split()
    return out


def _read_bindings() -> "list[ZoneBinding] | None":
    """Each active zone holding an interface, with its runtime target and rich
    rules (``--zone=Z --list-all``). Never raises; None when the active zones
    could not be listed."""
    res = run_result("firewall-cmd", "--get-active-zones")
    if not res.ok:
        return None
    bindings = []
    sources = _parse_active_sources(res.stdout)
    for name, ifaces in _parse_active_zones(res.stdout).items():
        if not ifaces and not sources.get(name):
            continue
        listing = run_result("firewall-cmd", f"--zone={name}", "--list-all").stdout or ""
        m = _TARGET_LINE.search(listing)
        rich = tuple(ln.strip() for ln in listing.splitlines() if ln.strip().startswith("rule "))
        physical = tuple(i for i in ifaces if _physically_backed(i))
        prio = _INGRESS_LINE.search(listing)
        bindings.append(ZoneBinding(name=name, interfaces=tuple(ifaces), physical=physical,
                                    target=m.group(1) if m else "", rich_rules=rich,
                                    sources=tuple(sources.get(name, ())),
                                    ingress_priority=int(prio.group(1)) if prio else 0))
    return bindings


def _physically_backed(iface: str, depth: int = 0) -> bool:
    """*iface* is a NIC, or sits on one: a bridge, bond or VLAN whose lower
    device (``/sys/class/net/<if>/lower_*``), followed down, is a NIC.

    v0.24.3 — a bare ``device`` test missed the host's real uplink whenever it
    is a bridge: measured on a Mint desktop, ``br0`` carries the default route
    and has no ``device`` link, only its member ``enp10s0`` does. A VLAN's lower
    is its parent and a bond's are its slaves (measured on Mint 22.3). docker0
    (veth members) and virbr0 (none) still resolve to no NIC.
    """
    base = Path("/sys/class/net") / iface
    if path_exists(base / "device"):
        return True
    if depth >= 4:
        return False
    try:
        lowers = [e[len("lower_"):] for e in os.listdir(base) if e.startswith("lower_")]
    except OSError:
        return False
    return any(_physically_backed(low, depth + 1) for low in lowers)


def _parse_active_policies(text: str) -> "dict[str, dict[str, list[str]]]":
    """``--get-active-policies`` → {policy: {"ingress-zones": [...], "egress-zones": [...]}}."""
    out: dict[str, dict[str, list[str]]] = {}
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            current = line.split()[0]
            out[current] = {}
        elif current and ":" in line:
            key, _, val = line.strip().partition(":")
            out[current][key] = val.split()
    return out


_PRIORITY_LINE = re.compile(r"^\s*priority:\s*(-?\d+)\s*$", re.MULTILINE)


def _read_host_policies() -> "list[HostPolicy] | None":
    """Active policies whose egress includes HOST, with their priority. Never
    raises; [] when there are none or this firewalld predates policies (0.9:
    measured on 2.4.0, an unknown option exits 2 with "unrecognized
    arguments"), None when the listing failed otherwise."""
    res = run_result("firewall-cmd", "--get-active-policies")
    if not res.ok:
        if res.code == 2 and "unrecognized arguments" in (res.stderr or ""):
            return []
        return None
    found = []
    for name, zones in _parse_active_policies(res.stdout).items():
        if "HOST" not in zones.get("egress-zones", []):
            continue
        listing = run_result("firewall-cmd", f"--policy={name}", "--list-all").stdout or ""
        m = _TARGET_LINE.search(listing)
        rich = tuple(ln.strip() for ln in listing.splitlines() if ln.strip().startswith("rule "))
        prio = _PRIORITY_LINE.search(listing)
        found.append(HostPolicy(name=name, ingress=tuple(zones.get("ingress-zones", [])),
                                target=m.group(1) if m else "", rich_rules=rich,
                                priority=int(prio.group(1)) if prio else None))
    return found
