"""
Shared parsing for ``ufw status numbered`` output.

Two checks read these rules — ``ports`` to decide whether a listening port is
covered at all, and ``services`` to classify a known service's exposure — and
until v0.15.0 each had its own matcher. They disagreed:

``ports`` anchored on the rule number and read only the To column, with a
docstring explaining exactly why ("to avoid matching port numbers appearing
later on the line, e.g. inside source IPs like 192.168.1.22"). ``services``
searched the whole line, so that one rule::

    [ 1] 80/tcp   ALLOW IN   192.168.1.22

made ports 1, 22, 168 and 192 all look covered by it — and port 22 in
particular, since it is the commonest last octet on an RFC1918 network. A host
running SSH with no firewall rule for it was reported as "open, restricted to
the local network".

One parser now, so the knowledge lives in one place.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from bob._atomic import read_text_capped

# `[ N] <To column> <ACTION> <From column>`
_NUMBERED_RE = re.compile(r"^\s*\[\s*\d+\]\s*(.*)$")
_ACTION_RE   = re.compile(r"\s(ALLOW|DENY|REJECT|LIMIT)\b", re.IGNORECASE)
# Digits with ranges (6000:6007) and lists (80,443), plus an optional protocol.
# This is exactly what ufw stores in `dport`.
_PORTSPEC_RE = re.compile(r"^([\d,:]+)(?:/(tcp|udp))?$", re.IGNORECASE)

_APPS_DIR = Path("/etc/ufw/applications.d")


class UfwRule:
    """One parsed rule line: what it covers, what it does, and from where."""

    __slots__ = ("to_col", "action", "from_col", "raw", "iface")

    def __init__(self, to_col: str, action: str, from_col: str, raw: str, iface: str = "") -> None:
        self.to_col = to_col
        self.action = action
        self.from_col = from_col
        self.raw = raw
        #: v0.31.0, fourth review — the interface of an ``on <iface>`` rule.
        self.iface = iface


def parse_rule(line: str) -> "UfwRule | None":
    """Split one ``ufw status numbered`` line, or None if it is not a rule.

    The To column is cleaned of the ``(v6)`` marker, which only duplicates an
    existing rule, and of a trailing ``on <iface>`` scope, which this project
    does not model either way.
    """
    m = _NUMBERED_RE.match(line)
    if not m:
        return None
    rest = m.group(1)
    action_m = _ACTION_RE.search(rest)
    if action_m:
        to_col = rest[:action_m.start()]
        action = action_m.group(1).upper()
        from_col = rest[action_m.end():]
    else:
        to_col, action, from_col = rest, "", ""
    to_col = to_col.replace("(v6)", "").strip()
    iface_m = re.search(r"\s+on\s+(\S+)$", to_col)
    iface = iface_m.group(1) if iface_m else ""
    to_col = to_col[:iface_m.start()].strip() if iface_m else to_col
    return UfwRule(to_col, action, from_col.strip(), line, iface)


def read_app_profiles(directory: "Path | None" = None) -> "dict[str, list[str]]":
    """Map each UFW application profile name to its port specifications.

    A profile file holds one or more ``[Name]`` sections with a ``ports=``
    line; ufw splits that value on ``|``, so Samba's ``137,138/udp|139,445/tcp``
    is two specifications. Names may contain spaces ("Postfix Submission").

    I/O only — call it from ``from_system``, never from a check.
    """
    apps: dict[str, list[str]] = {}
    base = directory if directory is not None else _APPS_DIR
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return apps
    for path in entries:
        try:
            if not path.is_file():
                continue
            text = read_text_capped(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        name: str | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                name = stripped[1:-1].strip()
            elif name and stripped.lower().startswith("ports="):
                apps[name] = [p for p in stripped.split("=", 1)[1].split("|") if p]
    return apps


def expand_port_spec(spec: str) -> "list[tuple[int, int, str | None]]":
    """Expand one ufw port specification into (low, high, proto) ranges.

    ``22/tcp`` -> [(22, 22, "tcp")]
    ``6000:6007/tcp`` -> [(6000, 6007, "tcp")]
    ``80,443/tcp`` -> [(80, 80, "tcp"), (443, 443, "tcp")]
    ``631`` -> [(631, 631, None)] — no protocol means any protocol.

    Ranges stay ranges: a rule may legitimately span the whole ephemeral range,
    and membership is a comparison.
    """
    m = _PORTSPEC_RE.match(spec.strip())
    if not m:
        return []
    proto = m.group(2).lower() if m.group(2) else None
    out: list[tuple[int, int, str | None]] = []
    for part in m.group(1).split(","):
        if not part:
            continue
        lo_s, _, hi_s = part.partition(":")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
        except ValueError:
            continue
        if lo > hi:
            lo, hi = hi, lo
        out.append((lo, hi, proto))
    return out


def to_column_ranges(
    to_col: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> "list[tuple[int, int, str | None]]":
    """Ranges covered by a rule's To column, resolving an application profile.

    A rule scoped to a destination address puts it in front of the port —
    `ufw allow from any to 192.168.1.5 port 22` prints `192.168.1.5 22/tcp`
    (see ufw's `backend_iptables.get_status`, which appends `" " + port` after
    a non-default destination). The port specification is therefore the last
    whitespace-separated token, and a profile name may itself contain spaces
    ("Postfix Submission"), so the whole column is tried as a profile first.
    """
    profiles = app_profiles or {}
    if to_col in profiles:
        return [r for spec in profiles[to_col] for r in expand_port_spec(spec)]
    candidate = to_col.rsplit(None, 1)[-1] if to_col else ""
    if _PORTSPEC_RE.match(candidate):
        return expand_port_spec(candidate)
    return [r for spec in profiles.get(candidate, []) for r in expand_port_spec(spec)]


def ranges_cover(
    ranges: "list[tuple[int, int, str | None]]", port: int, proto: str
) -> bool:
    """True if any range covers this port/proto.

    A rule with an explicit protocol covers only that protocol; one without
    covers any.
    """
    want = proto.lower()
    return any(lo <= port <= hi and (rp is None or rp == want)
               for lo, hi, rp in ranges)


def _names_no_port(to_col: str) -> bool:
    """v0.31.0 — a To column that names no port: Anywhere, or a bare address
    (``80`` and ``6000:6007`` are ports, not addresses)."""
    if to_col == "Anywhere":
        return True
    import ipaddress
    try:
        ipaddress.ip_network(to_col, strict=False)
    except ValueError:
        return False
    return True


#: The protocol of a rule naming no port, as ufw prints it after the source.
_FROM_PROTO_RE = re.compile(r"/(tcp|udp)$", re.IGNORECASE)


def is_v6_rule(line: str, rule: "UfwRule | None" = None) -> bool:
    """v0.31.0, third review of the changelog — the rule is an IPv6 one.

    ufw marks ``(v6)`` only a rule that names no address of its own. Measured
    on Kali (7 November 2026, review3-ufw.txt): `ufw allow from fd77::1 to any
    port 8099 proto tcp` prints ``8099/tcp  ALLOW IN  fd77::1`` — no marker;
    the IPv6 address in the To or From column says the family.
    """
    if "(v6)" in line:
        return True
    rule = rule if rule is not None else parse_rule(line)
    if rule is None:
        return False
    import ipaddress
    for token in rule.to_col.split() + rule.from_col.split("#", 1)[0].split():
        token = _FROM_PROTO_RE.sub("", token)
        if ":" not in token:
            continue
        try:
            if ipaddress.ip_network(token, strict=False).version == 6:
                return True
        except ValueError:
            continue
    return False


def broad_admits(ufw_numbered: str, v6: "bool | None" = None) -> "list[tuple[str, str | None, str]]":
    """v0.31.0 — the incoming ALLOW/LIMIT rules whose To column names no port.

    Such a rule admits every port (of its protocol) from its source, so a
    listener with no rule of its own is not "covered by the default deny".
    Measured on Kali in a network namespace (7 November 2026), UFW at default
    deny: `ufw allow from 10.77.0.1` and `ufw allow in on h0` opened 8099 over
    IPv4 and IPv6, and BOB said it was covered. As ufw prints them::

        [ 2] Anywhere                   ALLOW IN    10.77.0.1
        [ 3] Anywhere                   ALLOW IN    10.77.0.3/tcp
        [ 5] Anywhere on h0             ALLOW IN    Anywhere
        [ 7] Anywhere                   ALLOW FWD   10.77.0.6       (routed: not this)

    Returns ``(rule as printed, protocol or None, source)``; *v6* keeps only
    the ``(v6)`` rules (True) or only the others (False).
    """
    found = []
    for line in ufw_numbered.splitlines():
        rule = parse_rule(line)
        if rule is None or rule.action not in ("ALLOW", "LIMIT"):
            continue
        if v6 is not None and is_v6_rule(line, rule) != v6:
            continue
        words = rule.from_col.split("#", 1)[0].split()
        if words and words[0] in ("OUT", "FWD"):
            continue
        if words and words[0] == "IN":
            words = words[1:]
        if not _names_no_port(rule.to_col):
            continue
        source = " ".join(words).replace("(v6)", "").strip()
        m = _FROM_PROTO_RE.search(source)
        proto = m.group(1).lower() if m else None
        if m:
            source = source[:m.start()]
        printed = re.sub(r"\s+", " ", _NUMBERED_RE.match(line).group(1).split("#", 1)[0]).strip()
        found.append((printed, proto, source or "Anywhere"))
    return found


def admitted_before_own_rule(
    ufw_numbered: str,
    port: int,
    proto: str,
    v6: "bool | None" = None,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> "tuple[list[tuple[str, str | None, str]], str | None]":
    """v0.31.0 — the rules naming no port met before the first incoming rule
    for *port*/*proto*, and that rule's action (None when none names it).

    UFW applies the first rule that matches a packet. Measured on Kali in a
    network namespace (7 November 2026), UFW at default deny: `ufw allow from
    10.77.0.1` then `ufw deny 8099/tcp` left 8099 open to 10.77.0.1, and BOB
    read the port as refused by its rule; `deny 8099/tcp` first closed it.
    """
    earlier: "list[tuple[str, str | None, str]]" = []
    for line in ufw_numbered.splitlines():
        rule = parse_rule(line)
        if rule is None or not rule.to_col:
            continue
        if v6 is not None and is_v6_rule(line, rule) != v6:
            continue
        direction = rule.from_col.split()[:1]
        if direction and direction[0] in ("OUT", "FWD"):
            continue
        if ranges_cover(to_column_ranges(rule.to_col, app_profiles), port, proto):
            return earlier, rule.action
        earlier += [b for b in broad_admits(line) if b[1] in (None, proto.lower())]
    return earlier, None


def admitting_sources(
    ufw_numbered: str,
    port: int,
    proto: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> "tuple[list[str], bool]":
    """v0.31.0, third review of the changelog — the sources the incoming rules
    admit *port*/*proto* from, and whether a rule for the port refuses it.

    UFW applies the first rule that matches a packet, and a rule matches only
    its own source: a rule for one source leaves every other to the rules after
    it. Measured on Kali in a network namespace (7 November 2026,
    review3-ufw.txt), UFW at default deny, a public and a private client:
    `allow 8099 from <private>` then `allow 8099`, or then `allow from
    <public>` (no port), answered the public client while the services section
    said "restricted to local network"; `deny 8099 from <another host>` then
    `allow 8099` answered it while it said "explicitly blocked"; a refusal of
    8099 over IPv4 only left IPv6 to the rules after it.

    Each family is walked apart, up to the first rule for the port that refuses
    it from every source; each ALLOW/LIMIT rule for the port, or naming no
    port, met on the way adds its source. A refusal for one source does not
    take that source out of a later admission: this can overstate, never
    understate.

    v0.31.0, fourth review — a refusal ends the walk only when it refuses the
    port from every source, on every interface and to every address: an
    ``on <iface>`` rule or a rule with a destination address left the port open
    elsewhere. Measured on Kali (review4-ufw.txt), default deny: `deny in on
    <public side> port 8099` or `deny 8099 to <public-side address>`, then
    `allow 8099`, answered the private client, read "explicitly blocked".
    """
    sources, refused, _closed = _walk_sources(ufw_numbered, port, proto, app_profiles)
    return sources, refused


def refusal_closes(
    ufw_numbered: str,
    port: int,
    proto: str,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> bool:
    """v0.31.0, fourth review — True when, in both families, the walk of
    :func:`admitting_sources` ends on a rule that refuses *port*/*proto* from
    every source, on every interface and to every address. Otherwise what the
    rules leave falls to UFW's default incoming policy. Measured on Kali
    (review4-ufw.txt), default allow: a refusal for one host, for IPv4 only, or
    on one interface left 8099 answering other clients, read "explicitly
    blocked"; `deny 8099` refused everyone.
    """
    _sources, _refused, closed = _walk_sources(ufw_numbered, port, proto, app_profiles)
    return len(closed) == 2


def rules_leave_rest_open(
    ufw_numbered: str,
    port: int,
    proto: str,
    v6: bool,
    app_profiles: "dict[str, list[str]] | None" = None,
) -> bool:
    """v0.31.2 — True when, in family *v6*, the rules for *port*/*proto* (or
    naming no port) neither refuse it from every source, on every interface and
    to every address, nor admit it from any source (``Anywhere``): under UFW's
    default allow, the clients no rule matches reach it.

    0.31.1 counted a port with any rule of its own as covered in the ports and
    IPv6 sections. Measured on Kali at default allow (review10-ufw.txt W1,
    review4-ufw.txt R): `allow 8099 from <private>`, or `deny 8099 from
    <another host>`, answered the public client while both sections read the
    port covered; `deny 8099` refused everyone (closed), and `allow 8099`
    opens it on purpose (Anywhere) — neither is this case.
    """
    sources, _refused, closed = _walk_sources(ufw_numbered, port, proto, app_profiles, families=(v6,))
    return not closed and "Anywhere" not in sources


def _walk_sources(
    ufw_numbered: str,
    port: int,
    proto: str,
    app_profiles: "dict[str, list[str]] | None" = None,
    families: "tuple[bool, ...]" = (False, True),
) -> "tuple[list[str], bool, list[bool]]":
    """The walk of :func:`admitting_sources`, with the families it closed;
    v0.31.2 — *families* limits it to IPv4 (False) or IPv6 (True)."""
    sources: "list[str]" = []
    refused = False
    closed: "list[bool]" = []
    for v6 in families:
        for line in ufw_numbered.splitlines():
            rule = parse_rule(line)
            if rule is None or not rule.to_col or is_v6_rule(line, rule) != v6:
                continue
            words = rule.from_col.split("#", 1)[0].split()
            if words[:1] in (["OUT"], ["FWD"]):
                continue
            if not ranges_cover(to_column_ranges(rule.to_col, app_profiles), port, proto):
                sources += [src for _p, bp, src in broad_admits(line) if bp in (None, proto.lower())]
                continue
            words = words[1:] if words[:1] == ["IN"] else words
            source = " ".join(words).replace("(v6)", "").strip() or "Anywhere"
            if rule.action in ("ALLOW", "LIMIT"):
                sources.append(source)
            elif rule.action in ("DENY", "REJECT"):
                refused = True
                if source == "Anywhere" and not rule.iface and len(rule.to_col.split()) == 1:
                    closed.append(v6)
                    break
    return sources, refused, closed


def admitting(broad: "list[tuple[str, str | None, str]]", proto: str) -> "list[str]":
    """The rules of :func:`broad_admits` that admit *proto*, as printed."""
    return [printed for printed, p, _ in broad if p in (None, proto.lower())]


def is_rule_line(line: str) -> bool:
    """True if *line* is a numbered rule row rather than a header or blank."""
    return _NUMBERED_RE.match(line) is not None



def iface_matches(pattern: str, names: "frozenset[str]") -> bool:
    """An ``on <iface>`` pattern as iptables reads it: a trailing ``+`` is a
    prefix (``cali+``), anything else the whole name."""
    if pattern.endswith("+"):
        return any(n.startswith(pattern[:-1]) for n in names)
    return pattern in names


def outward_interfaces(addr_output: str, routes_v4: str, routes_v6: "str | None") -> "dict[bool, frozenset[str] | None]":
    """v0.31.3 — per family (False: IPv4, True: IPv6), the interfaces a client
    from the network can arrive on: those holding an address on a network
    (not loopback, not link-local, a prefix shorter than /32 or /128), or a
    route to one — a default route, or any route shorter than /32 or /128 —
    in any routing table (``ip route show table all``, ``ip -6 route show table
    all``; a route to a single peer is a /32 or /128 and does not count).
    *routes_v6* None: the IPv6 routes were not read, that family's interfaces
    are not known (None). The fifth review of the changelog: wg-quick puts a
    client's default route in a table of its own (51820), not main; reading
    every table gave the same interfaces on the Mint and the Ubuntu node
    (measured), the ``local`` table's routes being types, not addresses.

    Measured on Ubuntu Server 26.04 with MicroK8s 1.35.6 (8 November 2026):
    enp3s0 holds 192.168.1.0/24, a /64 and both default routes; calico's
    ``cali*`` hold only link-local addresses (a /32 route to one pod each) and
    ``vxlan.calico`` a /32 — no client from the network arrives on them. Second
    review of the 0.31.3 changelog: an interface holding a /32 with a route to
    a network through it (a WireGuard peer network, a point-to-point link)
    brings clients too; only a default route was read. Every IPv6 interface
    has an ``fe80::/64`` route (measured on Mint): link-local networks are not
    a network of clients.
    """
    found: "dict[bool, set[str]]" = {False: set(), True: set()}
    for line in addr_output.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
            continue
        name = parts[1].split("@", 1)[0]
        try:
            iface = ipaddress.ip_interface(parts[3])
        except ValueError:
            continue
        if iface.ip.is_loopback or iface.ip.is_link_local:
            continue
        if iface.network.prefixlen < iface.max_prefixlen:
            found[parts[2] == "inet6"].add(name)
    for v6, routes in ((False, routes_v4), (True, routes_v6 or "")):
        for entry in re.split(r"\n(?=\S)", routes):
            words = entry.split()
            if words[:1] == ["unicast"]:
                words = words[1:]
            if not words:
                continue
            if words[0] != "default":
                # A route type (blackhole, unreachable, local…) is not an
                # address; a route to one address reads as a /32 or /128.
                try:
                    net = ipaddress.ip_network(words[0], strict=False)
                except ValueError:
                    continue
                if net.prefixlen >= net.max_prefixlen or net.is_link_local or net.is_loopback or net.is_multicast:
                    continue
            for m in re.finditer(r"\bdev\s+(\S+)", entry):
                found[v6].add(m.group(1))
    return {False: frozenset(found[False]), True: frozenset(found[True]) if routes_v6 is not None else None}


def read_outward_interfaces() -> "dict[bool, frozenset[str] | None] | None":
    """:func:`outward_interfaces` of this host; None when the addresses or the
    IPv4 routes could not be read."""
    from bob.checks._run import run_result
    addrs = run_result("ip", "-o", "addr", "show")
    v4 = run_result("ip", "route", "show", "table", "all")
    if not (addrs.ok and v4.ok):
        return None
    v6 = run_result("ip", "-6", "route", "show", "table", "all")
    return outward_interfaces(addrs.stdout, v4.stdout, v6.stdout if v6.ok else None)


def network_rules(ufw_numbered: str, outward: "dict[bool, frozenset[str] | None] | None") -> str:
    """v0.31.3 — *ufw_numbered* without the incoming ALLOW/LIMIT rules limited
    to an interface (``on <iface>``) no client from the network arrives on
    (:func:`outward_interfaces`): they admit the pods, containers or VMs behind
    it, not the network the services, ports and IPv6 sections weigh. Rules of a
    family whose interfaces are not known (None, or *outward* None) are kept:
    BOB can overstate, never understate.

    Measured on Ubuntu Server 26.04, MicroK8s 1.35.6, UFW at default deny with
    the rules MicroK8s documents (``allow in on cali+``, ``allow in on
    vxlan.calico``): from the LAN only 22 answered, while the services section
    read Samba (445, 139) and Nextcloud (80, 443) "open to the internet — UFW
    rule allows from any address (Anywhere)", ALERT −2 each.
    """
    if not outward:
        return ufw_numbered
    kept = []
    for line in ufw_numbered.splitlines():
        rule = parse_rule(line)
        if rule is not None and rule.iface and rule.action in ("ALLOW", "LIMIT"):
            names = outward.get(is_v6_rule(line, rule))
            if names is not None and not iface_matches(rule.iface, names):
                continue
        kept.append(line)
    return "\n".join(kept)


#: The sed that turns ufw's IPv6 on, as `firewall._ipv6_enable_cmd` writes it
#: (spaces around ``=`` and any case, measured in v0.20.0).
_IPV6_ON = "sudo sed -i -E 's/^IPV6[[:space:]]*=[[:space:]]*no\\b.*/IPV6=yes/I' /etc/default/ufw"


def enable_cmd(ssh_ports: "list[int] | None" = None, ipv6_off: bool = False) -> "str | None":
    """``ufw enable``, preceded by an allow for every port sshd answers on.

    v0.24.4 — ufw starts at "deny (incoming)". Measured on a Raspberry Pi
    (trixie) over SSH: the bare ``sudo ufw enable`` BOB printed for an inactive
    firewall left port 22 silent for every new connection — the most urgent
    advice in the report cut a remote operator off. ``None`` (the listening set
    could not be read): no command — allowing 22 alone would cut an sshd on
    another port, and a guess is not a way in. ``[]`` (sshd answers on no
    external address) enables straight away.

    *ipv6_off*: ufw is set to ``IPV6=no`` and sshd answers over IPv6. ufw-init
    then drops all IPv6 (measured in v0.24.2), so an allow cannot keep an IPv6
    SSH path: IPv6 is turned on first, and the allow covers both families.
    """
    if ssh_ports is None:
        return None
    ports = sorted(set(ssh_ports))
    steps = [_IPV6_ON] if ipv6_off and ports else []
    return " && ".join(steps + [f"sudo ufw allow {p}/tcp" for p in ports] + ["sudo ufw enable"])
