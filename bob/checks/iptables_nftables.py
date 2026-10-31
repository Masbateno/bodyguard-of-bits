"""
CHECK 46 — iptables / nftables audit (UFW inactive).

Triggered only when UFW is inactive or not installed.
Detects the active backend (nftables native or iptables), reads the
default INPUT and FORWARD chain policies, and verifies loopback and
conntrack rules are in place when the INPUT policy is restrictive.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from bob.checks import _ufw
from bob.checks._run import _command_exists, _identity_t, _run, install_command, run_result
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
        nft_no_input_filter: True when nft answered and defines no input hook.
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
    # True when nft answered cleanly and its ruleset filters no inbound
    # traffic. A measurement, not an absence: the backend is installed.
    nft_no_input_filter: bool = False
    #: v0.24.4 — where the input / forward hooks live: ("nft", family, table,
    #: chain), ("iptables",) for a chain iptables manages (iptables-nft says
    #: so in the ruleset), or None when that could not be read.
    input_target:   "tuple | None" = None
    forward_target: "tuple | None" = None
    #: The chain the input fix would target holds a rule accepting everything:
    #: a drop policy behind it would change nothing.
    input_accepts_all: bool = False
    #: v0.26.0 — INPUT's restrictive verdict comes from a final rule that
    #: drops or rejects everything, not from the chain's policy.
    input_policy_by_rule: bool = False
    #: v0.28.0 — the same two facts for the forward hook.
    forward_accepts_all: bool = False
    forward_policy_by_rule: bool = False
    #: v0.28.0 — for the iptables backend, ``iptables -t T -S`` of the raw,
    #: mangle and security tables (refusals before or beside filter's INPUT);
    #: None when they could not be read.
    other_tables: "dict | None" = field(default=None, repr=False)
    #: v0.29.0 — this host's addresses (None: not read), and nft's ruleset
    #: when it answered with no input hook (read through iptables, but a
    #: prerouting or ingress chain of its own still refuses first).
    host_addresses: "frozenset | None" = field(default=None, repr=False)
    nft_pre_input: str = field(default="", repr=False)
    #: v0.29.0, review of the changelog — the chains on the way in, besides
    #: the input chains read, whose policy is drop: the input hook accepts by
    #: default, the way in does not.
    default_drop_before_input: "list[str]" = field(default_factory=list, repr=False)

    def port_verdict(self, port: int, proto: str) -> "tuple[str, str]":
        """v0.28.0 — the IPv4 verdict a new connection to *port* meets in this
        ruleset (:func:`nft_port_verdict`, :func:`ipt_port_verdict`)."""
        if self.backend == "nftables":
            return nft_port_verdict(self.raw_output, port, proto, self.host_addresses)
        if self.backend == "iptables":
            got = ipt_port_verdict(self.raw_output, port, proto, self.other_tables, self.host_addresses)
            if got[0] == "ACCEPT" and self.nft_pre_input and _nft_refused_before_input(
                    self.nft_pre_input, _nft_all_chains(self.nft_pre_input), port, proto,
                    hosts=self.host_addresses):
                return "UNKNOWN", ""
            return got
        return "UNKNOWN", ""

    @classmethod
    def from_system(cls) -> "IptablesNftSnapshot":
        """Collect live state. Never raises."""
        # --- try nftables first ---
        #
        # The exit code is the discriminator here, and deliberately so — the
        # opposite of the choice `unit_active_state` documents for systemctl.
        # `systemctl is-active` exits non-zero to *report* an inactive unit,
        # which is an answer; nft exits non-zero only when it could not answer.
        # Established against nft itself: refused prints "Operation not
        # permitted (you must be root)" and exits 1 with empty stdout, while a
        # genuinely empty ruleset exits 0, also with empty stdout. stdout alone
        # cannot tell them apart. The exit code can.
        nft_present  = _command_exists("nft")
        nft_answered = False
        nft_raw = ""
        if nft_present:
            nft_res = run_result("nft", "list", "ruleset")
            nft_answered, raw = nft_res.ok, nft_res.stdout
            nft_raw = (raw or "") if nft_answered else ""
            if raw and "hook input" in raw:
                hosts = _host_addresses()
                return cls(
                    backend="nftables",
                    # v0.29.0 — what the chains before input may refuse.
                    input_policy=_with_pre_input(_nft_policy(raw, "input"), _nft_refused_before_input(
                        raw, _nft_all_chains(raw), None, None, hosts=hosts)),
                    host_addresses=hosts,
                    default_drop_before_input=_nft_default_drop_before_input(raw),
                    forward_policy=_nft_policy(raw, "forward"),
                    has_loopback_rule=_nft_has_loopback(raw),
                    has_conntrack_rule=_nft_has_conntrack(raw),
                    raw_output=raw,
                    input_target=_nft_hook_target(raw, "input", _nft_managed(nft_res.stderr)),
                    forward_target=_nft_hook_target(raw, "forward", _nft_managed(nft_res.stderr)),
                    input_accepts_all=_nft_first_ipv4_chain_accepts_all(raw, "input"),
                    input_policy_by_rule=_nft_policy_by_rule(raw, "input"),
                    forward_accepts_all=_nft_first_ipv4_chain_accepts_all(raw, "forward"),
                    forward_policy_by_rule=_nft_policy_by_rule(raw, "forward"),
                )

        # --- fall back to iptables ---
        if _command_exists("iptables"):
            raw = _run("iptables", "-S")
            if raw:
                hosts = _host_addresses()
                other = _ipt_other_tables()
                # v0.29.0 — the raw, mangle and security tables, and nft's
                # own chains before input when it answered with no input hook.
                refused = None if other is None else (
                    _ipt_refused_before_input(other, None, None, hosts)
                    or bool(nft_raw and _nft_refused_before_input(nft_raw, _nft_all_chains(nft_raw),
                                                                  None, None, hosts=hosts)))
                return cls(
                    backend="iptables",
                    input_policy=_with_pre_input(_ipt_effective_input_policy(raw), refused),
                    host_addresses=hosts,
                    nft_pre_input=nft_raw,
                    forward_policy=_ipt_effective_forward_policy(raw),
                    has_loopback_rule=_ipt_has_loopback(raw),
                    has_conntrack_rule=_ipt_has_conntrack(raw),
                    raw_output=raw,
                    input_target=("iptables",),
                    forward_target=("iptables",),
                    input_accepts_all=bool(re.search(r"^-A INPUT -j ACCEPT\s*$", raw, re.MULTILINE)),
                    input_policy_by_rule=_ipt_terminal_input(raw) in ("DROP", "REJECT"),
                    forward_accepts_all=bool(re.search(r"^-A FORWARD -j ACCEPT\s*$", raw, re.MULTILINE)),
                    forward_policy_by_rule=_ipt_terminal_forward(raw) in ("DROP", "REJECT"),
                    other_tables=other,
                    default_drop_before_input=(_ipt_default_drop_before_input(other)
                                               + (_nft_default_drop_before_input(nft_raw) if nft_raw else [])),
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
        # nft present and refusing is the same "unknown" as iptables present
        # and refusing. Without this, a host running nftables with no iptables
        # binary — increasingly ordinary — was told it had no firewall backend
        # at all and to install iptables, for three points, the largest single
        # deduction in the check.
        # nft answering settles it: the query did not fail, whatever iptables
        # did or did not print. Only when nothing answered is the state unknown
        # — and nft refusing counts, which is the gap this closes. A host
        # running nftables with no iptables binary, increasingly ordinary, was
        # told it had no firewall backend at all and to install iptables, for
        # three points, the largest single deduction in the check.
        query_failed = (not nft_answered) and (
            _command_exists("iptables") or nft_present
        )
        # nft answered, and nothing in what it returned filters inbound
        # traffic. The backend exists; it is the ruleset that is empty.
        nft_no_input_filter = nft_present and nft_answered
        return cls(
            backend="none",
            query_failed=query_failed,
            nft_no_input_filter=nft_no_input_filter,
            input_policy="unknown",
            forward_policy="unknown",
            has_loopback_rule=False,
            has_conntrack_rule=False,
        )


# ---------------------------------------------------------------------------
# Parsers — nftables
# ---------------------------------------------------------------------------

#: The families whose base chains see IPv4 — what these findings are about.
#: An ``ip6`` chain filters IPv6 only (v0.24.4, measured on Mint: an ``ip6``
#: chain at policy drop beside ``ip filter INPUT`` at accept left 8080 open
#: over IPv4, and BOB had read the hook as DROP).
_IPV4_FAMILIES = ("ip", "inet")
_RULE_NOISE = re.compile(r"\bcounter(?:\s+packets\s+\d+\s+bytes\s+\d+)?|#.*$")


def _nft_base_chains(ruleset: str, hook: str) -> "list[dict]":
    """The base chains on *hook*, in ruleset order: family, table, chain,
    policy and the rules they hold."""
    chains: list = []
    table = current = None
    for line in ruleset.splitlines():
        text = line.strip()
        m = re.match(r"table\s+(\w+)\s+(\S+)\s*\{", text)
        if m:
            table, current = (m.group(1), m.group(2)), None
            continue
        m = re.match(r"chain\s+(\S+)\s*\{", text)
        if m and table:
            current = {"family": table[0], "table": table[1], "chain": m.group(1),
                       "hook": None, "policy": None, "rules": []}
            chains.append(current)
            continue
        if current is None:
            continue
        if text == "}":
            current = None
            continue
        hm = re.search(r"\bhook\s+(\w+)", text)
        if hm:
            current["hook"] = hm.group(1).lower()
            pm = re.search(r"\bpolicy\s+(\w+)", text)
            current["policy"] = pm.group(1).upper() if pm else "ACCEPT"
        elif text:
            current["rules"].append(text)
    return [c for c in chains if c["hook"] == hook]


def _nft_first_ipv4_chain_accepts_all(ruleset: str, hook: str) -> bool:
    """Whether the chain a fix would target (the first ip/inet base chain on
    *hook*) holds a rule accepting everything."""
    for c in _nft_base_chains(ruleset, hook):
        if c["family"] in _IPV4_FAMILIES:
            return any(_accepts_everything(r) for r in c["rules"])
    return False


#: v0.26.0 — a rule that drops or rejects every packet, counters and comments
#: aside: ``drop``, ``reject``, ``reject with icmp type host-prohibited``.
_DROPS_EVERYTHING = re.compile(r"^(drop|reject(?:\s+with\s+[\w\s-]+)?)$")


#: v0.27.0 — what a rule can do to a packet besides accepting it. Measured in
#: a network namespace (24 October 2026), nftables, IPv4 and IPv6 alike: an
#: input chain at policy accept with `tcp dport 8099 drop`, or with `jump x`
#: where x drops 8099, left 8099 closed — and BOB read "accept" (−3 for IPv4,
#: capped at 3/10 by "no firewall"; −2 for IPv6). A jump to a chain that only
#: accepts, an empty chain and a log rule left it open.
_NFT_REFUSES = re.compile(r"\b(?:drop|reject|queue)\b")
_NFT_JUMP = re.compile(r"\b(?:jump|goto)\s+([\w.-]+)")
#: A rule that matches only invalid packets refuses no new connection.
_NFT_INVALID_ONLY = re.compile(r"^ct\s+state\s+(?:\{\s*)?invalid(?:\s*\})?\s+drop$")
#: Measured after the review (24 October 2026): a refusal limited to some
#: sources — fail2ban's `ip saddr @addr-set-sshd reject`, `ip saddr 10.77.0.99
#: drop`, `-s 10.77.0.99 -j DROP`, a jump to fail2ban's chain of `-s … -j
#: REJECT` — and the loopback guard `iifname != "lo" ip daddr 127.0.0.0/8 drop`
#: left 8099 open to the others: the default still accepts them. A negated
#: source (`ip saddr != …`, `! -s …`) refuses nearly everyone, and closed it.
_NFT_SOME_SOURCES = re.compile(r"\bsaddr\s+(?!!=)|\bdaddr\s+(?:127\.|::1\b)")
_IPT_SOME_SOURCES = re.compile(r"(?<!! )(?:-s|--source)\s+\S+|--match-set\s+\S+\s+src\b|(?<!! )-d\s+(?:127\.|::1/)")
_QUOTED = re.compile(r'"[^"]*"')
#: v0.29.0 — a rule limited to given destinations (not negated).
_NFT_DADDR = re.compile(r"\bip6?\s+daddr\s+(?!!=)(\{[^}]*\}|\S+)")
_IPT_DADDR = re.compile(r"(?<!! )(?:-d|--destination)\s+(\S+)")


def _host_addresses() -> "frozenset | None":
    """This host's addresses (``ip -o addr show``), or None when not read."""
    import ipaddress
    res = run_result("ip", "-o", "addr", "show")
    if not res.ok:
        return None
    found = set()
    for m in re.finditer(r"\binet6?\s+([0-9a-fA-F.:]+)(?:/\d+)?", res.stdout or ""):
        try:
            found.add(ipaddress.ip_address(m.group(1)))
        except ValueError:
            return None
    return frozenset(found) or None


def _aimed_elsewhere(text: str, hosts: "frozenset | None", nft: bool = True) -> bool:
    """Whether a rule outside filter's INPUT (before the input hook, or on it
    in the mangle or security table) refuses only packets to
    destinations that hold none of this host's addresses, so that it cannot
    close a listener of the host (v0.29.0). Measured with Docker 29, both
    firewall backends: `-d 172.17.0.2/32 ! -i docker0 -j DROP` in the raw
    table (nft: `ip daddr 172.17.0.2 iifname != "docker0" drop`) guards the
    container, and 0.28.0 made every port of the host not established for it.
    Addresses not read, or a destination BOB cannot parse: False."""
    if not hosts:
        return False
    m = (_NFT_DADDR if nft else _IPT_DADDR).search(text)
    if not m:
        return False
    import ipaddress
    try:
        nets = [ipaddress.ip_network(a.strip(), strict=False)
                for a in m.group(1).strip("{}").split(",") if a.strip()]
    except ValueError:
        return False
    return bool(nets) and not any(h in n for n in nets for h in hosts if h.version == n.version)


def _nft_all_chains(ruleset: str) -> "dict[tuple, list[str]]":
    """Every chain's rules, base or not, keyed by (family, table, chain)."""
    chains: dict = {}
    table = current = None
    for line in ruleset.splitlines():
        text = line.strip()
        m = re.match(r"table\s+(\w+)\s+(\S+)\s*\{", text)
        if m:
            table, current = (m.group(1), m.group(2)), None
            continue
        m = re.match(r"chain\s+(\S+)\s*\{", text)
        if m and table:
            current = chains.setdefault((table[0], table[1], m.group(1)), [])
            continue
        if current is None:
            continue
        if text == "}":
            current = None
        elif text and not re.search(r"\bhook\s+\w+", text):
            current.append(text)
    return chains


#: v0.28.0 — the per-port verdict (lot 4, simple version). Measured in a
#: network namespace (25 October 2026), listeners 8098 and 8099: at policy
#: accept `tcp dport 8099 drop` (or `-p tcp --dport 8099 -j REJECT`) closed
#: 8099 only; at policy drop `tcp dport 8099 accept`, `{ 8098, 8099 }`,
#: `8090-8098`, `-m multiport --dports 8098,8099` and `--dport 8090:8098`
#: opened exactly the ports they name; `udp dport 8099 accept` did not open the
#: TCP listener; an accept placed before a drop for the same port won; an accept
#: limited to another source left 8099 closed to this one. Loopback,
#: established/related and invalid-only rules do not touch a new connection
#: from the network. Any other rule makes the port "not established".
_NFT_PORT_RULE = re.compile(
    r"^(?:meta\s+l4proto\s+(tcp|udp)\s+)?(tcp|udp)\s+dport\s+(\{[^}]*\}|[\d-]+)\s+"
    r"(accept|drop|reject(?:\s+with\s+[\w\s-]+)?)$")
_NFT_PORT_NEUTRAL = re.compile(
    r'^(?:iif|iifname)\s+"lo"\s+accept$'
    r"|^ct\s+state\s+(?:\{\s*)?(?:established|related)(?:\s*,\s*(?:established|related))*(?:\s*\})?\s+accept$"
    r"|^ct\s+state\s+(?:\{\s*)?invalid(?:\s*\})?\s+drop$"
    r"|^log\b[^;]*$"
    r"|^(?:ip\s+protocol\s+icmp|meta\s+l4proto\s+(?:icmp|ipv6-icmp)|icmp\s+type\b.*|icmpv6\s+type\b.*)\s*accept$")
_NFT_COMMENT = re.compile(r'\s*comment\s+"[^"]*"')
_IPT_PORT_RULE = re.compile(
    r"^-p (tcp|udp)(?: -m (?:tcp|udp))? --dport (\d+(?::\d+)?) -j (ACCEPT|DROP|REJECT)(?: --reject-with \S+)?$"
    r"|^-p (tcp|udp) -m multiport --dports ([\d,:]+) -j (ACCEPT|DROP|REJECT)(?: --reject-with \S+)?$")
_IPT_PORT_NEUTRAL = re.compile(
    r"^-i lo -j ACCEPT$"
    r"|^-m (?:conntrack --ctstate|state --state) (?:RELATED,ESTABLISHED|ESTABLISHED,RELATED|ESTABLISHED) -j ACCEPT$"
    r"|^-m (?:conntrack --ctstate|state --state) INVALID -j DROP$"
    r"|^-p (?:icmp|ipv6-icmp)\b.*-j ACCEPT$"
    r"|^-j LOG\b.*$")


def _port_in(spec: str, port: int, sep: str = "-") -> "bool | None":
    """Whether *port* is in a port list (``{ 80, 443 }``, ``8090-8098``,
    ``80,443``, ``8090:8098``); None when the list is not plain numbers."""
    for item in (x.strip() for x in spec.strip("{} ").split(",")):
        m = re.fullmatch(rf"(\d+)(?:{re.escape(sep)}(\d+))?", item)
        if not m:
            return None
        if int(m.group(1)) <= port <= int(m.group(2) or m.group(1)):
            return True
    return False


def _nft_port_walk(rules, chains, family, table, port, proto, seen):
    """("ACCEPT"|"DROP"|"UNKNOWN", "rule") when a rule decides, ("END", "")
    after a goto ran out, None when the chain falls through."""
    for rule in rules:
        text = re.sub(r"\s+", " ", _NFT_COMMENT.sub("", _RULE_NOISE.sub("", rule))).strip()
        if not text or _NFT_PORT_NEUTRAL.match(text):
            continue
        if text == "accept":
            return "ACCEPT", "rule"
        if _DROPS_EVERYTHING.match(text):
            return "DROP", "rule"
        if text == "return":
            return None
        m = _NFT_PORT_RULE.match(text)
        if m:
            if (m.group(1) or m.group(2)) != proto:
                continue
            inside = _port_in(m.group(3), port)
            if inside is None:
                return "UNKNOWN", ""
            if inside:
                return ("ACCEPT" if m.group(4) == "accept" else "DROP"), "rule"
            continue
        if _NFT_REFUSES.search(text) and _NFT_SOME_SOURCES.search(text) and "accept" not in text:
            continue                    # refuses given sources only (0.27.0)
        j = re.fullmatch(r"(jump|goto) ([\w.-]+)", text)
        if j and (family, table, j.group(2)) in chains and (family, table, j.group(2)) not in seen:
            key = (family, table, j.group(2))
            sub = _nft_port_walk(chains[key], chains, family, table, port, proto, seen | {key})
            if sub is not None:
                return sub
            if j.group(1) == "goto":
                return "END", ""
            continue
        return "UNKNOWN", ""
    return None


def _names_another_port(text: str, port: int, proto: str, nft: bool = True) -> bool:
    """Whether a port rule (nft text or an ``iptables -S`` rule body) names
    only other ports or another protocol, so that it cannot touch *port*."""
    if nft:
        m = _NFT_PORT_RULE.match(text)
        if not m:
            return False
        return (m.group(1) or m.group(2)) != proto or _port_in(m.group(3), port) is False
    m = _IPT_PORT_RULE.match(text)
    if not m:
        return False
    p, spec = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(5))
    return p != proto or _port_in(spec, port, ":") is False


def _nft_refused_before_input(ruleset: str, every: dict, port: "int | None", proto: "str | None",
                              families: tuple = _IPV4_FAMILIES, hosts: "frozenset | None" = None) -> bool:
    """Whether a hook the packet meets before input — prerouting (ip, inet)
    or ingress (netdev, inet) — may refuse a new connection to *port*.

    v0.28.0, round 2 — measured in a network namespace (29 October 2026),
    input at policy accept with a drop for 22: `tcp dport 8099 drop` in a
    prerouting chain at raw priority, in a netdev ingress chain, or
    `iptables -t raw -A PREROUTING … --dport 8099 -j DROP` closed 8099, and
    BOB read it "accepted by default" — a deduction on a closed port. A drop
    for another port, or `meta mark set`, left it open. A chain whose policy
    is not accept, or a rule that may refuse it, leaves the port not
    established (the rules there are not walked port by port).

    v0.29.0 — *port* None asks whether they may refuse anything (the
    hook's default verdict); *families* the prerouting families (IPv6:
    ip6, inet); a refusal aimed at destinations that are not this host's
    (:func:`_aimed_elsewhere`) does not count."""
    for hook, fams in (("prerouting", families), ("ingress", ("netdev", "inet"))):
        for c in _nft_base_chains(ruleset, hook):
            if c["family"] not in fams:
                continue
            if c["policy"] != "ACCEPT":
                return True
            for rule in c["rules"]:
                text = re.sub(r"\s+", " ", _NFT_COMMENT.sub("", _RULE_NOISE.sub("", rule))).strip()
                if port is not None and _names_another_port(text, port, proto):
                    continue
                if _aimed_elsewhere(text, hosts):
                    continue
                if _nft_rule_may_refuse(rule, every, c["family"], c["table"]):
                    return True
    return False


def _nft_default_drop_before_input(ruleset: str, families: tuple = _IPV4_FAMILIES) -> "list[str]":
    """The prerouting (*families*) and ingress (netdev, inet) base chains
    whose policy is not accept, as ``family table chain`` (v0.29.0, review
    of the changelog). Measured in a network namespace (31 October 2026): an
    inet prerouting chain at policy drop accepting 8098 only closed 8099 —
    the input hook accepted by default, the way in did not."""
    found = []
    for hook, fams in (("prerouting", families), ("ingress", ("netdev", "inet"))):
        for c in _nft_base_chains(ruleset, hook):
            if c["family"] in fams and c["policy"] != "ACCEPT":
                found.append(f"{c['family']} {c['table']} {c['chain']}")
    return found


def nft_port_verdict(ruleset: str, port: int, proto: str,
                     hosts: "frozenset | None" = None) -> "tuple[str, str]":
    """The IPv4 verdict a new connection to *port*/*proto* meets on the input
    hook: ("ACCEPT"|"DROP"|"UNKNOWN", "rule"|"default"|""). Every ip/inet base
    chain must accept it; one that refuses it closes it. A hook before input
    that may refuse it leaves an accept not established."""
    chains = [c for c in _nft_base_chains(ruleset, "input") if c["family"] in _IPV4_FAMILIES]
    if not chains:
        return "UNKNOWN", ""
    every = _nft_all_chains(ruleset)
    verdicts = []
    for c in chains:
        got = _nft_port_walk(c["rules"], every, c["family"], c["table"], port, proto, frozenset())
        if got is None or got[0] == "END":
            got = ("ACCEPT" if c["policy"] == "ACCEPT" else "DROP"
                   if c["policy"] in ("DROP", "REJECT") else "UNKNOWN", "default")
        verdicts.append(got)
    for v in verdicts:
        if v[0] == "DROP":
            return v
    if any(v[0] == "UNKNOWN" for v in verdicts):
        return "UNKNOWN", ""
    if _nft_refused_before_input(ruleset, every, port, proto, hosts=hosts):
        return "UNKNOWN", ""
    return ("ACCEPT", "rule") if any(v[1] == "rule" for v in verdicts) else ("ACCEPT", "default")


#: v0.28.0, round 2 — the chains of the other tables a packet to this host
#: meets on its way in, besides filter's INPUT: raw and mangle PREROUTING,
#: mangle and security INPUT. `iptables -S` prints the filter table only.
_IPT_PRE_INPUT = {"raw": ("PREROUTING",), "mangle": ("PREROUTING", "INPUT"), "security": ("INPUT",)}


def _ipt_other_tables(binary: str = "iptables") -> "dict[str, str] | None":
    """``iptables -t T -S`` for the tables in :data:`_IPT_PRE_INPUT`; a table
    the kernel does not have holds no rule; None when one could not be read.
    v0.29.0 — *binary* ``ip6tables`` for IPv6."""
    out = {}
    for table in _IPT_PRE_INPUT:
        res = run_result(binary, "-t", table, "-S")
        if res.ok:
            out[table] = res.stdout
        elif "Table does not exist" in (res.stderr or ""):
            out[table] = ""
        else:
            return None
    return out


def _ipt_default_drop_before_input(tables: "dict[str, str] | None") -> "list[str]":
    """The chains of :data:`_IPT_PRE_INPUT` whose policy is not accept, as
    ``table CHAIN`` (v0.29.0, review of the changelog): filter's INPUT
    accepts by default, and they refuse by default what they do not accept."""
    return [f"{table} {chain}" for table, text in (tables or {}).items()
            for chain in _IPT_PRE_INPUT.get(table, ())
            if _ipt_policy(text, chain) not in ("ACCEPT", "unknown")]


def _ipt_refused_before_input(tables: "dict[str, str]", port: "int | None", proto: "str | None",
                              hosts: "frozenset | None" = None) -> bool:
    """Whether a rule or a policy in those chains may refuse a new connection
    to *port* (measured: raw PREROUTING, mangle INPUT and security INPUT drops
    for 8099 closed it while BOB, reading `iptables -S`, said accepted by
    default; a mangle PREROUTING drop for 9000 left it open). v0.29.0 —
    *port* None: may they refuse anything; a refusal aimed at destinations
    that are not this host's does not count (:func:`_aimed_elsewhere`)."""
    for table, text in tables.items():
        for chain in _IPT_PRE_INPUT.get(table, ()):
            if _ipt_policy(text, chain) not in ("ACCEPT", "unknown"):
                return True
            prefix = f"-A {chain} "
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith(prefix):
                    continue
                if port is not None and _names_another_port(line[len(prefix):], port, proto, nft=False):
                    continue
                if _aimed_elsewhere(line, hosts, nft=False):
                    continue
                if _ipt_rule_may_refuse(line, text):
                    return True
    return False


def ipt_port_verdict(rules: str, port: int, proto: str,
                     other_tables: "dict[str, str] | None" = None,
                     hosts: "frozenset | None" = None) -> "tuple[str, str]":
    """The same verdict read from ``iptables -S`` (INPUT, user chains it jumps
    to unconditionally followed). *other_tables* holds ``iptables -t T -S``
    for raw, mangle and security; None when they could not be read, and an
    accept is then not established."""
    chains: "dict[str, list[str]]" = {}
    for line in rules.splitlines():
        m = re.match(r"^-A (\S+) (.*)$", line.strip())
        if m:
            chains.setdefault(m.group(1), []).append(m.group(2).strip())

    def walk(name, seen):
        for body in chains.get(name, []):
            if _IPT_PORT_NEUTRAL.match(body):
                continue
            m = re.fullmatch(r"-j (ACCEPT|DROP|REJECT)(?: --reject-with \S+)?", body)
            if m:
                return ("ACCEPT" if m.group(1) == "ACCEPT" else "DROP"), "rule"
            if body == "-j RETURN":
                return None
            m = _IPT_PORT_RULE.match(body)
            if m:
                p, spec, target, sep = ((m.group(1), m.group(2), m.group(3), ":") if m.group(1)
                                        else (m.group(4), m.group(5), m.group(6), ":"))
                if p != proto:
                    continue
                inside = _port_in(spec, port, sep)
                if inside is None:
                    return "UNKNOWN", ""
                if inside:
                    return ("ACCEPT" if target == "ACCEPT" else "DROP"), "rule"
                continue
            if re.search(r"-j (?:DROP|REJECT)\b", body) and _IPT_SOME_SOURCES.search(body):
                continue                # refuses given sources only (0.27.0)
            j = re.fullmatch(r"-([jg]) (\S+)", body)
            if j and j.group(2) in chains and j.group(2) not in seen:
                sub = walk(j.group(2), seen | {j.group(2)})
                if sub is not None:
                    return sub
                if j.group(1) == "g":
                    return "END", ""
                continue
            return "UNKNOWN", ""
        return None

    got = walk("INPUT", frozenset({"INPUT"}))
    if got is None or got[0] == "END":
        policy = _ipt_policy(rules, "INPUT")
        got = ("ACCEPT" if policy == "ACCEPT" else "DROP" if policy in ("DROP", "REJECT") else "UNKNOWN",
               "default")
    if got[0] == "ACCEPT" and (other_tables is None or _ipt_refused_before_input(other_tables, port, proto, hosts)):
        return "UNKNOWN", ""
    return got


def _with_pre_input(policy: str, refused: "bool | None") -> str:
    """The hook's default verdict once the other chains a packet meets on its
    way in are read — before the hook, or on it in another table (security
    INPUT runs after filter's) (v0.29.0): an ACCEPT that one of them may
    refuse is PARTIAL —
    accepted by default, refusals not weighed — and unknown when they could
    not be read. Measured in a network namespace: a drop for 8099 in an nft
    prerouting or ingress chain, a prerouting chain at policy drop, or one in
    raw PREROUTING, mangle or security INPUT closed 8099 over IPv4 or IPv6, and BOB
    said "no rule refuses it" (−3)."""
    if policy != "ACCEPT":
        return policy
    return "unknown" if refused is None else "PARTIAL" if refused else "ACCEPT"


def _nft_rule_may_refuse(rule: str, chains: dict, family: str, table: str, seen: "frozenset" = frozenset()) -> bool:
    """Whether *rule* can drop or reject a new packet, following its jumps and
    gotos into the chains they name (v0.27.0). A chain BOB cannot find may."""
    text = _QUOTED.sub("", _RULE_NOISE.sub("", rule)).strip()
    if _NFT_INVALID_ONLY.match(text) or _NFT_SOME_SOURCES.search(text):
        return False
    if _NFT_REFUSES.search(text):
        return True
    for target in _NFT_JUMP.findall(text):
        key = (family, table, target)
        if key in seen:
            continue
        if key not in chains:
            return True
        if any(_nft_rule_may_refuse(r, chains, family, table, seen | {key}) for r in chains[key]):
            return True
    return False


def _chain_verdict(chain: dict, chains: "dict | None" = None) -> "tuple[str, bool]":
    """(the verdict every packet meets in *chain*, whether a rule gave it).

    v0.27.0 — with *chains* (every chain of the ruleset), an accept reached
    after a rule that can refuse a new packet is "PARTIAL": accepted by
    default, with refusals BOB does not weigh port by port — not established.

    v0.26.0 — measured in a network namespace: a chain at policy accept whose
    last rule is a bare ``reject`` (nft) or ``-j REJECT`` (iptables) refused
    8099 while 8097, accepted above it, answered — and BOB read "no firewall"
    (−3, capped at 3/10). The first rule that takes every packet decides: an
    accept-everything rule, or a drop/reject with no match. A rule with a
    match (``ip protocol tcp … reject``) leaves the rest to the policy.
    """
    refused = False
    for rule in chain["rules"]:
        text = _RULE_NOISE.sub("", rule).strip()
        if text == "accept":
            return ("PARTIAL" if refused else "ACCEPT"), True
        m = _DROPS_EVERYTHING.match(text)
        if m:
            return ("DROP" if m.group(1) == "drop" else "REJECT"), True
        if chains is not None and not refused:
            refused = _nft_rule_may_refuse(text, chains, chain["family"], chain["table"])
    if refused and chain["policy"] == "ACCEPT":
        return "PARTIAL", False
    return chain["policy"], False


def _nft_policy_by_rule(ruleset: str, hook: str) -> bool:
    """Whether the restrictive verdict on *hook* comes from a final rule."""
    return any(v in ("DROP", "REJECT") and by_rule
               for v, by_rule in (_chain_verdict(c) for c in _nft_base_chains(ruleset, hook)
                                  if c["family"] in _IPV4_FAMILIES))


#: v0.27.0 — the families whose base chains see IPv6.
_IPV6_FAMILIES = ("ip6", "inet")


def nft_input_policy_v6(ruleset: str, hosts: "frozenset | None" = None) -> "str | None":
    """The default verdict on the input hook for IPv6 in an nft ruleset, read as
    :func:`_nft_policy` reads IPv4 (policies, and a rule that takes every
    packet) — None when no ip6/inet base chain sits on input (v0.27.0).
    v0.29.0 — and the chains before input (ip6/inet prerouting, ingress):
    one that may refuse makes an ACCEPT PARTIAL, with or without an input chain."""
    chains = [c for c in _nft_base_chains(ruleset, "input") if c["family"] in _IPV6_FAMILIES]
    every = _nft_all_chains(ruleset)
    refused = _nft_refused_before_input(ruleset, every, None, None, _IPV6_FAMILIES, hosts)
    if not chains:
        return "PARTIAL" if refused else None
    effective = {_chain_verdict(c, every)[0] for c in chains}
    return _with_pre_input(next((v for v in ("DROP", "REJECT", "PARTIAL") if v in effective), "ACCEPT"),
                           refused)


def read_input_policy_v6() -> str:
    """IPv6's default inbound verdict on a host filtered by a raw ruleset:
    "DROP", "REJECT", "ACCEPT" or "unknown" (v0.27.0). Until 0.26.1 BOB did not
    read which families a raw ruleset covers and said so (``ipv6.netfilter_v6``).
    nft first (iptables-nft's ip6 tables show there too), then ip6tables -S."""
    nft_answered = False
    hosts = None
    if _command_exists("nft"):
        res = run_result("nft", "list", "ruleset")
        nft_answered = res.ok
        if res.ok:
            hosts = _host_addresses()
            verdict = nft_input_policy_v6(res.stdout, hosts)
            if verdict:
                return verdict
    if _command_exists("ip6tables"):
        raw = _run("ip6tables", "-S")
        if raw and re.search(r"^-P INPUT ", raw, re.MULTILINE):
            # v0.29.0 — ip6tables' raw, mangle and security tables too.
            policy = _ipt_effective_input_policy(raw)
            if policy != "ACCEPT":
                return policy
            other = _ipt_other_tables("ip6tables")
            return _with_pre_input(policy, None if other is None else _ipt_refused_before_input(
                other, None, None, hosts if hosts is not None else _host_addresses()))
        return "unknown"
    return "ACCEPT" if nft_answered else "unknown"


def _accepts_everything(rule: str) -> bool:
    """A rule that accepts every packet: ``accept``, counters and comments aside."""
    return _RULE_NOISE.sub("", rule).strip() == "accept"


def _nft_policy(ruleset: str, hook: str) -> str:
    """Return the default policy on a hook in nft ruleset output, for IPv4.

    v0.24.4 — every base chain on a hook sees the packet in priority order; an
    accept hands it to the next one, a drop ends it. One chain dropping by
    default is enough for the hook to filter. Measured on Mint 22.3: with
    iptables-nft's ``ip filter INPUT`` at policy accept and a second chain
    (``inet bobB``, priority 10, policy drop) keeping SSH, port 8080 was closed
    — and BOB, reading the first chain only, raised "INPUT ACCEPT, all incoming
    traffic is allowed" (ALERT −3). Two limits, measured there too: an ``ip6``
    chain filters no IPv4, and a drop policy behind a rule that accepts
    everything is never reached — 8080 stayed open over IPv4 both times. BOB
    reads policies; it does not evaluate every rule.
    """
    chains = _nft_base_chains(ruleset, hook)
    if not chains:
        return "unknown"
    # v0.27.0 — the refusals a chain's rules make are weighed (PARTIAL).
    # v0.28.0 — on forward too: measured in network namespaces (a router
    # between two veths), FORWARD at policy accept with `tcp dport 8099 drop`,
    # or a jump to a chain dropping it, refused 8099 while 9000 passed — and
    # BOB said "transit traffic is not filtered" (−1).
    every = _nft_all_chains(ruleset)
    effective = [_chain_verdict(c, every)[0] for c in chains if c["family"] in _IPV4_FAMILIES]
    for restrictive in ("DROP", "REJECT", "PARTIAL"):
        if restrictive in effective:
            return restrictive
    # No IPv4 base chain on the hook filters nothing for IPv4.
    return "ACCEPT"


def _nft_managed(stderr: str) -> "frozenset[tuple]":
    """Tables nft says iptables-nft manages — it says so on stderr:
    ``# Warning: table ip filter is managed by iptables-nft, do not touch!``"""
    return frozenset(m.groups() for m in re.finditer(
        r"table\s+(\w+)\s+(\S+)\s+is managed by iptables-nft", stderr or ""))


def _nft_hook_target(ruleset: str, hook: str, managed: "frozenset[tuple]" = frozenset()) -> "tuple | None":
    """Where the first base chain on *hook* lives, as a fix must name it.

    v0.24.4 — the fixes named ``inet filter input`` whatever the host had.
    Measured on Mint 22.3 (iptables-nft): the input hook is chain ``INPUT`` in
    ``table ip filter``, and ``nft chain inet filter input …`` failed with "No
    such file or directory; did you mean table 'filter' in family ip?". nft
    prints "table ip filter is managed by iptables-nft, do not touch!" above
    such a table — on stderr, measured on Mint (nftables 1.0.9): *managed* —
    and those chains are iptables' to change.
    """
    for c in _nft_base_chains(ruleset, hook):
        if c["family"] not in _IPV4_FAMILIES:
            continue          # an ip6 chain does not carry the IPv4 policy the finding is about
        if (c["family"], c["table"]) in managed:
            return ("iptables",)
        return ("nft", c["family"], c["table"], c["chain"])
    return None


def _nft_has_loopback(ruleset: str) -> bool:
    """True if the ruleset accepts traffic arriving on the loopback interface.

    v0.15.4: matched ``iif`` only. nft has two spellings — ``iif`` matches the
    interface by index, ``iifname`` by name — and it preserves whichever the
    operator wrote instead of normalising to one. ``iifname "lo" accept`` is
    the form most guides and distributions ship, and BOB read it as *no
    loopback rule at all*, then deducted for the omission. A false deduction on
    a correctly configured host is worse than a missed one: the operator is
    told to add a rule that is already there.

    Verified against real `nft list ruleset` output: `meta iifname "lo"` and
    `iifname { "lo" }` are both normalised by nft to `iifname "lo"`, so those
    two need no pattern of their own.

    v0.26.0: iptables-nft writes a counter into every rule — ``iifname "lo"
    counter packets 0 bytes 0 accept`` (measured in a network namespace,
    ``iptables -A INPUT -i lo -j ACCEPT``) — and the pattern wanted ``accept``
    right after ``"lo"``: −1 for a rule that was there.
    """
    return bool(re.search(r'\biif(?:name)?\s+"?lo"?\s+(?:counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+)?accept',
                          ruleset, re.IGNORECASE))


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


def _ipt_effective_input_policy(rules: str) -> str:
    """INPUT's policy as packets meet it: ACCEPT when an unconditional
    ``-A INPUT -j ACCEPT`` sits in the chain, whatever ``-P`` says.

    v0.25.0 — measured on a Fedora 43 VM (iptables-legacy): ``-P INPUT DROP``
    then ``-A INPUT -j ACCEPT``, port 8080 answered from the LAN, and BOB read
    DROP — the policy is never reached. As for nftables, BOB reads policies
    and this one rule; a rule accepting a whole interface is not weighed.
    """
    refused = False
    for line in rules.splitlines():
        line = line.strip()
        if not line.startswith("-A INPUT "):
            continue
        m = re.match(r"^-A INPUT -j (ACCEPT|DROP|REJECT)(?:\s+--reject-with\s+\S+)?\s*$", line)
        if m:
            return "PARTIAL" if m.group(1) == "ACCEPT" and refused else m.group(1)
        refused = refused or _ipt_rule_may_refuse(line, rules)
    policy = _ipt_policy(rules, "INPUT")
    return "PARTIAL" if refused and policy == "ACCEPT" else policy


#: v0.27.0 — see _NFT_REFUSES: the same reading for `iptables -S`.
_IPT_TARGET = re.compile(r"\s-[jg]\s+(\S+)")
_IPT_INVALID_ONLY = re.compile(r"-m (?:conntrack --ctstate|state --state) INVALID -j DROP\s*$")


def _ipt_rule_may_refuse(line: str, rules: str, seen: "frozenset" = frozenset()) -> bool:
    """Whether an ``iptables -S`` rule can drop or reject a new packet,
    following a jump or goto into the user chain it names."""
    if _IPT_INVALID_ONLY.search(line) or _IPT_SOME_SOURCES.search(line):
        return False
    m = _IPT_TARGET.search(line)
    if not m:
        return False
    target = m.group(1)
    if target in ("DROP", "REJECT", "NFQUEUE", "QUEUE"):
        return True
    if target in seen or not re.search(rf"^-N {re.escape(target)}\s*$", rules, re.MULTILINE):
        return False        # a built-in target (ACCEPT, RETURN, LOG, MARK…)
    prefix = f"-A {target} "
    return any(_ipt_rule_may_refuse(r.strip(), rules, seen | {target})
               for r in rules.splitlines() if r.strip().startswith(prefix))


def _ipt_effective_forward_policy(rules: str) -> str:
    """FORWARD's policy as packets meet it, read as
    :func:`_ipt_effective_input_policy` reads INPUT (v0.28.0, measured in
    network namespaces, `iptables -S` read with nft hidden: ``-P FORWARD
    DROP`` then ``-A FORWARD -j ACCEPT`` forwarded 8099 and 9000, and BOB said
    "Default FORWARD policy: DROP (recommended)"; ``-p tcp --dport 8099 -j
    DROP`` at policy accept refused 8099 and BOB said "not filtered")."""
    refused = False
    for line in rules.splitlines():
        line = line.strip()
        if not line.startswith("-A FORWARD "):
            continue
        m = re.match(r"^-A FORWARD -j (ACCEPT|DROP|REJECT)(?:\s+--reject-with\s+\S+)?\s*$", line)
        if m:
            return "PARTIAL" if m.group(1) == "ACCEPT" and refused else m.group(1)
        refused = refused or _ipt_rule_may_refuse(line, rules)
    policy = _ipt_policy(rules, "FORWARD")
    return "PARTIAL" if refused and policy == "ACCEPT" else policy


def _ipt_terminal_forward(rules: str) -> str:
    """The first FORWARD rule that takes every packet, as :func:`_ipt_terminal_input`."""
    for line in rules.splitlines():
        m = re.match(r"^-A FORWARD -j (ACCEPT|DROP|REJECT)(?:\s+--reject-with\s+\S+)?\s*$", line.strip())
        if m:
            return m.group(1)
    return ""


def _ipt_terminal_input(rules: str) -> str:
    """The first INPUT rule that takes every packet: ``-j ACCEPT``, ``-j DROP``
    or ``-j REJECT`` with no match (v0.26.0, see :func:`_chain_verdict`); ""."""
    for line in rules.splitlines():
        m = re.match(r"^-A INPUT -j (ACCEPT|DROP|REJECT)(?:\s+--reject-with\s+\S+)?\s*$", line.strip())
        if m:
            return m.group(1)
    return ""


def _ipt_has_loopback(rules: str) -> bool:
    return bool(re.search(r"-i\s+lo\b.*-j\s+ACCEPT", rules, re.IGNORECASE))


def _ipt_has_conntrack(rules: str) -> bool:
    return bool(re.search(
        r"(--state|--ctstate)\s+[A-Z,]*ESTABLISHED[^\n]*-j\s+ACCEPT",
        rules, re.IGNORECASE,
    ))


#: ICMPv6 a host must accept to keep IPv6 working (RFC 4890 §4.4.1), as ufw's
#: before6.rules does, echo aside.
_ICMPV6_NEEDED = ("destination-unreachable, packet-too-big, time-exceeded, parameter-problem, "
                  "nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert")


def _nft_rule(target: tuple, rule: str) -> str:
    _, family, table, chain = target
    return f"sudo nft insert rule {family} {shlex.quote(table)} {shlex.quote(chain)} {rule}"


def _nft_append(target: tuple, rule: str) -> str:
    _, family, table, chain = target
    return f"sudo nft add rule {family} {shlex.quote(table)} {shlex.quote(chain)} {rule}"


def _nft_drop_policy(target: tuple) -> str:
    _, family, table, chain = target
    # The documented form (nft(8): {add | create} chain). Measured on nftables
    # 1.0.9: on an existing base chain it changes the policy, exit 0, as the
    # undocumented bare `nft chain …` BOB printed before did.
    return f"sudo nft add chain {family} {shlex.quote(table)} {shlex.quote(chain)} '{{ policy drop; }}'"


def _input_default_deny(target: "tuple | None", ssh_ports: "list[int] | None") -> "str | None":
    """Default-deny on input that keeps the operator's way in (v0.24.4).

    Measured on Mint 22.3 over SSH: ``iptables -P INPUT DROP``, as printed,
    left new connections unanswered and froze the session that ran it — no
    rule accepted loopback, established traffic or sshd's port. Loopback,
    established/related and the ports sshd answers on are accepted first; then
    the policy.

    The accepts are *appended*, after the rules already there. Measured on a
    Fedora 43 VM: a chain dropping SSH from one neighbour, then BOB's fix with
    its accepts inserted at the top — the neighbour got in, and BOB then said
    INPUT DROP, OK. Appended, the administrator's rules keep deciding first.
    """
    if target is None or ssh_ports is None:
        return None       # a policy that might cut an sshd BOB cannot place is no fix
    ports = sorted(set(ssh_ports))
    if target[0] == "iptables":
        steps = ["sudo iptables -A INPUT -i lo -j ACCEPT",
                 "sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
        steps += [f"sudo iptables -A INPUT -p tcp --dport {p} -j ACCEPT" for p in ports]
        return " && ".join(steps + ["sudo iptables -P INPUT DROP"])
    steps = [_nft_append(target, 'iif "lo" accept'), _nft_append(target, "ct state established,related accept")]
    if target[1] in ("inet", "ip6"):
        # IPv6 needs neighbour and router discovery, which conntrack does not
        # call established: without them a drop policy cuts IPv6 itself.
        steps.append(_nft_append(target, f"icmpv6 type '{{ {_ICMPV6_NEEDED} }}' accept"))
    steps += [_nft_append(target, f"tcp dport {p} accept") for p in ports]
    return " && ".join(steps + [_nft_drop_policy(target)])


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

def check_iptables_nftables(
    snapshot: IptablesNftSnapshot,
    ufw_installed: bool = False,
    firewalld=None,
    t=None,
    ssh_ports: "list[int] | None" = None,
    ufw_ipv6_off: bool = False,
) -> CheckResult:
    """
    Audit the non-UFW firewall layer (iptables or nftables).

    Only meaningful when UFW is inactive; caller is responsible for
    gating on fw_status.active.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # firewalld is the active front-end: it keeps the base chain policy at
    # ACCEPT and filters inside its zone chains (a jump to an explicit
    # drop/reject at the end). Reading the raw base policy here would call a
    # firewalled host wide-open — the false positive measured on a real Fedora
    # 44. Credit firewalld and report what its default zone exposes; the zone
    # rules themselves are firewalld's to audit, not this raw-policy check's.
    if firewalld is not None and firewalld.active:
        svc = firewalld.allows_summary()
        result.ok(
            message=_t("firewall_iptables.firewalld_active",
                       zone=firewalld.default_zone or "?", services=svc),
            key="firewall_iptables.firewalld_active",
        )
        return result

    # v0.26.0 — firewalld installed but firewall-cmd silent: if it runs, it
    # filters in its own chains and keeps the base policy at ACCEPT, so the
    # base chains say nothing about the host. Not judged; said.
    if firewalld is not None and getattr(firewalld, "installed", False) \
            and not getattr(firewalld, "readable", True):
        result.info(message=_t("firewall_iptables.firewalld_unreadable"),
                    key="firewall_iptables.firewalld_unreadable")
        return result

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
    if snapshot.nft_no_input_filter:
        if ufw_installed:
            _nft_no_input_cmd = _ufw.enable_cmd(ssh_ports, ipv6_off=ufw_ipv6_off)
            _nft_no_input_detail = _t("firewall.ssh_ports_unknown_detail") if ssh_ports is None else ""
        elif firewalld is not None and firewalld.installed:
            # v0.25.1 — firewalld installed and stopped: the host's front-end is
            # the remedy. `nft -f /etc/nftables.conf` named a file openSUSE Leap
            # 16 does not have (measured).
            from bob.checks.firewall import _firewall_install_fix
            _nft_no_input_cmd, _nft_no_input_detail = _firewall_install_fix(
                _t, ssh_ports, firewalld_installed=True)
        else:
            _nft_no_input_cmd, _nft_no_input_detail = "sudo nft -f /etc/nftables.conf", ""
        # Same weight as no_backend — nothing is filtering inbound traffic
        # either way — but the statement and the remedy are the host's own.
        # Telling an nftables machine to install iptables was false advice on
        # top of a true finding.
        result.warn_with_deduction(
            key="firewall_iptables.nft_no_input_filter",
            message=_t("firewall_iptables.nft_no_input_filter"),
            points=3,
            nature="action",
            cmd=_nft_no_input_cmd,
            detail=_nft_no_input_detail,
        )
        return result

    if snapshot.backend == "none":
        result.warn_with_deduction(
            key="firewall_iptables.no_backend",
            message=_t("firewall_iptables.no_backend"),
            points=3,
            nature="action",
            cmd=install_command("iptables"),
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
            # v0.24.4: a front-end the host has keeps SSH (the same command as
            # firewall.inactive); otherwise the backend's own default-deny,
            # with the way in accepted first, in the chain the hook uses.
            cmd=(_ufw.enable_cmd(ssh_ports, ipv6_off=ufw_ipv6_off) if ufw_installed
                 else None if snapshot.input_accepts_all
                 else _input_default_deny(snapshot.input_target, ssh_ports)),
            detail=(_t("firewall.ssh_ports_unknown_detail") if ssh_ports is None
                    else "" if ufw_installed or snapshot.input_target is None
                    else _t("firewall_iptables.accept_all_detail") if snapshot.input_accepts_all
                    else _t("firewall_iptables.runtime_only_detail")),
            nature="action",
        )
    elif snapshot.input_policy in ("DROP", "REJECT"):
        result.ok(
            # v0.26.0 — a final drop/reject rule, the chain's policy accept
            # never reached: said as it is, not as "policy DROP".
            message=(_t("firewall_iptables.input_ok_final_rule", policy=snapshot.input_policy)
                     if snapshot.input_policy_by_rule
                     else _t("firewall_iptables.input_ok", policy=snapshot.input_policy)),
            # v0.24.4: what this OK rests on — policies, not every rule.
            detail=_t("firewall_iptables.input_ok_detail"),
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
                    if snapshot.input_target == ("iptables",)
                    else _nft_rule(snapshot.input_target, 'iif "lo" accept') if snapshot.input_target
                    else None
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
                    if snapshot.input_target == ("iptables",)
                    else _nft_rule(snapshot.input_target, "ct state established,related accept")
                    if snapshot.input_target else None
                ),
                nature="action",
            )
    elif snapshot.input_policy == "PARTIAL":
        # v0.27.0 — accepted by default, with rules that can refuse: which
        # listeners they close is not established (a visibility gap, "≤").
        # v0.29.0, review of the changelog — a chain on the way in at policy
        # drop refuses by default what it does not accept: said, by name.
        result.info(
            message=(_t("firewall_iptables.input_accept_default_drop",
                        chains=", ".join(snapshot.default_drop_before_input))
                     if snapshot.default_drop_before_input
                     else _t("firewall_iptables.input_accept_unweighed")),
            detail=_t("firewall_iptables.input_accept_unweighed_detail"),
            key="firewall_iptables.input_accept_unweighed",
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
            # v0.28.0 — a rule accepting everything sits before the policy:
            # setting it to DROP would change nothing, so no command.
            cmd=(
                None if snapshot.forward_accepts_all
                else "sudo iptables -P FORWARD DROP"
                if snapshot.forward_target == ("iptables",)
                else _nft_drop_policy(snapshot.forward_target) if snapshot.forward_target
                else None
            ),
            detail=_t("firewall_iptables.forward_accept_all_detail") if snapshot.forward_accepts_all else "",
            nature="action",
        )
    elif snapshot.forward_policy in ("DROP", "REJECT"):
        result.ok(
            message=(_t("firewall_iptables.forward_ok_final_rule", policy=snapshot.forward_policy)
                     if snapshot.forward_policy_by_rule
                     else _t("firewall_iptables.forward_ok", policy=snapshot.forward_policy)),
            key="firewall_iptables.forward_ok",
        )
    elif snapshot.forward_policy == "PARTIAL":
        # v0.28.0 — forwarded by default, with rules that can refuse: which
        # traffic they stop is not established (a visibility gap, "≤").
        result.info(
            message=_t("firewall_iptables.forward_accept_unweighed"),
            detail=_t("firewall_iptables.forward_accept_unweighed_detail"),
            key="firewall_iptables.forward_accept_unweighed",
        )
    elif snapshot.forward_policy == "unknown":
        result.info(
            message=_t("firewall_iptables.forward_unknown"),
            key="firewall_iptables.forward_unknown",
        )

    return result
