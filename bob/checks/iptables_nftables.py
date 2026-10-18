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
        if nft_present:
            nft_res = run_result("nft", "list", "ruleset")
            nft_answered, raw = nft_res.ok, nft_res.stdout
            if raw and "hook input" in raw:
                return cls(
                    backend="nftables",
                    input_policy=_nft_policy(raw, "input"),
                    forward_policy=_nft_policy(raw, "forward"),
                    has_loopback_rule=_nft_has_loopback(raw),
                    has_conntrack_rule=_nft_has_conntrack(raw),
                    raw_output=raw,
                    input_target=_nft_hook_target(raw, "input", _nft_managed(nft_res.stderr)),
                    forward_target=_nft_hook_target(raw, "forward", _nft_managed(nft_res.stderr)),
                    input_accepts_all=_nft_first_ipv4_chain_accepts_all(raw, "input"),
                )

        # --- fall back to iptables ---
        if _command_exists("iptables"):
            raw = _run("iptables", "-S")
            if raw:
                return cls(
                    backend="iptables",
                    input_policy=_ipt_effective_input_policy(raw),
                    forward_policy=_ipt_policy(raw, "FORWARD"),
                    has_loopback_rule=_ipt_has_loopback(raw),
                    has_conntrack_rule=_ipt_has_conntrack(raw),
                    raw_output=raw,
                    input_target=("iptables",),
                    forward_target=("iptables",),
                    input_accepts_all=bool(re.search(r"^-A INPUT -j ACCEPT\s*$", raw, re.MULTILINE)),
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
    effective = ["ACCEPT" if any(_accepts_everything(r) for r in c["rules"]) else c["policy"]
                 for c in chains if c["family"] in _IPV4_FAMILIES]
    for restrictive in ("DROP", "REJECT"):
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
    """
    return bool(re.search(r'\biif(?:name)?\s+"?lo"?\s+accept', ruleset, re.IGNORECASE))


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
    if re.search(r"^-A INPUT -j ACCEPT\s*$", rules, re.MULTILINE):
        return "ACCEPT"
    return _ipt_policy(rules, "INPUT")


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
            message=_t("firewall_iptables.input_ok", policy=snapshot.input_policy),
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
            cmd=(
                "sudo iptables -P FORWARD DROP"
                if snapshot.forward_target == ("iptables",)
                else _nft_drop_policy(snapshot.forward_target) if snapshot.forward_target
                else None
            ),
            nature="action",
        )
    elif snapshot.forward_policy in ("DROP", "REJECT"):
        result.ok(
            message=_t("firewall_iptables.forward_ok", policy=snapshot.forward_policy),
            key="firewall_iptables.forward_ok",
        )
    elif snapshot.forward_policy == "unknown":
        result.info(
            message=_t("firewall_iptables.forward_unknown"),
            key="firewall_iptables.forward_unknown",
        )

    return result
