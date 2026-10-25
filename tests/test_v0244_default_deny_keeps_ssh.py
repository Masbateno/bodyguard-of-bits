"""v0.24.4 — a default-deny fix must not cut the operator off, and must name
the chain the host actually uses.

Measured on Linux Mint 22.3 over SSH (iptables-nft, ufw installed but off), with
a rollback armed first. ALERT ``firewall_iptables.input_accept`` offered
``sudo nft chain inet filter input '{ policy drop; }'``; applied, it failed —
"No such file or directory; did you mean table 'filter' in family ip?" — the
input hook is chain ``INPUT`` in ``table ip filter``, which nft itself flags
as managed by iptables-nft. The iptables form BOB prints on such a host,
``sudo iptables -P INPUT DROP``, succeeded: new SSH connections went
unanswered and the session that ran it froze. ``--fix --apply`` already
refused both unattended (v0.18.0); the printed command had no such guard.
"""

from __future__ import annotations

import pytest

from bob.checks import iptables_nftables as ipt
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from tests.helpers import _t

# `nft list ruleset` on Mint 22.3 (nftables 1.0.9), the input hook's table,
# trimmed. The iptables-nft warning is NOT in stdout: nft writes it to stderr.
_MINT = """table ip filter {
\tchain evpn.INPUT {
\t\tcounter packets 78971 bytes 59497363 jump evpn.a.100.protectLoopback
\t}

\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tcounter packets 78971 bytes 59497363 jump evpn.INPUT
\t}

\tchain evpn.a.100.protectLoopback {
\t}
}
"""
# v0.27.0 — the chain the jump names, which `nft list ruleset` prints in the
# same table; its rules were not part of this 0.24.4 excerpt. BOB now follows
# jumps (a chain it cannot find may refuse), so the excerpt names it, empty.
_MINT_STDERR = ("# Warning: table ip filter is managed by iptables-nft, do not touch!\n"
                "# Warning: table ip mangle is managed by iptables-nft, do not touch!\n"
                "# Warning: table ip6 mangle is managed by iptables-nft, do not touch!\n")
_NATIVE = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t}
}
"""


class TestWhichChainTheHookUses:
    def test_a_table_iptables_nft_manages(self):
        managed = ipt._nft_managed(_MINT_STDERR)
        assert ("ip", "filter") in managed
        assert ipt._nft_hook_target(_MINT, "input", managed) == ("iptables",)

    def test_the_warning_is_read_from_stderr(self):
        """A first draft looked for it in stdout; on Mint it never is."""
        assert ipt._nft_hook_target(_MINT, "input") == ("nft", "ip", "filter", "INPUT")

    def test_a_native_nftables_table(self):
        assert ipt._nft_hook_target(_NATIVE, "input") == ("nft", "inet", "filter", "input")
        assert ipt._nft_hook_target(_NATIVE, "forward") == ("nft", "inet", "filter", "forward")

    def test_an_unmanaged_ip_table(self):
        assert ipt._nft_hook_target(_MINT, "input", frozenset({("ip", "mangle")})) == \
            ("nft", "ip", "filter", "INPUT")

    def test_no_hook(self):
        assert ipt._nft_hook_target("table inet t {\n\tchain c {\n\t}\n}\n", "input") is None

    def test_the_snapshot_reads_it(self):
        import inspect
        src = inspect.getsource(IptablesNftSnapshot.from_system)
        assert 'input_target=_nft_hook_target(raw, "input", _nft_managed(nft_res.stderr)),' in src
        assert 'forward_target=_nft_hook_target(raw, "forward", _nft_managed(nft_res.stderr)),' in src


def _input_cmd(target, ufw_installed=False, ssh_ports=None, **kw):
    snap = IptablesNftSnapshot(backend="nftables" if target and target[0] == "nft" else "iptables",
                               input_policy="ACCEPT", forward_policy="DROP", has_loopback_rule=True,
                               has_conntrack_rule=True, input_target=target, forward_target=target)
    result = check_iptables_nftables(snap, ufw_installed=ufw_installed, t=_t, ssh_ports=ssh_ports, **kw)
    return next(f for f in result.findings if f.key == "firewall_iptables.input_accept").cmd


class TestTheWayInIsAcceptedFirst:
    def test_iptables(self):
        cmd = _input_cmd(("iptables",), ssh_ports=[2222, 22])
        assert cmd == ("sudo iptables -A INPUT -i lo -j ACCEPT && "
                       "sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && "
                       "sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT && "
                       "sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT && "
                       "sudo iptables -P INPUT DROP")

    def test_an_unknown_listening_set_gets_no_command(self):
        """BOB cannot place sshd: a default-deny keeping 22 alone could cut it."""
        assert not _input_cmd(("iptables",), ssh_ports=None)
        assert not _input_cmd(("iptables",), ufw_installed=True, ssh_ports=None)

    def test_nftables_names_the_chain_and_drops_last(self):
        cmd = _input_cmd(("nft", "ip", "filter", "INPUT"), ssh_ports=[22])
        steps = cmd.split(" && ")
        assert steps[-1] == "sudo nft add chain ip filter INPUT '{ policy drop; }'"
        assert "sudo nft add rule ip filter INPUT tcp dport 22 accept" in steps
        assert "sudo nft add rule ip filter INPUT ct state established,related accept" in steps
        assert 'sudo nft add rule ip filter INPUT iif "lo" accept' in steps

    def test_an_unknown_chain_gets_no_command(self):
        assert not _input_cmd(None)

    def test_a_host_with_ufw_gets_ufw(self):
        """Mint: ufw installed, off — the front-end's own enable, SSH allowed first."""
        assert _input_cmd(("iptables",), ufw_installed=True, ssh_ports=[22]) == \
            "sudo ufw allow 22/tcp && sudo ufw enable"


class TestTheOtherFixesNameTheChainToo:
    def _cmd(self, key, **kw):
        base = dict(backend="nftables", input_policy="DROP", forward_policy="DROP", has_loopback_rule=True,
                    has_conntrack_rule=True, input_target=("nft", "ip", "filter", "INPUT"),
                    forward_target=("nft", "ip", "filter", "FORWARD"))
        base.update(kw)
        result = check_iptables_nftables(IptablesNftSnapshot(**base), t=_t)
        return next(f for f in result.findings if f.key == key).cmd

    def test_forward(self):
        assert self._cmd("firewall_iptables.forward_accept", forward_policy="ACCEPT") == \
            "sudo nft add chain ip filter FORWARD '{ policy drop; }'"

    def test_loopback(self):
        assert self._cmd("firewall_iptables.no_loopback", has_loopback_rule=False) == \
            'sudo nft insert rule ip filter INPUT iif "lo" accept'

    def test_conntrack(self):
        assert self._cmd("firewall_iptables.no_conntrack", has_conntrack_rule=False) == \
            "sudo nft insert rule ip filter INPUT ct state established,related accept"

    def test_a_managed_table_is_iptables_business(self):
        assert self._cmd("firewall_iptables.forward_accept", forward_policy="ACCEPT",
                         forward_target=("iptables",)) == "sudo iptables -P FORWARD DROP"


@pytest.mark.parametrize("cmd", ["sudo iptables -I INPUT 1 -i lo -j ACCEPT && sudo iptables -P INPUT DROP",
                                 "sudo nft insert rule ip filter INPUT iif \"lo\" accept && "
                                 "sudo nft add chain ip filter INPUT '{ policy drop; }'"])
def test_still_never_run_unattended(cmd):
    """The way in is now accepted first, but a default-deny stays a human's call."""
    from bob.fixes import _can_apply_unattended
    assert _can_apply_unattended(cmd) is False


class TestEveryBaseChainOnTheHook:
    """Measured on Mint 22.3: iptables-nft's ``ip filter INPUT`` at policy
    accept, and a second base chain on the input hook (``inet bobB``,
    priority 10, policy drop, SSH kept). Port 8080 was closed; BOB, reading the
    first chain, raised "all incoming traffic is allowed" (ALERT −3). BOB's
    fix, applied there, kept SSH: an accept hands the packet on, and the
    second chain kept accepting what it accepted before."""

    _BOBB = """table inet bobB {
\tchain input {
\t\ttype filter hook input priority 10; policy drop;
\t\tiif "lo" accept
\t\tct state established,related accept
\t\ttcp dport 22 accept
\t}
}
"""

    def test_one_dropping_chain_filters_the_hook(self):
        assert ipt._nft_policy(_MINT + self._BOBB, "input") == "DROP"

    def test_every_chain_accepting_is_accept(self):
        assert ipt._nft_policy(_MINT + _NATIVE, "input") == "ACCEPT"


class TestIpv6KeepsWorking:
    def test_an_inet_chain_accepts_neighbour_discovery(self):
        cmd = _input_cmd(("nft", "inet", "filter", "input"), ssh_ports=[22])
        steps = cmd.split(" && ")
        icmp = next(s for s in steps if "icmpv6" in s)
        for kind in ("nd-neighbor-solicit", "nd-neighbor-advert", "nd-router-advert", "packet-too-big"):
            assert kind in icmp
        assert steps.index(icmp) < len(steps) - 1          # before the policy

    def test_an_ip_chain_needs_none(self):
        assert "icmpv6" not in _input_cmd(("nft", "ip", "filter", "INPUT"), ssh_ports=[22])


class TestItSaysItDoesNotLast:
    def _finding(self, target, ufw_installed=False):
        snap = IptablesNftSnapshot(backend="iptables", input_policy="ACCEPT", forward_policy="DROP",
                                   has_loopback_rule=True, has_conntrack_rule=True,
                                   input_target=target, forward_target=target)
        from bob import i18n
        i18n.init("en")
        try:
            result = check_iptables_nftables(snap, ufw_installed=ufw_installed, t=i18n.t, ssh_ports=[22])
        finally:
            i18n.init(lang="en")
        return next(f for f in result.findings if f.key == "firewall_iptables.input_accept")

    def test_the_raw_command_is_runtime_only(self):
        assert "next boot" in self._finding(("iptables",)).detail

    def test_it_promises_no_ssh_the_chain_already_refuses(self):
        """Appended accepts leave earlier rules deciding (measured: the refused
        neighbour stayed refused) — the detail says so rather than promise SSH."""
        assert "still refuses it" in self._finding(("iptables",)).detail

    def test_ufw_saves_its_own(self):
        assert "next boot" not in self._finding(("iptables",), ufw_installed=True).detail


class TestWhatTheHookFiltersForIpv4:
    """Measured on Mint 22.3, iptables-nft's ``ip filter INPUT`` at accept,
    8080 listening, one more base chain at priority 10, policy drop:

    ===================================================  ============  =========
    the extra chain                                      8080 (IPv4)   BOB had
    ===================================================  ============  =========
    ``inet``, an ``accept`` rule before the policy       open          DROP
    ``ip6``, SSH and ICMPv6 kept                         open          DROP
    ``ip``, SSH kept                                     closed        DROP
    ===================================================  ============  =========
    """

    @staticmethod
    def _chain(family, rules, table="bobx"):
        body = "".join(f"\t\t{r}\n" for r in rules)
        return (f"table {family} {table} {{\n\tchain input {{\n"
                f"\t\ttype filter hook input priority 10; policy drop;\n{body}\t}}\n}}\n")

    def test_a_drop_behind_an_accept_everything_rule(self):
        ruleset = _MINT + self._chain("inet", ["counter packets 12 bytes 840 accept"])
        assert ipt._nft_policy(ruleset, "input") == "ACCEPT"

    def test_an_ip6_chain_filters_no_ipv4(self):
        ruleset = _MINT + self._chain("ip6", ['iif "lo" accept', "tcp dport 22 accept"])
        assert ipt._nft_policy(ruleset, "input") == "ACCEPT"

    def test_an_ip_chain_filters_ipv4(self):
        ruleset = _MINT + self._chain("ip", ['iif "lo" accept', "tcp dport 22 accept"])
        assert ipt._nft_policy(ruleset, "input") == "DROP"

    @pytest.mark.parametrize("rule, everything", [
        ("accept", True), ("counter packets 5 bytes 300 accept", True),
        ("tcp dport 22 accept", False), ("ct state established,related accept", False),
    ])
    def test_what_accepts_everything(self, rule, everything):
        assert ipt._accepts_everything(rule) is everything

    def test_the_fix_targets_an_ipv4_chain(self):
        ruleset = self._chain("ip6", ["tcp dport 22 accept"], table="six") + _NATIVE
        assert ipt._nft_hook_target(ruleset, "input") == ("nft", "inet", "filter", "input")


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_explain_entry_accepts_the_way_in_before_the_nft_policy(lang):
    """Its nft step was the bare policy on an assumed inet filter table — the
    command measured failing, and cutting, on Mint."""
    import json
    from pathlib import Path
    how = json.loads(Path(f"bob/locales/{lang}.json").read_text())["explain"]["firewall_iptables"]["input_accept"]["how"]
    nft = how[how.index("3."):]
    assert nft.index("tcp dport 22 accept") < nft.index("policy drop")
    assert "nd-neighbor-solicit" in nft and "iptables-nft" in nft and "/etc/nftables.conf" in nft


def test_a_later_chain_refusing_new_ssh_gets_no_fix_to_cut_it():
    """Measured on Mint: a second ``inet`` chain (priority 10, policy drop)
    keeping loopback and established traffic only refused new SSH connections
    before any fix — and BOB read the hook as DROP and offered no input fix,
    so its fix cannot be the thing that cuts them."""
    later = ("table inet bobE {\n\tchain input {\n\t\ttype filter hook input priority 10; policy drop;\n"
             "\t\tiif \"lo\" accept\n\t\tct state established,related accept\n\t}\n}\n")
    ruleset = _MINT + later
    snap = IptablesNftSnapshot(backend="nftables", input_policy=ipt._nft_policy(ruleset, "input"),
                               forward_policy="DROP", has_loopback_rule=True, has_conntrack_rule=True,
                               input_target=ipt._nft_hook_target(ruleset, "input"))
    keys = {f.key for f in check_iptables_nftables(snap, t=_t, ssh_ports=[22]).findings}
    assert "firewall_iptables.input_ok" in keys and "firewall_iptables.input_accept" not in keys


@pytest.mark.parametrize("lang, needle", [("en", "is not established here"), ("fr", "n'est pas établi ici")])
def test_input_ok_says_it_reads_policies_not_reachability(lang, needle):
    """A later chain can refuse new SSH connections while the hook reads DROP:
    the OK states what it rests on, not that SSH gets through."""
    from bob import i18n
    snap = IptablesNftSnapshot(backend="nftables", input_policy="DROP", forward_policy="DROP",
                               has_loopback_rule=True, has_conntrack_rule=True,
                               input_target=("nft", "inet", "filter", "input"))
    i18n.init(lang)
    try:
        ok = next(f for f in check_iptables_nftables(snap, t=i18n.t, ssh_ports=[22]).findings
                  if f.key == "firewall_iptables.input_ok")
    finally:
        i18n.init(lang="en")
    assert needle in ok.detail


class TestTheRulesAlreadyThere:
    """Measured on a Fedora 43 VM, a native ``inet`` chain at policy accept, a
    neighbour at 10.99.0.2 in a network namespace:

    - with ``ip saddr 10.99.0.2 tcp dport 22 drop`` in the chain, the neighbour
      was refused; BOB's fix, its accepts inserted at the top, let it in — and
      BOB then said INPUT DROP, OK;
    - with a rule accepting everything, the fix changed nothing: 8080 stayed
      open, the finding came back."""

    def test_no_insert_ahead_of_the_administrators_rules(self):
        for target in (("iptables",), ("nft", "inet", "bobT", "input")):
            cmd = _input_cmd(target, ssh_ports=[22])
            assert " -I " not in cmd and "insert rule" not in cmd
            assert ("-A INPUT" in cmd) or ("nft add rule" in cmd)

    def test_an_accept_everything_rule_gets_no_command(self):
        from bob import i18n
        snap = IptablesNftSnapshot(backend="nftables", input_policy="ACCEPT", forward_policy="DROP",
                                   has_loopback_rule=True, has_conntrack_rule=True,
                                   input_target=("nft", "inet", "bobT", "input"), input_accepts_all=True)
        i18n.init("en")
        try:
            f = next(f for f in check_iptables_nftables(snap, t=i18n.t, ssh_ports=[22]).findings
                     if f.key == "firewall_iptables.input_accept")
        finally:
            i18n.init(lang="en")
        assert not f.cmd and "would change nothing" in f.detail

    def test_the_snapshot_sees_it(self):
        ruleset = ("table inet bobT {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n"
                   "\t\taccept\n\t}\n}\n")
        assert ipt._nft_first_ipv4_chain_accepts_all(ruleset, "input") is True
        assert ipt._nft_first_ipv4_chain_accepts_all(_NATIVE, "input") is False
        import inspect
        src = inspect.getsource(IptablesNftSnapshot.from_system)
        assert 'input_accepts_all=_nft_first_ipv4_chain_accepts_all(raw, "input"),' in src
        assert 'input_accepts_all=bool(re.search(r"^-A INPUT -j ACCEPT\\s*$", raw, re.MULTILINE)),' in src


class TestAnIptablesChainAcceptingEverything:
    """v0.25.0 — measured on a Fedora 43 VM, iptables-legacy: ``-P INPUT
    DROP`` then ``-A INPUT -j ACCEPT``; 8080 answered from the LAN and BOB
    read DROP (a false OK)."""

    _RULES = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -j ACCEPT\n"

    def test_the_policy_is_never_reached(self):
        assert ipt._ipt_effective_input_policy(self._RULES) == "ACCEPT"

    def test_a_narrower_accept_leaves_the_policy(self):
        rules = "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
        assert ipt._ipt_effective_input_policy(rules) == "DROP"

    def test_the_snapshot_reads_it(self):
        import inspect
        assert "input_policy=_ipt_effective_input_policy(raw)," in inspect.getsource(IptablesNftSnapshot.from_system)
