"""v0.26.1 — the IPv6 INPUT chain is followed into its user chains.

Measured on Mint 22.3 (ufw 0.36.2, IPV6=no): ip6tables INPUT was -P DROP with
-j evpn.INPUT (ExpressVPN), -j LIBVIRT_INP (libvirt) and -i lo -j ACCEPT, both
user chains empty — IPv6 inbound closed. 0.26.0 said it could not show whether
the LAN reached [::]:22, and the ports section said every port on every
interface was filtered by UFW, which it had not established for IPv6.

Bench (network namespace, IPv6 probe from a peer): that shape — closed, BOB
"blocked"; the chain accepting ICMPv6 and 8099/tcp — open, BOB withholds; the
chain accepting ICMPv6 only — closed, BOB withholds (an ACCEPT); the chain
dropping — closed, BOB "blocked".
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import ipv6 as ipv6_mod
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from tests.helpers import _keys, _t

MINT = ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n-N LIBVIRT_INP\n-N evpn.INPUT\n"
        "-A INPUT -j evpn.INPUT\n-A INPUT -j LIBVIRT_INP\n-A INPUT -i lo -j ACCEPT\n")


class _R:
    def __init__(self, ok, stdout=""):
        self.ok, self.stdout = ok, stdout


def _through_the_reader(monkeypatch, listing, t=None):
    monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: _R(True, listing))
    policy, rules, chains, shape = ipv6_mod._read_ip6_filter_full()
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False, ipv6_listeners=["22/tcp"],
                        has_global_ipv6=False, ufw_present=True, ip6_input_policy=policy,
                        ip6_input_rules=rules, ip6_user_chains=chains, ip6_ufw_init_shape=shape)
    return check_ipv6(snap, ufw_active=True, t=t or _t)


def test_the_mint_shape_is_blocked(monkeypatch):
    assert "ipv6.ufw_v6_off_blocked" in _keys(_through_the_reader(monkeypatch, MINT))


@pytest.mark.parametrize("rules, blocked", [
    ("-A evpn.INPUT -p ipv6-icmp -j ACCEPT\n-A evpn.INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n", False),
    ("-A evpn.INPUT -p ipv6-icmp -j ACCEPT\n", False),
    ("-A evpn.INPUT -j DROP\n", True),
    ("-A evpn.INPUT -p tcp -j REJECT --reject-with tcp-reset\n-A evpn.INPUT -j RETURN\n", True),
    # After review, measured on the bench: LOG and RETURN decide nothing —
    # LOG, then an ACCEPT: open; RETURN, then an ACCEPT in INPUT: open.
    ("-A evpn.INPUT -j LOG\n-A evpn.INPUT -p ipv6-icmp -j ACCEPT\n"
     "-A evpn.INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n", False),
    ("-A evpn.INPUT -j RETURN\n-A INPUT -p ipv6-icmp -j ACCEPT\n"
     "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n", False),
    ("-A evpn.INPUT -j LOG\n-A evpn.INPUT -j RETURN\n", True),
])
def test_what_the_chain_holds_decides(monkeypatch, rules, blocked):
    assert ("ipv6.ufw_v6_off_blocked" in _keys(_through_the_reader(monkeypatch, MINT + rules))) is blocked


def test_a_return_in_input_itself_withholds(monkeypatch):
    """After review, measured on the bench: a RETURN in INPUT applies the DROP
    policy — the ACCEPT after it never runs, 8099 stayed closed. BOB weighs the
    rules after it anyway: too cautious, never a false "blocked"."""
    listing = ("-P INPUT DROP\n-A INPUT -j RETURN\n-A INPUT -p ipv6-icmp -j ACCEPT\n"
               "-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n")
    assert "ipv6.ufw_v6_off_blocked" not in _keys(_through_the_reader(monkeypatch, listing))


def test_a_chain_not_read_withholds(monkeypatch):
    calls = []
    def fake(*a, **k):
        calls.append(a)
        return _R(False) if a == ("ip6tables", "-S") else _R(True, MINT)
    monkeypatch.setattr(ipv6_mod, "run_result", fake)
    policy, rules, chains = ipv6_mod._read_ip6_filter()
    assert chains is None and rules == ["-A INPUT -j evpn.INPUT", "-A INPUT -j LIBVIRT_INP",
                                        "-A INPUT -i lo -j ACCEPT"]
    snap = IPv6Snapshot(ufw_ipv6_enabled=False, ip6_input_policy=policy, ip6_input_rules=rules,
                        ip6_user_chains=chains)
    assert not ipv6_mod._ipv6_input_closed(snap)


def _ports(ipv6_unproven):
    lp = ListeningPort(port=22, proto="tcp", address="0.0.0.0", raw_line="", process="sshd")
    res = check_ports(PortsSnapshot(ports=[lp], ufw_rules="", ss_output=""), ufw_active=True,
                      default_incoming_policy="deny", t=_t, ipv6_unproven=ipv6_unproven)
    return next(f.message for f in res.findings if f.key == "ports.all_covered")


def test_the_ports_ok_speaks_for_ipv4_when_ipv6_is_not_established():
    assert _ports(True) == "ports.all_covered_policy_ipv4"
    assert _ports(False) == "ports.all_covered_policy"


def test_the_runner_hands_the_ipv6_verdict():
    from bob import runner
    src = inspect.getsource(runner)
    assert "and not _ipv6_input_closed(ipv6_snapshot,\n" in src
    assert "extended=not ipv6_snapshot.has_global_ipv6))," in src
    assert "ipv6_unproven=(ipv6_snapshot.ufw_ipv6_enabled is False" in src


@pytest.mark.parametrize("lang, words", [("en", "over IPv4"), ("fr", "en IPv4")])
def test_the_ok_renders(lang, words):
    i18n.init(lang)
    try:
        text = i18n.t("ports.all_covered_policy_ipv4")
    finally:
        i18n.init(lang="en")
    assert words in text and "IPV6=no" in text


def test_with_a_global_address_the_0260_reading_stands(monkeypatch):
    """A patch moves no score: with a global IPv6 address the extended reading
    would lift the WARN −2 — it waits for 0.27.0 (decided 22 October 2026)."""
    monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: _R(True, MINT))
    policy, rules, chains = ipv6_mod._read_ip6_filter()
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False, ipv6_listeners=["22/tcp"],
                        has_global_ipv6=True, ufw_present=True, ip6_input_policy=policy,
                        ip6_input_rules=rules, ip6_user_chains=chains)
    keys = _keys(check_ipv6(snap, ufw_active=True, t=_t))
    assert "ipv6.ufw_v6_off_blocked" not in keys and "ipv6.ufw_disabled_listeners_present" in keys


class TestWhoClosesIt:
    """After review: closed through ExpressVPN's and libvirt's chains is not
    "UFW drops all IPv6 traffic", and with OUTPUT unread, not "IPv6 is
    unusable". The ufw-init shape keeps its 0.24.2 text; the extended verdict
    says what was read."""

    def test_the_mint_shape_names_the_chains(self, monkeypatch):
        res = _through_the_reader(monkeypatch, MINT)
        f = next(x for x in res.findings if x.key == "ipv6.ufw_v6_off_blocked")
        assert f.message == "ipv6.ufw_v6_off_blocked_chains"
        assert f.detail == "ipv6.ufw_v6_off_blocked_chains_detail"

    # Measured in a network namespace, ufw 0.36.2 with IPV6=no: `ip6tables -S`.
    UFW_INIT = ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n"
                "-A INPUT -i lo -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\n")

    def test_the_whole_ufw_init_shape_keeps_its_text(self, monkeypatch):
        res = _through_the_reader(monkeypatch, self.UFW_INIT)
        f = next(x for x in res.findings if x.key == "ipv6.ufw_v6_off_blocked")
        assert f.message == "ipv6.ufw_v6_off_blocked"

    @pytest.mark.parametrize("rest", [
        "-P FORWARD DROP\n-P OUTPUT ACCEPT\n",                   # outbound left open
        "-P FORWARD DROP\n-P OUTPUT DROP\n-A OUTPUT -j evpn.OUTPUT\n-N evpn.OUTPUT\n",  # another tool there
        # After review: FORWARD is part of the claim too — open, not ufw-init's.
        "-P FORWARD ACCEPT\n-P OUTPUT DROP\n-A OUTPUT -o lo -j ACCEPT\n",
    ])
    def test_input_alone_in_shape_says_inbound_only(self, monkeypatch, rest):
        """After review: the 0.24.2 text says "IPv6 is unusable", which only the
        whole table establishes — INPUT in ufw-init's shape is not enough."""
        listing = "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n" + rest
        f = next(x for x in _through_the_reader(monkeypatch, listing).findings
                 if x.key == "ipv6.ufw_v6_off_blocked")
        assert f.message == "ipv6.ufw_v6_off_blocked_chains"

    @pytest.mark.parametrize("lang, words", [("en", "outbound is not established"),
                                             ("fr", "en sortie par cet hôte n'est pas établi")])
    def test_the_text_renders_the_chains(self, monkeypatch, lang, words):
        i18n.init(lang)
        try:
            res = _through_the_reader(monkeypatch, MINT, t=i18n.t)
            f = next(x for x in res.findings if x.key == "ipv6.ufw_v6_off_blocked")
        finally:
            i18n.init(lang="en")
        assert "evpn.INPUT, LIBVIRT_INP" in f.message and words in f.detail   # INPUT's order
        assert "unusable" not in f.message and "inutilisable" not in f.message
        assert "{" not in f.message

    def test_the_ports_ok_does_not_credit_ufw(self):
        lp = ListeningPort(port=22, proto="tcp", address="0.0.0.0", raw_line="", process="sshd")
        res = check_ports(PortsSnapshot(ports=[lp], ufw_rules="", ss_output=""), ufw_active=True,
                          default_incoming_policy="deny", t=_t, ipv6_closed_by_chains=True)
        assert next(f.message for f in res.findings if f.key == "ports.all_covered") \
            == "ports.all_covered_policy_ipv6_closed"

    def test_the_runner_hands_it(self):
        from bob import runner
        assert "ipv6_closed_by_chains=ipv6_closed_by_chains(ipv6_snapshot)," in inspect.getsource(runner)



@pytest.mark.parametrize("lang, words", [("en", "beyond loopback"), ("fr", "hors boucle locale")])
def test_the_ufw_init_text_keeps_loopback_out_of_the_claim(lang, words):
    """After review: with IPV6=no ufw-init still accepts loopback (measured),
    so the claim is "no IPv6 connectivity beyond loopback", not "unusable"."""
    i18n.init(lang)
    try:
        text = i18n.t("ipv6.ufw_v6_off_blocked", count=1)
    finally:
        i18n.init(lang="en")
    assert words in text and "unusable" not in text and "inutilisable" not in text


_GOTO_BASE = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N A\n-N B\n-A INPUT -i lo -j ACCEPT\n"


@pytest.mark.parametrize("rules, kernel, blocked", [
    # After review round 12, each measured in a network namespace (8099 probed).
    ("-A INPUT -j A\n-A INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n-A A -g B\n-A A -j DROP\n-A B -j RETURN\n",
     "open", False),          # RETURN after a goto resumes INPUT, past A's DROP
    ("-A INPUT -j A\n-A A -g B\n-A A -p tcp -m tcp --dport 8099 -j ACCEPT\n-A B -j RETURN\n",
     "closed", False),        # the goto skips A's ACCEPT; BOB withholds — cautious, never false
    ("-A INPUT -j A\n-A A -j B\n-A A -p tcp -m tcp --dport 8099 -j ACCEPT\n-A B -j RETURN\n",
     "open", False),          # the same with -j: RETURN resumes A, its ACCEPT runs
    ("-A INPUT -j A\n-A A -g B\n-A B -j DROP\n", "closed", True),
    ("-A INPUT -j A\n-A A -g B\n-A B -p tcp -m tcp --dport 8099 -j ACCEPT\n", "open", False),
])
def test_a_goto_never_gives_a_false_blocked(monkeypatch, rules, kernel, blocked):
    """"blocked" needs no admitting rule in any chain reached, by -j or -g: how
    a RETURN resumes after a goto cannot turn an open path into a closed one."""
    got = "ipv6.ufw_v6_off_blocked" in _keys(_through_the_reader(monkeypatch, _GOTO_BASE + rules))
    assert got is blocked
    assert not (got and kernel == "open")
