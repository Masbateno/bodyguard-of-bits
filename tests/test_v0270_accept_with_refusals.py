"""v0.27.0 — an inbound policy of accept with rules that refuse is not "open".

Found by the external review of the 0.27.0 changelog, then measured in a
network namespace (24 October 2026), nftables and iptables, IPv4 and IPv6
alike: an input chain at policy accept with a drop for 8099 (`tcp dport 8099
drop`, `-p tcp --dport 8099 -j DROP`), or a jump to a chain dropping 8099, left
8099 closed — and BOB read "accept": for IPv4 the ALERT −3 "all incoming traffic
is allowed" and, with no UFW nor firewalld, "no firewall" capped at 3/10; for
IPv6 the new WARN −2. A jump to a chain that only accepts, an empty chain, a log
rule, `ct state invalid drop` alone and a comment saying "drop" left 8099 open.

A refusal limited to some sources is not one: measured the same way, fail2ban's
shapes (`ip saddr @set reject`, a jump to a chain of `-s … -j REJECT`), `ip
saddr 10.77.0.99 drop`, `-s … -j DROP` and the loopback guard `iifname != "lo"
ip daddr 127.0.0.0/8 drop` left 8099 open to the others; a negated source
(`ip saddr != …`, `! -s …`) closed it.

Such a ruleset now reads PARTIAL: accepted by default, with refusals BOB does
not weigh port by port — not established, the score a ceiling ("≤").
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf
from bob.checks.firewall import FirewallStatus, check_firewall, resolve_firewall_posture
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.visibility import is_visibility_key


def _inet(*rules, extra=""):
    body = "".join(f"\t\t{r}\n" for r in rules)
    return ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy accept;\n"
            f"{body}\t}}\n{extra}}}\n")


X_DROPS = "\tchain x {\n\t\ttcp dport 8099 drop\n\t}\n"
X_ACCEPTS = "\tchain x {\n\t\taccept\n\t}\n"

NFT = {
    "A1": (_inet("tcp dport 8099 drop"), "PARTIAL"),
    "A2": (_inet("jump x", extra=X_DROPS), "PARTIAL"),
    "A3": (_inet("jump x", extra=X_ACCEPTS), "ACCEPT"),
    "A4": (_inet(), "ACCEPT"),
    "A5": (_inet("tcp dport 8099 log"), "ACCEPT"),
    "A6": (_inet("ct state invalid drop"), "ACCEPT"),
    "A7": (_inet('tcp dport 8099 counter packets 0 bytes 0 comment "drop later"'), "ACCEPT"),
}

NFT.update({
    "S1": (_inet("tcp dport 8099 ip saddr 10.77.0.99 drop"), "ACCEPT"),
    "S2": (_inet("ip saddr != 10.77.0.99 tcp dport 8099 drop"), "PARTIAL"),
    "S3": (_inet('iifname != "lo" ip daddr 127.0.0.0/8 drop'), "ACCEPT"),
    "S4": (_inet("tcp dport 8099 ip saddr @banned reject"), "ACCEPT"),
    "S1v6": (_inet("tcp dport 8099 ip6 saddr fd00::99 drop"), "ACCEPT"),
})

def _chain(family, table, prio, policy, *rules):
    body = "".join(f"\t\t{r}\n" for r in rules)
    return (f"table {family} {table} {{\n\tchain in {{\n\t\ttype filter hook input priority {prio}; "
            f"policy {policy};\n{body}\t}}\n}}\n")


#: Found by the third review — several base chains on input, measured in a
#: network namespace: each reads as its packets met them.
MULTI = {
    "M1": (_chain("inet", "a", 0, "accept") + _chain("inet", "b", 10, "accept", "tcp dport 8099 drop"),
           "PARTIAL", "PARTIAL"),
    "M2": (_chain("inet", "a", 0, "accept", "tcp dport 8099 drop") + _chain("inet", "b", -10, "accept", "accept"),
           "PARTIAL", "PARTIAL"),
    "M3": (_chain("inet", "a", 0, "accept", "accept")
           + _chain("inet", "b", 10, "drop", "meta l4proto ipv6-icmp accept"), "DROP", "DROP"),
    "M4": (_chain("ip", "a", 0, "accept", "tcp dport 8099 drop") + _chain("inet", "b", 10, "accept"),
           "PARTIAL", "ACCEPT"),
}

IPT_HEAD = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
IPT = {
    "I1": (IPT_HEAD + "-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n", "PARTIAL"),
    "I2": (IPT_HEAD + "-N X\n-A INPUT -j X\n-A X -p tcp -m tcp --dport 8099 -j DROP\n", "PARTIAL"),
    "I3": (IPT_HEAD + "-N X\n-A INPUT -j X\n-A X -j ACCEPT\n", "ACCEPT"),
    "I4": (IPT_HEAD + "-A INPUT -m conntrack --ctstate INVALID -j DROP\n", "ACCEPT"),
    "T1": (IPT_HEAD + "-A INPUT -s 10.77.0.99/32 -p tcp -m tcp --dport 8099 -j DROP\n", "ACCEPT"),
    "T2": (IPT_HEAD + "-A INPUT ! -s 10.77.0.99/32 -p tcp -m tcp --dport 8099 -j DROP\n", "PARTIAL"),
    "T3": (IPT_HEAD + "-N f2b-sshd\n-A INPUT -p tcp -m multiport --dports 8099 -j f2b-sshd\n"
           "-A f2b-sshd -s 10.77.0.99/32 -j REJECT --reject-with icmp-port-unreachable\n-A f2b-sshd -j RETURN\n",
           "ACCEPT"),
    "T4": (IPT_HEAD + "-A INPUT -p tcp -m set --match-set f2b-sshd src -j REJECT\n", "ACCEPT"),
}


class TestTheMeasuredRulesets:

    @pytest.mark.parametrize("name", list(NFT))
    def test_nftables_both_families(self, name):
        ruleset, verdict = NFT[name]
        assert nf._nft_policy(ruleset, "input") == verdict
        assert nf.nft_input_policy_v6(ruleset) == verdict

    @pytest.mark.parametrize("name", list(MULTI))
    def test_several_base_chains(self, name):
        ruleset, v4, v6 = MULTI[name]
        assert nf._nft_policy(ruleset, "input") == v4
        assert nf.nft_input_policy_v6(ruleset) == v6

    @pytest.mark.parametrize("name", list(IPT))
    def test_iptables_s(self, name):
        rules, verdict = IPT[name]
        assert nf._ipt_effective_input_policy(rules) == verdict

    def test_an_accept_all_after_a_refusal_is_partial(self):
        assert nf._nft_policy(_inet("tcp dport 8099 drop", "accept"), "input") == "PARTIAL"
        assert nf._ipt_effective_input_policy(
            IPT_HEAD + "-A INPUT -p tcp -m tcp --dport 8099 -j DROP\n-A INPUT -j ACCEPT\n") == "PARTIAL"

    def test_a_drop_policy_stays_drop(self):
        ruleset = _inet("tcp dport 8099 drop").replace("policy accept", "policy drop")
        assert nf._nft_policy(ruleset, "input") == "DROP"

    def test_a_jump_to_a_chain_bob_cannot_find_may_refuse(self):
        assert nf._nft_policy(_inet("jump nowhere"), "input") == "PARTIAL"

    def test_a_loop_of_jumps_ends(self):
        loop = "\tchain x {\n\t\tjump y\n\t}\n\tchain y {\n\t\tjump x\n\t}\n"
        assert nf._nft_policy(_inet("jump x", extra=loop), "input") == "ACCEPT"

    def test_forward_keeps_its_reading(self):
        ruleset = _inet("tcp dport 8099 drop").replace("hook input", "hook forward")
        assert nf._nft_policy(ruleset, "forward") == "ACCEPT"


def _snap(policy):
    return IptablesNftSnapshot(backend="nftables", input_policy=policy, forward_policy="DROP",
                               has_loopback_rule=True, has_conntrack_rule=True)


def _keys(res):
    return {f.key for f in res.findings}


class TestWhatIsSaid:

    def test_ipv4_partial_is_a_ceiling_not_an_alert(self):
        res = check_iptables_nftables(_snap("PARTIAL"), t=lambda k, **kw: k)
        assert "firewall_iptables.input_accept_unweighed" in _keys(res)
        assert "firewall_iptables.input_accept" not in _keys(res)
        assert not res.deductions
        assert is_visibility_key("firewall_iptables.input_accept_unweighed")

    def test_ipv4_accept_keeps_its_alert(self):
        res = check_iptables_nftables(_snap("ACCEPT"), t=lambda k, **kw: k)
        assert "firewall_iptables.input_accept" in _keys(res)

    def test_no_front_end_and_a_partial_ruleset_is_not_no_firewall(self):
        status = FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                                ufw_output="", numbered_output="", ipv6_ufw_enabled=False)
        res = check_firewall(status, firewalld=None, netfilter_protective=False,
                             netfilter_partial=True, t=lambda k, **kw: k)
        assert "firewall.netfilter_unweighed" in _keys(res)
        assert "prerequisites.firewall_missing" not in _keys(res)
        assert not res.caps
        assert is_visibility_key("firewall.netfilter_unweighed")

    def test_the_posture_is_netfilter_partial(self):
        status = FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                                ufw_output="", numbered_output="", ipv6_ufw_enabled=False)
        posture = resolve_firewall_posture(status, None, "PARTIAL")
        assert (posture.backend, posture.policy) == ("netfilter", "partial")

    def test_ipv6_partial_is_a_ceiling_not_a_warn(self):
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False, ipv6_listeners=["22/tcp"],
                            has_global_ipv6=True)
        res = check_ipv6(snap, ufw_active=False, netfilter_active=True, netfilter_v6_policy="PARTIAL",
                         t=lambda k, **kw: k)
        assert "ipv6.netfilter_v6" in _keys(res) and not res.deductions

    @pytest.mark.parametrize("lang, words", [("en", "refuses some of it"), ("fr", "en refuse une partie")])
    def test_the_ipv6_text_says_it(self, lang, words):
        i18n.init(lang)
        try:
            snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False, ipv6_listeners=["22/tcp"])
            res = check_ipv6(snap, ufw_active=False, netfilter_active=True, netfilter_v6_policy="PARTIAL",
                             t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in res.findings)

    def test_the_runner_hands_it_and_keeps_deny_texts_for_deny(self):
        from bob import runner
        src = inspect.getsource(runner)
        assert "netfilter_partial=_netfilter_partial" in src
        assert '_netfilter_denies = fw_posture.backend == "netfilter" and fw_posture.policy in ("deny", "reject")' in src
        assert src.count("netfilter_active=_netfilter_denies") == 2


class TestThePortsAndTheSummary:
    """Measured in the namespace render: with a PARTIAL ruleset dropping 8099,
    the ports section said "8099/tcp … no active firewall to filter it" and the
    summary "default inbound policy not read" — neither was so."""

    @staticmethod
    def _ports(address="0.0.0.0"):
        from bob.checks.ports import ListeningPort, PortsSnapshot
        lp = ListeningPort(port=8099, proto="tcp", address=address, raw_line="")
        return PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")

    @pytest.mark.parametrize("address, key", [("0.0.0.0", "ports.uncovered_netfilter_unweighed"),
                                              ("192.0.2.10", "ports.uncovered_bound_address_netfilter_unweighed")])
    def test_ports(self, address, key):
        from bob.checks.ports import check_ports
        res = check_ports(self._ports(address), ufw_active=False, netfilter_partial=True, t=lambda k, **kw: k)
        assert key in _keys(res)
        assert "ports.uncovered_ufw_inactive" not in _keys(res)

    def test_service_exposure(self):
        from bob.checks.services import Exposure, _check_port_exposure
        from bob.scoring import CheckResult
        res = CheckResult()
        _check_port_exposure(None, "22/tcp", Exposure.NO_RULE, res, "local", False,
                             lambda k, **kw: f"{k}|{kw.get('exposure', '')}", netfilter_partial=True)
        assert "no_rule_netfilter_unweighed" in res.findings[0].message

    def test_the_summary(self):
        from bob.checks.ports import PortsSnapshot
        from bob.exposure import compute_exposure
        from bob.scoring import ScoreEngine

        class _NC:
            def __getattr__(self, _a):
                return None
        items = compute_exposure(ScoreEngine(), PortsSnapshot(ports=[], ufw_rules="", ss_output=""), _NC(),
                                 True, "partial", lambda k, **kw: k, fw_backend="netfilter")
        assert next(i for i in items if i.label == "exposure.firewall").detail == "exposure.firewall_policy_partial"

    def test_the_runner_hands_it_to_both(self):
        from bob import runner
        assert inspect.getsource(runner).count("netfilter_partial=_netfilter_partial,") == 3
