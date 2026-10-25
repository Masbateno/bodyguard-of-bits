"""v0.27.0 — IPv6 behind UFW's IPV6=no and behind a raw ruleset, read where 0.26.1 stopped.

* With a global IPv6 address, 0.26.1 kept the 0.26.0 reading (a patch moves no
  score). Measured in a network namespace with 2001:db8:b0b::/64: the Mint
  host's shape (INPUT at DROP, jumps to two empty chains) left 8099 closed;
  one chain accepting ICMPv6 and 8099 left it open. The chains are now read on
  every host — the WARN −2 "exposed" lifts where inbound is closed.
* What reaches the IPv6 listeners not established — UFW at IPV6=no with a rule
  BOB does not resolve on INPUT's path, or a raw ruleset whose IPv6 default
  could not be read — marks the score as a ceiling ("≤").
* A raw ruleset's IPv6 families (ip6, inet) are read as its IPv4 ones are.
  Measured with nftables in a network namespace, IPv6 probe from a peer:
  an ip table at policy drop only — open; inet or ip6 at policy drop — closed;
  inet at policy drop behind an accept-everything rule — open; inet at policy
  drop with 8099 accepted — open, read "denied by default" (a per-port accept
  is not weighed, as for IPv4).
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.visibility import is_visibility_key

N1 = "table ip f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
N2 = ("table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy drop;\n"
      "\t\tmeta l4proto ipv6-icmp accept\n\t}\n}\n")
N3 = N2.replace("table inet f", "table ip6 f")
N4 = "table inet f {\n\tchain in {\n\t\ttype filter hook input priority filter; policy drop;\n\t\taccept\n\t}\n}\n"
N5 = N2.replace("ipv6-icmp accept\n", "ipv6-icmp accept\n\t\ttcp dport 8099 accept\n")


def _keys(res):
    return {f.key: f for f in res.findings}


class TestTheRawRulesetIsRead:

    @pytest.mark.parametrize("ruleset, verdict", [(N1, None), (N2, "DROP"), (N3, "DROP"),
                                                  (N4, "ACCEPT"), (N5, "DROP")])
    def test_the_measured_rulesets(self, ruleset, verdict):
        assert nf.nft_input_policy_v6(ruleset) == verdict

    def test_no_ip6_chain_on_nft_then_ip6tables_decides(self, monkeypatch):
        class _R:
            ok, stdout = True, N1
        monkeypatch.setattr(nf, "_command_exists", lambda c: True)
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: _R)
        monkeypatch.setattr(nf, "_run", lambda *a, **k: "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n")
        assert nf.read_input_policy_v6() == "ACCEPT"

    def test_ip6tables_silent_is_unknown(self, monkeypatch):
        class _R:
            ok, stdout = False, ""
        monkeypatch.setattr(nf, "_command_exists", lambda c: True)
        monkeypatch.setattr(nf, "run_result", lambda *a, **k: _R)
        monkeypatch.setattr(nf, "_run", lambda *a, **k: "")
        assert nf.read_input_policy_v6() == "unknown"


def _raw(policy, global_ipv6=True):
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False, ipv6_listeners=["22/tcp"],
                        has_global_ipv6=global_ipv6)
    return check_ipv6(snap, ufw_active=False, netfilter_active=True, netfilter_v6_policy=policy,
                      t=lambda k, **kw: k)


class TestTheRawVerdict:

    def test_denied_by_default(self):
        assert "ipv6.netfilter_v6_filtered" in _keys(_raw("DROP"))

    def test_open_with_a_global_address_weighs(self):
        res = _raw("ACCEPT")
        assert "ipv6.netfilter_v6_open" in _keys(res)
        assert [d.points for d in res.deductions] == [2]

    def test_open_on_link_local_is_reported(self):
        res = _raw("ACCEPT", global_ipv6=False)
        assert "ipv6.netfilter_v6_open_link_local" in _keys(res) and not res.deductions

    def test_unread_is_a_visibility_gap(self):
        assert "ipv6.netfilter_v6" in _keys(_raw("unknown"))
        assert is_visibility_key("ipv6.netfilter_v6")

    @pytest.mark.parametrize("lang, words", [("en", "denies IPv6 inbound by default"),
                                             ("fr", "refuse par défaut l'IPv6 entrant")])
    def test_by_default_is_said(self, lang, words):
        i18n.init(lang)
        try:
            snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False, ipv6_listeners=["22/tcp"])
            res = check_ipv6(snap, ufw_active=False, netfilter_active=True, netfilter_v6_policy="DROP", t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in res.findings)

    def test_the_runner_reads_and_hands_it(self):
        from bob import runner
        src = inspect.getsource(runner)
        assert "_v6_policy = read_input_policy_v6()" in src and "netfilter_v6_policy=_v6_policy" in src


class TestNotEstablishedIsACeiling:

    def test_the_unresolved_ufw_case(self):
        assert is_visibility_key("ipv6.ufw_v6_off_rules_unresolved")

    def test_the_score_says_le(self):
        from bob.scoring import ScoreEngine
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False, ufw_present=True,
                            ipv6_listeners=["22/tcp"], ip6_input_policy="DROP",
                            ip6_input_rules=["-A INPUT -p tcp --dport 22 -j ACCEPT"], ip6_user_chains=frozenset())
        res = check_ipv6(snap, ufw_active=True, t=lambda k, **kw: k)
        assert "ipv6.ufw_v6_off_rules_unresolved" in _keys(res)
        engine = ScoreEngine()
        engine.apply(res, section="ipv6")
        assert engine.score_is_upper_bound


class TestAGlobalAddress:

    MINT = ("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT DROP\n-N LIBVIRT_INP\n-N evpn.INPUT\n"
            "-A INPUT -j evpn.INPUT\n-A INPUT -j LIBVIRT_INP\n-A INPUT -i lo -j ACCEPT\n")

    def _check(self, monkeypatch, listing):
        from bob.checks import ipv6 as m

        class _R:
            ok, stdout = True, listing
        monkeypatch.setattr(m, "run_result", lambda *a, **k: _R)
        policy, rules, chains, shape = m._read_ip6_filter_full()
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False, ipv6_listeners=["22/tcp"],
                            has_global_ipv6=True, ufw_present=True, ip6_input_policy=policy,
                            ip6_input_rules=rules, ip6_user_chains=chains, ip6_ufw_init_shape=shape)
        return check_ipv6(snap, ufw_active=True, t=lambda k, **kw: k)

    def test_closed_through_the_chains_is_blocked(self, monkeypatch):
        res = self._check(monkeypatch, self.MINT)
        assert "ipv6.ufw_v6_off_blocked" in _keys(res) and not res.deductions

    def test_a_chain_admitting_8099_keeps_the_warn(self, monkeypatch):
        res = self._check(monkeypatch, self.MINT + "-A evpn.INPUT -p ipv6-icmp -j ACCEPT\n"
                                                   "-A evpn.INPUT -p tcp -m tcp --dport 8099 -j ACCEPT\n")
        assert "ipv6.ufw_disabled_listeners_present" in _keys(res)
        assert [d.points for d in res.deductions] == [2]
