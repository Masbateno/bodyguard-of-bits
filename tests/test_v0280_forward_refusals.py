"""v0.28.0 — the forward hook is read as the input hook is.

0.27.0 weighed the rules that can refuse on input and wrote down the limit:
"the forward hook keeps the 0.26.0 reading". Measured in network namespaces
(25 October 2026), a router between two veths, 8099 and 9000 listening behind
it:

- FORWARD at policy accept with `-p tcp --dport 8099 -j DROP`, a jump to a
  chain dropping 8099, nft's `tcp dport 8099 drop` or `jump x` (x drops 8099):
  8099 refused, 9000 forwarded — and BOB said "transit traffic is not
  filtered" (WARN −1);
- a drop for one source (`-s 10.10.0.9 -j DROP`), a log rule, nothing at all:
  both forwarded — "accept" is right there;
- `-P FORWARD DROP` then `-A FORWARD -j ACCEPT`, read through `iptables -S`
  (nft hidden): both forwarded — and BOB said "Default FORWARD policy: DROP
  (recommended)". nft's reading already saw the final accept.

Forward now reads PARTIAL when a rule can refuse (not established, a ceiling),
and through `iptables -S` as packets meet FORWARD.
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import iptables_nftables as nf
from bob.checks.iptables_nftables import IptablesNftSnapshot, check_iptables_nftables
from bob.visibility import is_visibility_key


def _fw(*rules, policy="accept", extra=""):
    body = "".join(f"\t\t{r}\n" for r in rules)
    return ("table inet f {\n\tchain fw {\n"
            f"\t\ttype filter hook forward priority filter; policy {policy};\n{body}\t}}\n{extra}}}\n")


X_DROPS = "\n\tchain x {\n\t\ttcp dport 8099 drop\n\t}\n"


def _ipt(policy, *rules):
    return "\n".join(["-P INPUT DROP", f"-P FORWARD {policy}", "-P OUTPUT ACCEPT", *rules]) + "\n"


class TestTheMeasuredRulesets:

    @pytest.mark.parametrize("ruleset, verdict", [
        (_fw("tcp dport 8099 drop"), "PARTIAL"),                       # F4
        (_fw("jump x", extra=X_DROPS), "PARTIAL"),                     # F5
        (_fw("ip saddr 10.10.0.9 drop"), "ACCEPT"),                    # one source
        (_fw("log"), "ACCEPT"),
        (_fw(), "ACCEPT"),
        (_fw("accept", policy="drop"), "ACCEPT"),                      # F1, nft
        (_fw("tcp dport 9000 accept", policy="drop"), "DROP"),         # F9
    ], ids=["port-drop", "jump-drop", "one-source", "log", "nothing", "final-accept", "drop-policy"])
    def test_nftables(self, ruleset, verdict):
        assert nf._nft_policy(ruleset, "forward") == verdict

    @pytest.mark.parametrize("rules, verdict", [
        (_ipt("ACCEPT", "-A FORWARD -p tcp -m tcp --dport 8099 -j DROP"), "PARTIAL"),              # F2
        (_ipt("ACCEPT", "-N X", "-A FORWARD -j X", "-A X -p tcp -m tcp --dport 8099 -j DROP"), "PARTIAL"),  # F3
        (_ipt("ACCEPT", "-A FORWARD -s 10.10.0.9/32 -j DROP"), "ACCEPT"),                          # F6
        (_ipt("ACCEPT", "-A FORWARD -j LOG"), "ACCEPT"),                                           # F7
        (_ipt("ACCEPT"), "ACCEPT"),                                                                # F8
        (_ipt("DROP", "-A FORWARD -j ACCEPT"), "ACCEPT"),                                          # F1L
        (_ipt("DROP", "-A FORWARD -p tcp -m tcp --dport 9000 -j ACCEPT"), "DROP"),                 # F9L
        (_ipt("ACCEPT", "-A FORWARD -j DROP"), "DROP"),
        (_ipt("ACCEPT", "-A FORWARD -p tcp -m tcp --dport 8099 -j DROP", "-A FORWARD -j ACCEPT"), "PARTIAL"),
    ], ids=["port-drop", "jump-drop", "one-source", "log", "nothing", "final-accept", "drop-policy",
            "final-drop", "refusal-then-accept-all"])
    def test_iptables_s(self, rules, verdict):
        assert nf._ipt_effective_forward_policy(rules) == verdict

    def test_input_rules_do_not_count_for_forward(self):
        assert nf._ipt_effective_forward_policy(_ipt("ACCEPT", "-A INPUT -p tcp --dport 8099 -j DROP")) == "ACCEPT"

    def test_the_snapshot_reads_forward_this_way(self):
        src = inspect.getsource(IptablesNftSnapshot.from_system)
        assert "forward_policy=_ipt_effective_forward_policy(raw)" in src
        assert 'forward_policy=_nft_policy(raw, "forward")' in src
        assert 'forward_accepts_all=_nft_first_ipv4_chain_accepts_all(raw, "forward")' in src


def _snap(policy, **kw):
    return IptablesNftSnapshot(backend="iptables", input_policy="DROP", forward_policy=policy,
                               has_loopback_rule=True, has_conntrack_rule=True,
                               forward_target=("iptables",), **kw)


def _run(snap, lang=None):
    if lang is None:
        return check_iptables_nftables(snap, t=lambda k, **kw: k)
    i18n.init(lang)
    try:
        return check_iptables_nftables(snap, t=i18n.t)
    finally:
        i18n.init(lang="en")


def _forward(res):
    return [f for f in res.findings if "forward" in f.key]


class TestWhatIsSaid:

    def test_partial_is_a_ceiling_not_a_warn(self):
        res = _run(_snap("PARTIAL"))
        assert [f.key for f in _forward(res)] == ["firewall_iptables.forward_accept_unweighed"]
        assert not res.deductions
        assert is_visibility_key("firewall_iptables.forward_accept_unweighed")

    def test_accept_keeps_its_warn_and_its_command(self):
        res = _run(_snap("ACCEPT"))
        assert [(d.key, d.points) for d in res.deductions] == [("firewall_iptables.forward_accept", 1)]
        assert _forward(res)[0].cmd == "sudo iptables -P FORWARD DROP"

    def test_an_accept_all_rule_gets_no_policy_command(self):
        res = _run(_snap("ACCEPT", forward_accepts_all=True))
        f = _forward(res)[0]
        assert f.key == "firewall_iptables.forward_accept" and not f.cmd
        assert f.detail == "firewall_iptables.forward_accept_all_detail"

    def test_a_final_rule_is_said_as_a_rule(self):
        res = _run(_snap("DROP", forward_policy_by_rule=True))
        assert _forward(res)[0].message == "firewall_iptables.forward_ok_final_rule"

    @pytest.mark.parametrize("lang, policy, words", [
        ("en", "PARTIAL", "which traffic they stop is not established"),
        ("fr", "PARTIAL", "quel trafic elles arrêtent n'est pas établi"),
        ("en", "ACCEPT", "no rule refuses it beyond given sources"),
        ("fr", "ACCEPT", "aucune règle ne le refuse au-delà de sources désignées"),
    ])
    def test_the_text_says_it(self, lang, policy, words):
        assert any(words in f.message for f in _forward(_run(_snap(policy), lang)))

    @pytest.mark.parametrize("lang, words", [("en", "iptables -S FORWARD"), ("fr", "iptables -S FORWARD")])
    def test_the_accept_all_detail_names_forward(self, lang, words):
        f = _forward(_run(_snap("ACCEPT", forward_accepts_all=True), lang))[0]
        assert words in f.detail and "INPUT" not in f.detail
