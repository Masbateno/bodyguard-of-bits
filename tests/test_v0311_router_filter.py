"""v0.31.1 — behind an IPv4 NAT with a public IPv6 address, the router decides.

0.31.0 stopped calling such a host "behind NAT" (display only) and planned the
rest for 0.31.1 (decided 7 November 2026): measured on a real Kali behind a
home router, its IPv6 firewall off, a phone on mobile data reached the host's
``[::]:8080``; on, nothing arrived. The router's filter cannot be read from the
host, so when the host's own rules leave an IPv6 listener reachable — or their
filtering is not established — the score is a ceiling. When the host's rules
close IPv6 inbound, the router decides nothing and nothing changes.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from bob import runner
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob.scoring import ScoreEngine
from bob.visibility import VISIBILITY_KEYS
from tests.helpers import _t

KEY = "ipv6.router_filter_unverified"


def _snap(**kw):
    base = dict(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True, ipv6_listeners=["22/tcp", "8080/tcp"],
                ufw_v6_covered=[], has_global_ipv6=True, ufw_present=True)
    base.update(kw)
    return IPv6Snapshot(**base)


def _keys(result):
    return {f.key for f in result.findings}


class TestTheRouterDecides:

    def test_no_firewall_on_the_host(self):
        """The Kali case: UFW not running, no other firewall, a public IPv6."""
        res = check_ipv6(_snap(ufw_present=False), ufw_active=False, t=_t, behind_ipv4_nat=True)
        assert "ipv6.no_firewall_v6" in _keys(res) and KEY in _keys(res)

    def test_a_listener_a_rule_allows(self):
        """UFW at default deny, 22 allowed by a (v6) rule, 8080 left to the
        default: the section says only "covered by the default deny" for 8080,
        yet 22 is reachable — the router decides."""
        res = check_ipv6(_snap(ufw_v6_covered=["22/tcp"]), ufw_active=True, t=_t,
                         ufw_incoming_policy="deny", behind_ipv4_nat=True)
        assert "ipv6.ports_default_deny" in _keys(res) and KEY in _keys(res)

    def test_it_makes_the_score_a_ceiling(self):
        assert KEY in VISIBILITY_KEYS
        engine = ScoreEngine()
        engine.apply(check_ipv6(_snap(ufw_present=False), ufw_active=False, t=_t, behind_ipv4_nat=True))
        assert KEY in engine.unverified and engine.score_is_upper_bound is True


class TestNothingChanges:
    """Polarity twins: the router does not decide."""

    def test_not_behind_an_ipv4_nat(self):
        res = check_ipv6(_snap(ufw_present=False), ufw_active=False, t=_t, behind_ipv4_nat=False)
        assert KEY not in _keys(res)

    def test_no_public_ipv6(self):
        res = check_ipv6(_snap(ufw_present=False, has_global_ipv6=False), ufw_active=False, t=_t,
                         behind_ipv4_nat=True)
        assert KEY not in _keys(res)

    @pytest.mark.parametrize("policy", ["deny", "reject"])
    def test_the_host_s_default_deny_closes_every_listener(self, policy):
        res = check_ipv6(_snap(), ufw_active=True, t=_t, ufw_incoming_policy=policy, behind_ipv4_nat=True)
        assert "ipv6.ports_default_deny" in _keys(res) and KEY not in _keys(res)

    def test_no_ipv6_listener(self):
        res = check_ipv6(_snap(ufw_present=False, ipv6_listeners=[]), ufw_active=False, t=_t,
                         behind_ipv4_nat=True)
        assert KEY not in _keys(res)


def test_the_runner_hands_whether_ipv4_is_behind_nat():
    calls = [n for n in ast.walk(ast.parse(inspect.getsource(runner))) if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "_sec" and n.args
             and isinstance(n.args[0], ast.Constant) and n.args[0].value == "ipv6"]
    kw = {k.arg: k.value for k in calls[0].keywords}
    assert "behind_ipv4_nat" in kw and ast.unparse(kw["behind_ipv4_nat"]) == "network_context == 'local'"
