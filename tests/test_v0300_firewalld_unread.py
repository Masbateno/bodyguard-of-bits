"""v0.30.0 — firewalld that would not answer is not "no firewall" downstream either.

0.26.0 made the firewall section and the risk level say "not established"
when firewall-cmd is present and silent. Measured in a network namespace
(1 November 2026, `~/.cache/bob-fieldtest/netnsbench/fwbench.sh`, a
firewall-cmd refusing every query in silence, UFW installed but off,
listeners on IPv4 and IPv6), the rest still said there was none:

- the IPv6 section: "UFW is installed but not active, and no other firewall
  filters inbound traffic";
- each port: "no active firewall to filter it";
- the summary read the posture "no firewall" (inactive).

Now the posture is "firewalld, policy not read" (the summary says the policy
was not read), and the ports, the services and the IPv6 section say
firewall-cmd gave no answer and the exposure is not established. The score
does not move (7, a ceiling, no risk floor).
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks.firewall import FirewallStatus, resolve_firewall_posture


class _Fwd:
    def __init__(self, installed=True, readable=False, active=False):
        self.installed, self.readable, self.active = installed, readable, active


def _status():
    return FirewallStatus(installed=True, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


class TestThePosture:

    def test_firewalld_silent(self):
        p = resolve_firewall_posture(_status(), _Fwd(), None)
        assert (p.backend, p.policy, p.active) == ("firewalld", "unknown", True)

    def test_a_ruleset_bob_read_comes_first(self):
        assert resolve_firewall_posture(_status(), _Fwd(), "DROP").backend == "netfilter"

    @pytest.mark.parametrize("fwd", [_Fwd(readable=True), _Fwd(installed=False), None],
                             ids=["stopped", "absent", "none"])
    def test_otherwise_no_firewall_as_before(self, fwd):
        assert not resolve_firewall_posture(_status(), fwd, None).active

    @staticmethod
    def _summary(unread):
        from bob.checks.ports import PortsSnapshot
        from bob.exposure import compute_exposure
        from bob.scoring import ScoreEngine

        class _NC:
            def __getattr__(self, _a):
                return None
        items = compute_exposure(ScoreEngine(), PortsSnapshot(ports=[], ufw_rules="", ss_output=""), _NC(),
                                 True, "unknown", lambda k, **kw: k, fw_backend="firewalld", fw_unread=unread)
        return next(i for i in items if i.label == "exposure.firewall")

    def test_the_summary_does_not_say_active(self):
        """Measured: 0.29.0 "No active firewall — all ports unfiltered"; the first
        0.30.0 fix "active (firewalld)" — firewall-cmd said neither."""
        line = self._summary(True)
        assert (line.detail, line.icon) == ("exposure.firewall_firewalld_unread", "⚠")

    def test_a_running_firewalld_whose_policy_is_unread_keeps_its_line(self):
        assert self._summary(False).detail == "exposure.firewall_policy_unread"

    def test_the_summary_is_handed_it(self):
        from bob import __main__ as main
        from bob import runner
        assert "fw_unread=_firewalld_unread," in inspect.getsource(runner)
        src = inspect.getsource(main)
        assert "fw_unread          = result.fw_unread" in src and "fw_unread=fw_unread)" in src


class TestDownstream:

    @staticmethod
    def _ports(address):
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        snap = PortsSnapshot(ports=[ListeningPort(port=8099, proto="tcp", address=address, raw_line="")],
                             ufw_rules="", ss_output="")
        return check_ports(snap, ufw_active=False, firewalld_unread=True, t=lambda k, **kw: k)

    @pytest.mark.parametrize("address, key", [("0.0.0.0", "ports.uncovered_firewalld_unread"),
                                              ("192.0.2.10", "ports.uncovered_bound_address_firewalld_unread")])
    def test_ports(self, address, key):
        res = self._ports(address)
        keys = {f.key for f in res.findings}
        assert key in keys and not {"ports.uncovered_ufw_inactive", "ports.uncovered_bound_address"} & keys
        assert not res.deductions

    def test_services(self):
        from bob.checks.services import Exposure, _check_port_exposure
        from bob.scoring import CheckResult
        res = CheckResult()
        _check_port_exposure(None, "22/tcp", Exposure.NO_RULE, res, "local", False,
                             lambda k, **kw: f"{k}|{kw.get('exposure', '')}", firewalld_unread=True)
        assert "no_rule_firewalld_unread" in res.findings[0].message

    def test_ipv6(self):
        from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=True, ipv6_listeners=["8099/tcp"],
                            has_global_ipv6=True)
        res = check_ipv6(snap, ufw_active=False, firewalld_unread=True, t=lambda k, **kw: k)
        keys = {f.key for f in res.findings}
        assert "ipv6.firewalld_unread" in keys and "ipv6.no_firewall_v6" not in keys
        assert not res.deductions

    def test_the_hand_down(self):
        from bob import runner
        from bob.checks import services
        from bob.display import check_single_service_display
        src = inspect.getsource(runner)
        assert '_firewalld_unread = fw_posture.backend == "firewalld" and fw_posture.policy == "unknown"' in src
        assert src.count("firewalld_unread=_firewalld_unread") == 3
        assert inspect.getsource(services).count("firewalld_unread=firewalld_unread,") == 2
        assert "firewalld_unread=firewalld_unread," in inspect.getsource(check_single_service_display)


@pytest.mark.parametrize("lang, key, words", [
    ("en", "ports.uncovered_firewalld_unread", "firewall-cmd gave no answer: whether this port is reachable is not established"),
    ("fr", "ports.uncovered_firewalld_unread", "firewall-cmd n'a rien répondu : que ce port soit joignable n'est pas établi"),
    ("en", "ipv6.firewalld_unread", "whether these listeners are reachable is not established"),
    ("fr", "ipv6.firewalld_unread", "que ces services soient joignables n'est pas établi"),
    ("en", "exposure.firewall_firewalld_unread", "firewall-cmd gave no answer — whether a firewall filters"),
    ("fr", "exposure.firewall_firewalld_unread", "firewall-cmd n'a rien répondu — qu'un pare-feu filtre"),
    ("en", "exposure.firewall_netfilter_unknown", "read in part (a table refused) — whether a firewall filters"),
    ("fr", "exposure.firewall_netfilter_unknown", "lu qu'en partie (une table refusée) — qu'un pare-feu filtre"),
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key, port="8099/tcp", count=1, ports="8099/tcp", address="192.0.2.10")
    finally:
        i18n.init(lang="en")


class TestThePortLinesTakeNoPointsAndNoSecondCeiling:
    """0.30.0, review of the changelog — the per-port and IPv6 lines under a
    firewall-cmd that would not answer or a ruleset read in part are INFO: no
    points, and no ceiling of their own (the gap is marked once, by
    ``firewall.firewalld_unreadable`` or ``firewall.netfilter_unknown``). A
    visibility key on the ports or IPv6 section would mark that domain read in
    part and widen the score's span: a second count of one gap. Measured
    against 0.29.0 (`fwstopbench.txt`, `unreadbench-after.txt`): no
    deduction from them, ``unverified`` holding the two section keys only."""

    KEYS = ("ports.uncovered_netfilter_unknown", "ports.uncovered_bound_address_netfilter_unknown",
            "ports.uncovered_firewalld_unread", "ports.uncovered_bound_address_firewalld_unread",
            "ipv6.firewalld_unread")

    @pytest.mark.parametrize("key", KEYS)
    def test_not_a_visibility_key(self, key):
        from bob.visibility import is_visibility_key
        assert not is_visibility_key(key)

    def test_the_engine_counts_nothing_for_them(self):
        from bob.scoring import CheckResult, ScoreEngine
        res = CheckResult()
        for key in self.KEYS:
            res.info(message=key, key=key)
        engine = ScoreEngine()
        before = engine.score
        engine2 = ScoreEngine()
        engine2.apply(res, section="ports")
        assert (engine2.score, engine2.unverified, engine2.score_is_upper_bound) == (before, [], False)
