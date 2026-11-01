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

    def test_the_summary_says_it_unread(self):
        from bob.checks.ports import PortsSnapshot
        from bob.exposure import compute_exposure
        from bob.scoring import ScoreEngine

        class _NC:
            def __getattr__(self, _a):
                return None
        items = compute_exposure(ScoreEngine(), PortsSnapshot(ports=[], ufw_rules="", ss_output=""), _NC(),
                                 True, "unknown", lambda k, **kw: k, fw_backend="firewalld")
        assert next(i for i in items if i.label == "exposure.firewall").detail == "exposure.firewall_policy_unread"


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
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key, port="8099/tcp", count=1, ports="8099/tcp", address="192.0.2.10")
    finally:
        i18n.init(lang="en")
