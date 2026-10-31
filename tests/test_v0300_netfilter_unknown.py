"""v0.30.0 — a raw ruleset BOB read only in part is not "no firewall".

0.29.0 left it written as a limit: with `iptables -S` answering and the raw,
mangle or security table refusing, INPUT reads undetermined, but the firewall
section still said "UFW firewall is disabled. Your machine is currently
unprotected." Measured in a network namespace (31 October 2026,
`~/.cache/bob-fieldtest/netnsbench/unreadbench2.sh`, an `iptables` shim
refusing the three tables, UFW installed but off, listeners 8098 and 8099):

- before: `firewall.inactive` ALERT, the Firewall & Network domain capped at
  3/10, the risk level raised for "firewall inactive", each port "no active
  firewall to filter it" — score 5;
- after: `firewall.netfilter_unknown` INFO, no cap, no raised level, each port
  "read in part: whether this port is reachable is not established" — score 7,
  a ceiling (`unverified`).

As firewalld that would not answer since 0.26.0: unknown is not absent.
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks.firewall import FirewallStatus, check_firewall, resolve_firewall_posture
from bob.visibility import is_visibility_key


def _status(installed=True):
    return FirewallStatus(installed=installed, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _keys(res):
    return {f.key for f in res.findings}


class TestTheFirewallSection:

    @pytest.mark.parametrize("installed", [True, False], ids=["ufw-installed-off", "no-ufw"])
    def test_said_without_alert_or_cap(self, installed):
        res = check_firewall(_status(installed), firewalld=None, netfilter_protective=False,
                             netfilter_unknown=True, t=lambda k, **kw: k)
        assert "firewall.netfilter_unknown" in _keys(res)
        assert not {"firewall.inactive", "prerequisites.firewall_missing"} & _keys(res)
        assert not res.caps and not res.deductions
        assert is_visibility_key("firewall.netfilter_unknown")

    def test_a_ruleset_that_was_not_read_at_all_is_still_no_firewall(self):
        res = check_firewall(_status(True), firewalld=None, netfilter_protective=False,
                             t=lambda k, **kw: k)
        assert "firewall.inactive" in _keys(res) and res.caps


class TestThePosture:

    def test_a_netfilter_backend_whose_default_is_not_read(self):
        posture = resolve_firewall_posture(_status(), None, "unknown")
        assert (posture.backend, posture.policy, posture.active) == ("netfilter", "unknown", True)

    def test_the_summary_says_it_unread(self):
        from bob.checks.ports import PortsSnapshot
        from bob.exposure import compute_exposure
        from bob.scoring import ScoreEngine

        class _NC:
            def __getattr__(self, _a):
                return None
        items = compute_exposure(ScoreEngine(), PortsSnapshot(ports=[], ufw_rules="", ss_output=""), _NC(),
                                 True, "unknown", lambda k, **kw: k, fw_backend="netfilter")
        assert next(i for i in items if i.label == "exposure.firewall").detail == "exposure.firewall_policy_unread"

    def test_no_risk_floor(self):
        from bob.scoring import ScoreEngine, set_posture_from_engine
        engine = ScoreEngine()
        set_posture_from_engine(engine, fw_active=resolve_firewall_posture(_status(), None, "unknown").active)
        assert not engine._posture_firewall_inactive


class TestThePortsAndServices:

    @staticmethod
    def _ports(address="0.0.0.0"):
        from bob.checks.ports import ListeningPort, PortsSnapshot
        lp = ListeningPort(port=8099, proto="tcp", address=address, raw_line="")
        return PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")

    @pytest.mark.parametrize("address, key", [("0.0.0.0", "ports.uncovered_netfilter_unknown"),
                                              ("192.0.2.10", "ports.uncovered_bound_address_netfilter_unknown")])
    def test_ports(self, address, key):
        from bob.checks.ports import check_ports
        res = check_ports(self._ports(address), ufw_active=False, netfilter_unknown=True, t=lambda k, **kw: k)
        assert key in _keys(res)
        assert not {"ports.uncovered_ufw_inactive", "ports.uncovered_bound_address"} & _keys(res)
        assert not res.deductions

    def test_service_exposure(self):
        from bob.checks.services import Exposure, _check_port_exposure
        from bob.scoring import CheckResult
        res = CheckResult()
        _check_port_exposure(None, "22/tcp", Exposure.NO_RULE, res, "local", False,
                             lambda k, **kw: f"{k}|{kw.get('exposure', '')}", netfilter_unknown=True)
        assert "no_rule_netfilter_unknown" in res.findings[0].message

    def test_the_service_check_hands_it_down(self):
        from bob.checks import services
        from bob.display import check_single_service_display
        assert inspect.getsource(services).count("netfilter_unknown=netfilter_unknown,") == 2
        assert "netfilter_unknown=netfilter_unknown," in inspect.getsource(check_single_service_display)


class TestTheRunner:

    def test_it_reads_and_hands_it(self):
        from bob import runner
        src = inspect.getsource(runner)
        assert '_netfilter_unknown = _nf_snap.backend != "none" and _nf_snap.input_policy == "unknown"' in src
        assert "if _netfilter_protective or _netfilter_partial or _netfilter_unknown:" in src
        assert src.count("netfilter_unknown=_netfilter_unknown,") == 3


@pytest.mark.parametrize("lang, key, words", [
    ("en", "firewall.netfilter_unknown", "whether it filters inbound traffic is not established"),
    ("fr", "firewall.netfilter_unknown", "qu'il filtre le trafic entrant n'est pas établi"),
    ("en", "firewall.netfilter_unknown_detail", "nor raises the risk level on a reading it did not finish"),
    ("fr", "firewall.netfilter_unknown_detail", "ne relève pas le niveau de risque sur une lecture qu'il n'a pas terminée"),
    ("en", "ports.uncovered_netfilter_unknown", "read in part (a table refused)"),
    ("fr", "ports.uncovered_netfilter_unknown", "lu en partie (une table a refusé)"),
    ("en", "services.exposure.no_rule_netfilter_unknown", "whether this port is reachable is not established"),
    ("fr", "services.exposure.no_rule_netfilter_unknown", "que ce port soit joignable n'est pas établi"),
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key, port="8099/tcp", address="192.0.2.10")
    finally:
        i18n.init(lang="en")
