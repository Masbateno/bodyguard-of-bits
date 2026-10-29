"""v0.28.0 — a listener the PARTIAL raw ruleset reaches by default is scored.

Lot 4, scoring half (user-approved 25 October 2026). Until now a listener
measured reachable under a raw accept-default ruleset (no UFW/firewalld) was
INFO only, while an identical gap under UFW was -1/-2: a false negative that
made the score depend on the backend, not the exposure. Measured in a network
namespace (scorebench.sh, real listeners): a port the permissive default
reaches with no rule naming it — verdict ("ACCEPT","default") — is open; a port
a rule accepts (opened on purpose) or drops is not. Now:

  - unknown listener, ("ACCEPT","default"), PARTIAL, no front-end
        -> ports.uncovered_netfilter_open, WARN/ALERT, -1 local / -2 public;
  - known service, same -> scored as open-world (services.exposed.<id>),
        criticality weights (-1, or -2/-3 for a high/critical service);
  - ("ACCEPT","rule") (opened on purpose) or ("DROP",*) -> INFO, no deduction;
  - UNKNOWN verdict -> INFO + the visibility ceiling, unchanged;
  - a deny-default (netfilter_active) ruleset -> never this deduction.

The firewall-posture finding stays a "≤" ceiling: the default is still accept,
and a port opened tomorrow would be exposed.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports


def _vf(table):
    return lambda port, proto: table.get(port, ("UNKNOWN", ""))


def _ports(*ports):
    return PortsSnapshot(
        ports=[ListeningPort(port=p, proto="tcp", address="0.0.0.0", raw_line="") for p in ports],
        ufw_rules="", ss_output="")


def _run(snap, lang="en", **kw):
    i18n.init(lang)
    try:
        return check_ports(snap, ufw_active=False, t=i18n.t, **kw)
    finally:
        i18n.init("en")


class TestUnknownListeners:

    @pytest.mark.parametrize("ctx, pts", [("local", 1), ("public", 2), ("ddns", 2)])
    def test_accept_by_default_is_scored(self, ctx, pts):
        r = _run(_ports(8098), network_context=ctx, netfilter_partial=True,
                 netfilter_port_verdict=_vf({8098: ("ACCEPT", "default")}))
        assert [(d.key, d.points) for d in r.deductions] == [("ports.uncovered_netfilter_open", pts)]
        assert any(f.key == "ports.uncovered_netfilter_open" and f.level.value == "alert" for f in r.findings)

    @pytest.mark.parametrize("verdict", [("ACCEPT", "rule"), ("DROP", "rule"), ("DROP", "default"), ("UNKNOWN", "")])
    def test_other_verdicts_are_not_scored(self, verdict):
        r = _run(_ports(8098), netfilter_partial=True, netfilter_port_verdict=_vf({8098: verdict}))
        assert not r.deductions
        assert not any(f.key == "ports.uncovered_netfilter_open" for f in r.findings)

    def test_a_deny_default_ruleset_never_scores(self):
        r = _run(_ports(8098), netfilter_active=True,
                 netfilter_port_verdict=_vf({8098: ("ACCEPT", "default")}))
        assert not r.deductions

    def test_an_ipv6_only_listener_is_not_scored(self):
        snap = PortsSnapshot(ports=[ListeningPort(port=8098, proto="tcp", address="::", raw_line="")],
                             ufw_rules="", ss_output="")
        r = _run(snap, netfilter_partial=True, netfilter_port_verdict=_vf({8098: ("ACCEPT", "default")}))
        assert not r.deductions

    @pytest.mark.parametrize("lang, words", [
        ("en", "accepts it by default and no rule refuses this port: reachable"),
        ("fr", "l'accepte par défaut et aucune règle ne refuse ce port : joignable")])
    def test_the_text(self, lang, words):
        r = _run(_ports(8098), lang, netfilter_partial=True,
                 netfilter_port_verdict=_vf({8098: ("ACCEPT", "default")}))
        assert any(words in f.message for f in r.findings)


class TestKnownServices:

    def _svc(self, verdict, critical=True, ctx="local", lang="en", all_ifaces=True):
        from types import SimpleNamespace
        from bob.checks.services import Exposure, _check_port_exposure
        from bob.scoring import CheckResult
        snap = SimpleNamespace(service=SimpleNamespace(id="ssh", is_high_or_critical=critical),
                               label="SSH", local_sources={})
        i18n.init(lang)
        try:
            res = CheckResult()
            _check_port_exposure(snap, "22/tcp", Exposure.NO_RULE, res, ctx, False, i18n.t,
                                 netfilter_partial=True, netfilter_port_verdict=lambda p, pr: verdict,
                                 netfilter_all_interfaces=(None if all_ifaces is None
                                                           else (lambda p: all_ifaces)))
        finally:
            i18n.init("en")
        return res

    @pytest.mark.parametrize("all_ifaces", [False, None], ids=["bound-to-one-address", "not-given"])
    def test_a_service_not_on_all_interfaces_is_not_scored(self, all_ifaces):
        """After review (round 1): a service bound to one address (the Mint
        host's Samba on its LAN address) is said, not scored, as in the ports
        section; and without the information BOB does not score."""
        assert not self._svc(("ACCEPT", "default"), all_ifaces=all_ifaces).deductions

    def test_the_runner_hands_the_interface_scope(self):
        import inspect
        from bob import runner
        src = inspect.getsource(runner)
        assert "netfilter_all_interfaces=_v4_on_all_interfaces," in src
        assert "lp.is_all_interfaces" in src

    @pytest.mark.parametrize("critical, ctx, pts", [(True, "local", 2), (True, "public", 3), (False, "local", 1)])
    def test_reachable_by_default_scored_by_criticality(self, critical, ctx, pts):
        res = self._svc(("ACCEPT", "default"), critical, ctx)
        assert [(d.key, d.points) for d in res.deductions] == [("services.exposed.ssh", pts)]

    @pytest.mark.parametrize("verdict", [("ACCEPT", "rule"), ("DROP", "default"), ("UNKNOWN", "")])
    def test_other_verdicts_not_scored(self, verdict):
        assert not self._svc(verdict).deductions

    def test_a_deny_default_service_is_not_reclassified(self):
        from types import SimpleNamespace
        from bob.checks.services import Exposure, _check_port_exposure
        from bob.scoring import CheckResult
        snap = SimpleNamespace(service=SimpleNamespace(id="ssh", is_high_or_critical=True),
                               label="SSH", local_sources={})
        res = CheckResult()
        _check_port_exposure(snap, "22/tcp", Exposure.NO_RULE, res, "local", False, i18n.t,
                             netfilter_active=True, netfilter_port_verdict=lambda p, pr: ("ACCEPT", "default"))
        assert not res.deductions

    @pytest.mark.parametrize("lang, words", [
        ("en", "accepts it by default over IPv4 and no rule refuses"),
        ("fr", "l'accepte par défaut en IPv4 et aucune règle ne refuse")])
    def test_the_text(self, lang, words):
        res = self._svc(("ACCEPT", "default"), lang=lang)
        assert any(words in f.message for f in res.findings)


def test_the_new_key_is_fully_contracted():
    import json
    from pathlib import Path
    from bob.explain import EXPLAIN_KEYS
    root = Path(__file__).resolve().parent.parent
    assert "ports.uncovered_netfilter_open" in EXPLAIN_KEYS
    refs = json.loads((root / "bob" / "data" / "cis_refs.json").read_text())
    assert refs["ports.uncovered_netfilter_open"]["code"] == "CIS:3.5.1.7"
    en = json.loads((root / "bob" / "locales" / "en.json").read_text())
    assert set(en["explain"]["ports"]["uncovered_netfilter_open"]) >= {"title", "why", "how"}
