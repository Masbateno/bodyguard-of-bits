"""A stopped service is inventory. BOB reports it and does not score it.

Measured on Kali 2026.2, v0.17.1 development. Seven services installed and
stopped produced seven deductions of one key and took the *Firewall & Services*
domain to 3/10 — more, in aggregate, than a genuinely world-exposed critical
service costs (2 pt). On the same screen BOB said:

    ⚠ VNC Server is installed on this system — service is currently stopped,
      but the presence of this package is a potential attack vector

    HOW TO FIX
    3. Enable and start:
       sudo systemctl enable --now <service>

It called VNC an attack vector and then told the operator to start it.
Following BOB's own remediation made the machine strictly more exposed.

Both halves come from one mistake. v0.8.0 attached the point reasoning that a
dormant critical *security service* is a real defensive gap — true of fail2ban,
clamav, auditd, and of nothing in this registry: all 38 entries are
network-listening services, and those three carry their own inactive findings.
The justification had no instance in the data it ran on, and the explain text
was written for the services it described rather than the ones it fires on.

What replaces it follows the rule BOB states in its own README — *"BOB is not a
threat-modeling engine — it does not enumerate attacker paths"*. Three things
are measured: the package is installed, the unit is not running, it is not
enabled. All three are stated. Deducting for them would require calling a
stopped service an attack vector, which needs a path BOB cannot see.

Nothing is hidden by this: the finding still prints, once per service.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bob.checks.services import check_services
from tests.test_services import (
    ServiceState, has_level, make_service, make_snapshot, total_deductions,
)

_ROOT = Path(__file__).resolve().parent.parent
_REGISTRY = json.loads((_ROOT / "bob" / "data" / "services.json")
                       .read_text(encoding="utf-8"))
_KEY = "services.state.installed_inactive_critical"


class TestReportedAndNotScored:
    @pytest.mark.parametrize("risk", ["high", "critical"])
    def test_the_finding_is_still_emitted(self, risk):
        """The half that must never regress: nothing is hidden."""
        snap = make_snapshot(service=make_service(risk=risk),
                             state=ServiceState.INACTIVE_DISABLED)
        result = check_services([snap])
        assert result.findings, "the operator lost the information entirely"
        assert has_level(result, "info")

    @pytest.mark.parametrize("risk", ["high", "critical"])
    def test_it_costs_nothing(self, risk):
        snap = make_snapshot(service=make_service(risk=risk),
                             state=ServiceState.INACTIVE_DISABLED)
        assert total_deductions(check_services([snap])) == 0

    def test_a_dormant_service_never_outweighs_a_running_one(self):
        """Seven stopped packages must not cost more than one real exposure."""
        stopped = [make_snapshot(service=make_service(risk="critical"),
                                 state=ServiceState.INACTIVE_DISABLED)
                   for _ in range(7)]
        assert total_deductions(check_services(stopped)) == 0


class TestTheOldRationaleHasNoInstance:
    """v0.8.0 scored these as dormant *defensive* controls. There are none."""

    def test_every_registry_entry_is_a_listening_service(self):
        defensive = [s for s in _REGISTRY
                     if any(w in str(s.get("label", "")).lower()
                            for w in ("fail2ban", "clamav", "auditd", "rkhunter",
                                      "apparmor", "selinux"))]
        assert not defensive, (
            "a defensive control entered the service registry: the "
            "'dormant protection = no defence' reasoning would apply to it, "
            f"and this decision needs re-taking rather than inheriting: {defensive}")

    @pytest.mark.parametrize("module,key", [
        ("fail2ban", "fail2ban.service_inactive"),
        ("auditd", "auditd.service_inactive"),
        ("clamav", "clamav.clamd_inactive"),
    ])
    def test_the_defensive_tools_keep_their_own_finding(self, module, key):
        """Dropping the deduction here loses no coverage — it lives elsewhere."""
        src = (_ROOT / "bob" / "checks" / f"{module}.py").read_text(encoding="utf-8")
        assert key in src, (
            f"{module} no longer reports its own inactive state, so removing "
            "the registry deduction would leave a real defensive gap unscored")


class TestTheAdviceNoLongerContradictsTheFinding:
    """It told the operator to start what it had just called an attack vector."""

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_removal_is_offered_before_starting(self, locale):
        data = json.loads((_ROOT / "bob" / "locales" / f"{locale}.json")
                          .read_text(encoding="utf-8"))
        how = data["explain"]["services"]["state"]["installed_inactive_critical"]["how"]
        assert "purge" in how or "remove" in how, f"{locale}: no removal path offered"
        i_remove = min((how.find(w) for w in ("purge", "remove") if how.find(w) >= 0),
                       default=-1)
        i_start = how.find("enable --now")
        assert i_remove >= 0
        assert i_start < 0 or i_remove < i_start, (
            f"{locale}: starting the service is offered before removing it — "
            "the first remedy BOB names for a stopped high-risk daemon should "
            "not be the one that makes it listen"
        )

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_the_message_states_what_was_measured(self, locale):
        data = json.loads((_ROOT / "bob" / "locales" / f"{locale}.json")
                          .read_text(encoding="utf-8"))
        msg = data["services"]["state"][_KEY.split(".")[-1]]
        for claim in ("attack vector", "vecteur d'attaque"):
            assert claim not in msg, (
                f"{locale}: the message still asserts a threat model rather "
                "than the three facts BOB measured"
            )
        assert "{label}" in msg

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_the_explanation_is_about_the_services_it_fires_on(self, locale):
        data = json.loads((_ROOT / "bob" / "locales" / f"{locale}.json")
                          .read_text(encoding="utf-8"))
        why = data["explain"]["services"]["state"][_KEY.split(".")[-1]]["why"]
        for wrong in ("fail2ban", "clamav", "auditd", "rkhunter"):
            assert wrong not in why.lower(), (
                f"{locale}: the explanation still describes defensive tools, "
                "none of which is in this registry"
            )
