"""One state in the enum rendered nothing at all.

Stress pass 3, on Alpine: `rc-service sshd stop` and the audit stopped saying
anything about sshd's state. Driven deterministically afterwards, every state
in `ServiceState` produced a `services.state.*` finding except one::

    active_enabled       -> services.state.active_enabled
    active_disabled      -> services.state.active_disabled
    inactive_enabled     -> (nothing)
    inactive_disabled    -> services.state.installed_inactive_critical
    unknown              -> services.state.unknown

`_STATE_PRIORITY` ranked INACTIVE_ENABLED, `_detect_state` returned it, and no
branch consumed it — the "declared but never consumed" class this project has
closed before. Worse, the port-exposure finding still fired, so the service
appeared in the panorama with no verdict on its state beside it.

It is the state that says *the machine was told to run this and it is not
running* — a crash, a start that failed, a dependency that never came up — and
it is the mirror of ACTIVE_DISABLED, which BOB has warned about and scored
since v0.8.0 for the same kind of reason: a measured disagreement between
configured intent and running reality. It is treated the same way.
"""

from __future__ import annotations

import pytest

from bob.checks.services import ServiceState, _STATE_PRIORITY, check_services
from bob.scoring import FindingLevel
from tests.test_services import make_service, make_snapshot, total_deductions


def _state_keys(state, risk="critical"):
    result = check_services([make_snapshot(service=make_service(risk=risk),
                                           state=state)])
    return {f.key for f in result.findings if f.key.startswith("services.state")}


class TestNoStateIsSilent:
    @pytest.mark.parametrize("state", list(ServiceState))
    def test_every_state_renders_a_verdict(self, state):
        assert _state_keys(state), (
            f"{state.value} produces no services.state.* finding; the service "
            "still appears in the panorama through its port exposure, with "
            "nothing said about its state"
        )

    def test_every_ranked_state_is_reachable(self):
        """The priority table is the list of states `_detect_state` can return."""
        for state in _STATE_PRIORITY:
            assert _state_keys(state), f"{state.value} is ranked but never rendered"


class TestEnabledButDown:
    def test_it_has_its_own_key(self):
        assert "services.state.inactive_enabled" in _state_keys(
            ServiceState.INACTIVE_ENABLED)

    def test_it_warns(self):
        result = check_services([make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.INACTIVE_ENABLED)])
        finding = next(f for f in result.findings
                       if f.key == "services.state.inactive_enabled")
        assert finding.level is FindingLevel.WARN

    def test_it_is_scored_like_its_mirror(self):
        """ACTIVE_DISABLED loses the service at the next reboot and costs a
        point; this one has lost it already."""
        down = total_deductions(check_services([make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.INACTIVE_ENABLED)]))
        mirror = total_deductions(check_services([make_snapshot(
            service=make_service(risk="critical"),
            state=ServiceState.ACTIVE_DISABLED)]))
        assert down == mirror == 1

    def test_it_names_the_service(self):
        result = check_services([make_snapshot(
            service=make_service(risk="critical", label="SSH Server"),
            state=ServiceState.INACTIVE_ENABLED)])
        finding = next(f for f in result.findings
                       if f.key == "services.state.inactive_enabled")
        assert "SSH Server" in finding.message

    def test_it_does_not_claim_to_know_why(self):
        """A crash, a failed start and a deliberate stop look identical."""
        import json
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        for locale in ("en", "fr"):
            data = json.loads((root / "bob" / "locales" / f"{locale}.json")
                              .read_text(encoding="utf-8"))
            detail = data["services"]["state"]["inactive_enabled_detail"].lower()
            assert any(w in detail for w in ("why", "pourquoi")), (
                f"{locale}: the detail must say it does not know why, because "
                "BOB cannot tell a crash from a maintenance stop"
            )


class TestBothInitSystemsAreAddressed:
    """Alpine is where this surfaced; the advice must not be systemd-only."""

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_the_explanation_names_openrc_too(self, locale):
        import json
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        data = json.loads((root / "bob" / "locales" / f"{locale}.json")
                          .read_text(encoding="utf-8"))
        how = data["explain"]["services"]["state"]["inactive_enabled"]["how"]
        assert "systemctl" in how and "rc-service" in how, (
            "the state was found on an OpenRC host; advice that only names "
            "systemd is advice that host cannot follow"
        )
