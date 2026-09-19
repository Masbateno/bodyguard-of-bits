"""An inactive, static .service reachable through an active .socket is not stopped.

Found on a real Fedora 44 server (v0.20.2 stress pass): cockpit ships with
``cockpit.service`` *static* and *inactive*, while ``cockpit.socket`` is active
and listening on 9090. BOB read ``cockpit.service`` alone — inactive + not
"enabled" → INACTIVE_DISABLED — and rendered "installed but not running and not
enabled at boot, nothing is listening for it". False: the web admin interface is
reachable on 9090 right now.

The v0.18.0 socket handling covered the *enabled*-inactive branch (cups.socket)
and the v0.20.1 fix covered the *active*-service branch (ssh.socket). This is the
third layout: the service unit itself is inactive AND not enabled (static or
disabled), and only its active socket makes it reachable. The trigger must be
consulted here too, not only inside the is_enabled branch.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import services as S


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _fake_systemctl(units: "dict[str, dict]"):
    def run(*args, **kwargs):
        argv = list(args)
        if argv[:2] == ["systemctl", "is-active"]:
            return "active" if units.get(argv[2], {}).get("active") else "inactive"
        if argv[:2] == ["systemctl", "is-enabled"]:
            # cockpit.service reports "static"; anything that is not exactly
            # "enabled" must take the not-enabled path.
            return units.get(argv[2], {}).get("enabled_str", "disabled")
        if argv[:2] == ["systemctl", "show"] and "TriggeredBy" in argv:
            return "TriggeredBy=" + " ".join(units.get(argv[2], {}).get("triggered_by", []))
        if argv[:2] == ["systemctl", "list-units"]:
            return ""
        return ""
    return run


# The real Fedora 44 cockpit layout.
_COCKPIT = {
    "cockpit": {"active": False, "enabled_str": "static",
                "triggered_by": ["cockpit.socket"]},
    "cockpit.socket": {"active": True, "enabled_str": "enabled"},
}


def test_static_inactive_service_with_active_socket_is_socket_activated(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_systemctl(_COCKPIT))
    assert S._detect_single_unit_state("cockpit") == S.ServiceState.SOCKET_ACTIVATED


def test_socket_activated_reads_as_active(monkeypatch):
    """SOCKET_ACTIVATED must count as active so its port exposure is audited."""
    monkeypatch.setattr(S, "_run", _fake_systemctl(_COCKPIT))
    state = S._detect_single_unit_state("cockpit")
    assert state.is_active is True


def test_inactive_service_without_any_active_trigger_stays_inactive(monkeypatch):
    """Polarity: no active trigger → genuinely stopped, must not be upgraded."""
    units = {"app": {"active": False, "enabled_str": "disabled", "triggered_by": []}}
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("app") == S.ServiceState.INACTIVE_DISABLED


def test_inactive_service_with_an_inactive_socket_stays_inactive(monkeypatch):
    """A socket that exists but is not active does not make the service reachable."""
    units = {
        "app": {"active": False, "enabled_str": "static",
                "triggered_by": ["app.socket"]},
        "app.socket": {"active": False, "enabled_str": "disabled"},
    }
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("app") == S.ServiceState.INACTIVE_DISABLED
