"""An active service started by an *enabled* socket restarts on boot.

Ubuntu 24.04+ ships ssh as a socket-activated service: `ssh.service` is
*disabled*, `ssh.socket` is *enabled*, and ssh is active because a connection
spawned it. BOB read `ssh.service` alone — active + disabled → ACTIVE_DISABLED,
rendered "active now but will not restart automatically", a WARN. On a default
Ubuntu 26.04 server that is a false positive: ssh.socket is enabled, so ssh
comes back on every boot. Found on a real Ubuntu 26.04 server during the v0.20.x
stress pass.

The v0.18.0 socket handling only covered the *inactive*-enabled branch
(cups.socket, `test_v0181_socket_activated_is_not_stopped`). This is the active
branch, and the distinction that matters is *enabled* vs merely *active*: a
socket that is up now but not enabled will not survive a reboot, so that case
must keep warning.
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
            return "enabled" if units.get(argv[2], {}).get("enabled") else "disabled"
        if argv[:2] == ["systemctl", "show"] and "TriggeredBy" in argv:
            return "TriggeredBy=" + " ".join(units.get(argv[2], {}).get("triggered_by", []))
        if argv[:2] == ["systemctl", "list-units"]:
            return ""
        return ""
    return run


# The real Ubuntu 26.04 ssh layout.
_SSH = {
    "ssh": {"active": True, "enabled": False, "triggered_by": ["ssh.socket"]},
    "ssh.socket": {"active": True, "enabled": True},
}


def test_active_service_with_enabled_socket_is_active_enabled(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_systemctl(_SSH))
    assert S._detect_single_unit_state("ssh") == S.ServiceState.ACTIVE_ENABLED


def test_enabled_trigger_names_the_socket(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_systemctl(_SSH))
    assert S._enabled_trigger("ssh") == "ssh.socket"


def test_active_service_started_by_hand_still_warns(monkeypatch):
    """No trigger at all: started manually, will not come back — must warn."""
    units = {"app": {"active": True, "enabled": False, "triggered_by": []}}
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("app") == S.ServiceState.ACTIVE_DISABLED


def test_active_service_with_a_socket_that_is_not_enabled_still_warns(monkeypatch):
    """The distinction that matters: a socket up *now* but not enabled will not
    survive a reboot, so the service genuinely will not restart automatically."""
    units = {
        "app": {"active": True, "enabled": False, "triggered_by": ["app.socket"]},
        "app.socket": {"active": True, "enabled": False},
    }
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("app") == S.ServiceState.ACTIVE_DISABLED


def test_a_fully_enabled_active_service_is_unchanged(monkeypatch):
    units = {"nginx": {"active": True, "enabled": True, "triggered_by": []}}
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("nginx") == S.ServiceState.ACTIVE_ENABLED
