"""A socket-activated service is available on demand, not stopped.

Measured on a Raspberry Pi Zero W: cups.service was inactive and enabled,
cups.socket active. systemd's `TriggeredBy=cups.socket cups.path` says the
service starts the moment a client connects to the socket — the designed
state of a socket-activated daemon, and the port is genuinely held.

v0.18.0 read cups.service alone: enabled + inactive → INACTIVE_ENABLED,
rendered as "enabled at boot but is not running", WARN −1, with a detail
calling it "a crash, a failed start, or a hand stop nobody undid". That was
this release's own regression — INACTIVE_ENABLED had rendered nothing before
v0.18.0, and giving it a voice gave it the wrong one for this case.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import services as S
from bob.registry import Service


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _fake_systemctl(units: "dict[str, dict]"):
    """A _run stand-in answering is-active / is-enabled / show TriggeredBy
    from a {unit: {"active":bool,"enabled":bool,"triggered_by":[...]}} map."""
    def run(*args, **kwargs):
        argv = list(args)
        if argv[:2] == ["systemctl", "is-active"]:
            return "active" if units.get(argv[2], {}).get("active") else "inactive"
        if argv[:2] == ["systemctl", "is-enabled"]:
            return "enabled" if units.get(argv[2], {}).get("enabled") else "disabled"
        if argv[:2] == ["systemctl", "show"] and "TriggeredBy" in argv:
            trig = units.get(argv[2], {}).get("triggered_by", [])
            return "TriggeredBy=" + " ".join(trig)
        if argv[:2] == ["systemctl", "list-units"]:
            return ""
        return ""
    return run


_CUPS = {
    "cups": {"active": False, "enabled": True, "triggered_by": ["cups.socket", "cups.path"]},
    "cups.socket": {"active": True, "enabled": True},
    "cups.path": {"active": False, "enabled": True},
}


def _cups_service():
    return Service(id="cups", label="CUPS (network printing)", packages=("cups",),
                   services=("cups",), ports=["631/tcp"], risk="low", detection={})


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_the_cups_case_is_socket_activated_not_inactive_enabled(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_systemctl(_CUPS))
    assert S._detect_single_unit_state("cups") == S.ServiceState.SOCKET_ACTIVATED


def test_enabled_and_inactive_with_no_active_trigger_is_still_stopped(monkeypatch):
    """The mirror: an enabled service whose socket is also down is stopped."""
    units = {"foo": {"active": False, "enabled": True, "triggered_by": ["foo.socket"]},
             "foo.socket": {"active": False, "enabled": True}}
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("foo") == S.ServiceState.INACTIVE_ENABLED


def test_enabled_and_inactive_with_no_trigger_at_all_is_stopped(monkeypatch):
    units = {"bar": {"active": False, "enabled": True, "triggered_by": []}}
    monkeypatch.setattr(S, "_run", _fake_systemctl(units))
    assert S._detect_single_unit_state("bar") == S.ServiceState.INACTIVE_ENABLED


def test_active_trigger_names_the_socket(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_systemctl(_CUPS))
    assert S._active_trigger("cups") == "cups.socket"


# ---------------------------------------------------------------------------
# The collector carries the trigger through to the snapshot
# ---------------------------------------------------------------------------

def test_the_snapshot_from_the_collector_knows_the_trigger(monkeypatch):
    monkeypatch.setattr(S, "_run", _fake_systemctl(_CUPS))
    monkeypatch.setattr(S, "_detect_installation", lambda svc: (True, "pkg"))
    monkeypatch.setattr(S, "_resolve_ports", lambda svc: ["631/tcp"])
    monkeypatch.setattr(S, "_classify_exposure", lambda *a, **k: S.Exposure.NO_RULE)
    snap = S.ServiceSnapshot._build_snapshot(_cups_service(), "", None, None)
    assert snap.state == S.ServiceState.SOCKET_ACTIVATED
    assert snap.activation_trigger == "cups.socket"
    assert snap.is_active, "a socket-activated service is serving on demand"


# ---------------------------------------------------------------------------
# The verdict, as rendered
# ---------------------------------------------------------------------------

def _state_finding(result):
    return next(f for f in result.findings if f.key.startswith("services.state."))


def test_it_renders_info_no_deduction_and_names_the_trigger():
    snap = S.ServiceSnapshot(
        service=_cups_service(), installed=True, install_via="pkg",
        state=S.ServiceState.SOCKET_ACTIVATED, ports=["631/tcp"],
        exposures={"631/tcp": S.Exposure.NO_RULE}, activation_trigger="cups.socket")
    result = S.check_services([snap], t=i18n.t)
    f = _state_finding(result)
    assert f.key == "services.state.socket_activated"
    assert f.level.name == "INFO"
    assert "cups.socket" in f.message
    assert not any(d.key == "services.state.socket_activated" for d in result.deductions)


def test_a_genuinely_stopped_enabled_service_still_warns_and_costs():
    """INACTIVE_ENABLED must keep its v0.18.0 warning — the mirror case."""
    snap = S.ServiceSnapshot(
        service=_cups_service(), installed=True, install_via="pkg",
        state=S.ServiceState.INACTIVE_ENABLED, ports=["631/tcp"],
        exposures={"631/tcp": S.Exposure.NO_RULE})
    result = S.check_services([snap], t=i18n.t)
    assert _state_finding(result).key == "services.state.inactive_enabled"
    assert any(d.key == "services.state.inactive_enabled" for d in result.deductions)
