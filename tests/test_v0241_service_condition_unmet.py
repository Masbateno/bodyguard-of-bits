"""v0.24.1 — an enabled unit systemd skipped by design is not a stopped service.

Measured on the Mint desktop: ``inetutils-inetd.service`` is enabled and
carries ``ExecCondition=grep -qr ^[0-9A-Za-z/] /etc/inetd.conf /etc/inetd.d/``.
With no service configured in inetd.conf the condition fails and systemd skips
the unit (``Result: exec-condition``, ``ConditionResult=no``). BOB read only
is-active/is-enabled and reported "Telnet Server is enabled at boot but is not
running" — WARN −1, detail "a crash, a failed start…". Nothing crashed and no
telnet was served.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import services as S
from bob.checks.services import ServiceState, _STATE_PRIORITY, check_services
from tests.test_services import make_service, make_snapshot, total_deductions


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _systemctl(show: str):
    def run(*args, **kwargs):
        argv = list(args)
        if argv[:2] == ["systemctl", "is-active"]:
            return "inactive"
        if argv[:2] == ["systemctl", "is-enabled"]:
            return "enabled"
        if argv[:2] == ["systemctl", "show"] and "ConditionResult" in argv:
            return show
        if argv[:2] == ["systemctl", "show"] and "TriggeredBy" in argv:
            return "TriggeredBy="
        return ""
    return run


def test_exec_condition_skip_is_condition_unmet(monkeypatch):
    # Property values exactly as systemd 255 printed them on the Mint desktop.
    monkeypatch.setattr(S, "_run", _systemctl("Result=exec-condition\nConditionResult=no\n"))
    assert S._detect_single_unit_state("inetutils-inetd") == ServiceState.CONDITION_UNMET


def test_condition_directive_skip_is_condition_unmet(monkeypatch):
    monkeypatch.setattr(S, "_run", _systemctl("Result=success\nConditionResult=no\n"))
    assert S._detect_single_unit_state("foo") == ServiceState.CONDITION_UNMET


def test_failed_start_stays_enabled_but_down(monkeypatch):
    monkeypatch.setattr(S, "_run", _systemctl("Result=exit-code\nConditionResult=yes\n"))
    assert S._detect_single_unit_state("foo") == ServiceState.INACTIVE_ENABLED


def test_unreadable_properties_stay_enabled_but_down(monkeypatch):
    monkeypatch.setattr(S, "_run", _systemctl(""))
    assert S._detect_single_unit_state("foo") == ServiceState.INACTIVE_ENABLED


def test_condition_unmet_is_info_without_deduction():
    snap = make_snapshot(service=make_service(risk="critical"),
                         state=ServiceState.CONDITION_UNMET)
    result = check_services([snap])
    keys = {f.key for f in result.findings}
    assert "services.state.condition_unmet" in keys
    assert "services.state.inactive_enabled" not in keys
    assert total_deductions(result) == 0


def test_a_failed_sibling_outranks_a_skipped_one():
    assert _STATE_PRIORITY[ServiceState.INACTIVE_ENABLED] > _STATE_PRIORITY[ServiceState.CONDITION_UNMET]
    assert _STATE_PRIORITY[ServiceState.CONDITION_UNMET] > _STATE_PRIORITY[ServiceState.INACTIVE_DISABLED]
