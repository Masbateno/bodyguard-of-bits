"""A unit systemd skipped by an unmet Condition is not a stopped service.

Measured on a Raspberry Pi Zero W, stock kernel (AppArmor built in but off):

    systemctl show apparmor.service -p ConditionResult  → ConditionResult=no
    ActiveState=inactive  SubState=dead  Result=success

apparmor.service carries ConditionSecurity=apparmor; the kernel has AppArmor
off, so systemd skipped it and left it inactive-and-enabled. BOB 0.18.0
reported "Security service enabled but not running: apparmor" — blaming the
service for the kernel, and contradicting the mac_policy verdict that owns
that state. ConditionResult=no is the discriminator: the unit did exactly
what it should.
"""

from __future__ import annotations

import pytest

import bob.checks.services_state as SS
from bob import i18n
from bob.checks.services_state import ServicesStateSnapshot, check_services_state
from bob.scoring import FindingLevel


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _fake_run(*, enabled, units, condition):
    """A _run stand-in for the three systemctl calls from_system makes.

    enabled:   list-unit-files output (UNIT STATE)
    units:     list-units --all output (UNIT LOAD ACTIVE SUB DESC)
    condition: {unit_id: "yes"|"no"} for `systemctl show -p ConditionResult`
    """
    def run(*args, **kwargs):
        argv = list(args)
        if "list-unit-files" in argv:
            return "\n".join(f"{u} {st}" for u, st in enabled)
        if "list-units" in argv:
            return "\n".join(units)
        if "show" in argv and "ConditionResult" in argv:
            unit = argv[argv.index("show") + 1]
            return f"ConditionResult={condition.get(unit, 'yes')}"
        return ""
    return run


def _collect(monkeypatch, **kw):
    monkeypatch.setattr(SS, "_command_exists", lambda name: name == "systemctl")
    monkeypatch.setattr(SS, "_run", _fake_run(**kw))
    return ServicesStateSnapshot.from_system()


# ---------------------------------------------------------------------------
# The board
# ---------------------------------------------------------------------------

def test_apparmor_skipped_by_condition_is_not_enabled_inactive(monkeypatch):
    snap = _collect(
        monkeypatch,
        enabled=[("apparmor.service", "enabled")],
        units=["apparmor.service loaded inactive dead Load AppArmor profiles"],
        condition={"apparmor.service": "no"},
    )
    assert "apparmor" not in snap.enabled_inactive


def test_it_produces_no_finding_and_no_deduction(monkeypatch):
    snap = _collect(
        monkeypatch,
        enabled=[("apparmor.service", "enabled")],
        units=["apparmor.service loaded inactive dead Load AppArmor profiles"],
        condition={"apparmor.service": "no"},
    )
    result = check_services_state(snap, t=i18n.t)
    assert "services_health.service_inactive" not in [f.key for f in result.findings]
    assert not result.deductions


# ---------------------------------------------------------------------------
# The mirror: a genuinely stopped security service still warns
# ---------------------------------------------------------------------------

def test_a_service_stopped_with_condition_met_is_still_a_gap(monkeypatch):
    """ConditionResult=yes and inactive = it should have started and did not."""
    snap = _collect(
        monkeypatch,
        enabled=[("fail2ban.service", "enabled")],
        units=["fail2ban.service loaded inactive dead Fail2Ban"],
        condition={"fail2ban.service": "yes"},
    )
    assert "fail2ban" in snap.enabled_inactive
    result = check_services_state(snap, t=i18n.t)
    f = _finding(result, "services_health.service_inactive")
    assert f is not None and f.level in (FindingLevel.WARN, FindingLevel.ALERT)
    assert result.deductions


def test_a_failed_service_with_condition_met_still_warns(monkeypatch):
    snap = _collect(
        monkeypatch,
        enabled=[("auditd.service", "enabled")],
        units=["auditd.service loaded failed failed Security Auditing"],
        condition={"auditd.service": "yes"},
    )
    assert "auditd" in snap.enabled_inactive


def test_the_condition_check_only_excuses_condition_no(monkeypatch):
    """A missing/blank ConditionResult must not silence a real gap."""
    snap = _collect(
        monkeypatch,
        enabled=[("fail2ban.service", "enabled")],
        units=["fail2ban.service loaded inactive dead Fail2Ban"],
        condition={},                      # show returns ConditionResult=yes
    )
    assert "fail2ban" in snap.enabled_inactive


def _finding(result, key):
    return next((f for f in result.findings if f.key == key), None)
