"""
v0.15.5 — a mute systemctl was read as "the service is stopped".

Found with the second variant of the blind-audit instrument: every binary
replaced, one at a time, by a stub that refuses. Removing a tool is not how
tools usually fail — running BOB without sudo is, and the binary is then
*present*, so `_command_exists` says yes and every no-tool branch is skipped.

`unit_active_state` already returns a tri-state, and its docstring exists
precisely because `is_unit_active` collapsed "inactive" and "systemd never
answered" into the same False. The **fallback** underneath had the identical
collapse one level down:

    status = _run("auditctl", "-s") or ""
    snap.service_active = "enabled 1" in status

With neither systemd nor auditd able to answer, `""` produced False, and BOB
warned that a running auditd was stopped — a deduction, plus an order to start
a service that is already running. fail2ban carried a copy of the same code.

A working `auditctl -s` always prints its status block, and `fail2ban-client
ping` always prints "pong"; empty output is the honest signal that no answer
was obtained.
"""

from __future__ import annotations

import pytest

import bob.checks.auditd as auditd_mod
import bob.checks.fail2ban as f2b_mod
from bob.checks.auditd import AuditdSnapshot, check_auditd
from bob.checks.fail2ban import Fail2banSnapshot, check_fail2ban


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


def _deducted(result) -> set[str]:
    return {d.key for d in getattr(result, "deductions", [])}


# --- the two modules, one table -------------------------------------------
#
# The defect was a copy, so the test is one too: whatever is asserted for
# auditd is asserted for fail2ban with the same words.
CASES = [
    pytest.param(auditd_mod, "auditd", "auditctl", "enabled 1\n", id="auditd"),
    pytest.param(f2b_mod, "fail2ban", "fail2ban-client", "pong\n", id="fail2ban"),
]


@pytest.fixture
def no_systemd(monkeypatch):
    """systemd gives no answer, so the fallback is the only source left."""
    def _apply(mod, tool):
        # Patch the names the module holds, not the ones _run holds: mac_policy
        # taught this lesson in the same release — a test that patches the
        # wrong reference reports a fix working without ever exercising it.
        monkeypatch.setattr(mod, "_command_exists", lambda name: name in (tool, "systemctl"))
        monkeypatch.setattr(mod, "unit_active_state", lambda *a, **k: None)
    return _apply


class TestAMuteToolIsNotAStoppedService:

    @pytest.mark.parametrize("mod,unit,tool,alive", CASES)
    def test_no_answer_from_either_source_is_unknown(self, mod, unit, tool, alive, no_systemd, monkeypatch):
        no_systemd(mod, tool)
        monkeypatch.setattr(mod, "_run", lambda *a, **k: "")
        snap = mod.__dict__[f"{'Auditd' if unit == 'auditd' else 'Fail2ban'}Snapshot"].from_system()
        assert snap.service_active is None

    @pytest.mark.parametrize("mod,unit,tool,alive", CASES)
    def test_the_polarity_twin_still_reads_a_running_service(self, mod, unit, tool, alive, no_systemd, monkeypatch):
        """The fallback must keep working, or the fix is just a mute switch."""
        no_systemd(mod, tool)
        monkeypatch.setattr(mod, "_run", lambda *a, **k: alive)
        snap = mod.__dict__[f"{'Auditd' if unit == 'auditd' else 'Fail2ban'}Snapshot"].from_system()
        assert snap.service_active is True


class TestUnknownCostsNothingAndIsStated:

    def test_auditd_unknown(self):
        result = check_auditd(AuditdSnapshot(installed=True, service_active=None))
        assert "auditd.service_inactive" not in _deducted(result)
        assert "auditd.state_unknown" in _keys(result)

    def test_fail2ban_unknown(self):
        result = check_fail2ban(Fail2banSnapshot(installed=True, service_active=None))
        assert "fail2ban.service_inactive" not in _deducted(result)
        assert "fail2ban.state_unknown" in _keys(result)

    def test_auditd_genuinely_stopped_still_deducts(self):
        result = check_auditd(AuditdSnapshot(installed=True, service_active=False))
        assert "auditd.service_inactive" in _deducted(result)

    def test_fail2ban_genuinely_stopped_still_deducts(self):
        result = check_fail2ban(Fail2banSnapshot(installed=True, service_active=False))
        assert "fail2ban.service_inactive" in _deducted(result)
