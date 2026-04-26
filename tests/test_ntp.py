"""Tests for CHECK 28 — NTP time synchronisation."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bob.checks.ntp import NtpSnapshot, check_ntp
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# NtpSnapshot dataclass defaults
# ---------------------------------------------------------------------------

class TestNtpSnapshotDefaults:
    def test_ntp_enabled_default_false(self):
        assert not NtpSnapshot().ntp_enabled

    def test_ntp_synchronized_default_false(self):
        assert not NtpSnapshot().ntp_synchronized

    def test_ntp_service_default_empty(self):
        assert NtpSnapshot().ntp_service == ""

    def test_timedatectl_ok_default_false(self):
        assert not NtpSnapshot().timedatectl_ok


# ---------------------------------------------------------------------------
# NtpSnapshot.from_system() — timedatectl path
# ---------------------------------------------------------------------------

_TIMEDATECTL_SYNCED = (
    "Timezone=Europe/Paris\n"
    "NTP=yes\n"
    "NTPSynchronized=yes\n"
    "CanNTP=yes\n"
)

_TIMEDATECTL_ENABLED_NOT_SYNCED = (
    "Timezone=Europe/Paris\n"
    "NTP=yes\n"
    "NTPSynchronized=no\n"
    "CanNTP=yes\n"
)

_TIMEDATECTL_DISABLED = (
    "Timezone=Europe/Paris\n"
    "NTP=no\n"
    "NTPSynchronized=no\n"
    "CanNTP=yes\n"
)


def _make_run_side_effect(timedatectl_out: str, active_service: str = "systemd-timesyncd"):
    """Return a side_effect for _run that simulates timedatectl + systemctl."""
    def _run_stub(*args):
        if args[0] == "timedatectl":
            return timedatectl_out
        if args[0] == "systemctl" and args[1] == "is-active":
            return "active\n" if args[2] == active_service else "inactive\n"
        return ""
    return _run_stub


class TestNtpFromSystemTimedatectl:
    def test_synced(self):
        with patch("bob.checks.ntp._command_exists", return_value=True), \
             patch("bob.checks.ntp._run", side_effect=_make_run_side_effect(_TIMEDATECTL_SYNCED)):
            snap = NtpSnapshot.from_system()
        assert snap.ntp_enabled
        assert snap.ntp_synchronized
        assert snap.timedatectl_ok

    def test_enabled_not_synced(self):
        with patch("bob.checks.ntp._command_exists", return_value=True), \
             patch("bob.checks.ntp._run", side_effect=_make_run_side_effect(_TIMEDATECTL_ENABLED_NOT_SYNCED)):
            snap = NtpSnapshot.from_system()
        assert snap.ntp_enabled
        assert not snap.ntp_synchronized

    def test_disabled(self):
        with patch("bob.checks.ntp._command_exists", return_value=True), \
             patch("bob.checks.ntp._run", side_effect=_make_run_side_effect(_TIMEDATECTL_DISABLED)):
            snap = NtpSnapshot.from_system()
        assert not snap.ntp_enabled
        assert not snap.ntp_synchronized

    def test_service_detected_when_enabled(self):
        with patch("bob.checks.ntp._command_exists", return_value=True), \
             patch("bob.checks.ntp._run", side_effect=_make_run_side_effect(
                 _TIMEDATECTL_SYNCED, active_service="systemd-timesyncd")):
            snap = NtpSnapshot.from_system()
        assert snap.ntp_service == "systemd-timesyncd"

    def test_service_detected_chronyd(self):
        with patch("bob.checks.ntp._command_exists", return_value=True), \
             patch("bob.checks.ntp._run", side_effect=_make_run_side_effect(
                 _TIMEDATECTL_SYNCED, active_service="chronyd")):
            snap = NtpSnapshot.from_system()
        assert snap.ntp_service == "chronyd"

    def test_timedatectl_empty_output(self):
        with patch("bob.checks.ntp._command_exists", return_value=True), \
             patch("bob.checks.ntp._run", return_value=""):
            snap = NtpSnapshot.from_system()
        assert not snap.timedatectl_ok
        assert not snap.ntp_enabled


# ---------------------------------------------------------------------------
# NtpSnapshot.from_system() — fallback path (no timedatectl)
# ---------------------------------------------------------------------------

class TestNtpFromSystemFallback:
    def test_no_timedatectl_no_service(self):
        with patch("bob.checks.ntp._command_exists", return_value=False):
            snap = NtpSnapshot.from_system()
        assert not snap.ntp_enabled
        assert not snap.timedatectl_ok

    def test_no_timedatectl_systemctl_active(self):
        def _cmd_exists(name):
            return name == "systemctl"

        def _run_stub(*args):
            if args[0] == "systemctl" and args[1] == "is-active" and args[2] == "chronyd":
                return "active\n"
            return "inactive\n"

        with patch("bob.checks.ntp._command_exists", side_effect=_cmd_exists), \
             patch("bob.checks.ntp._run", side_effect=_run_stub):
            snap = NtpSnapshot.from_system()
        assert snap.ntp_enabled
        assert snap.ntp_service == "chronyd"


# ---------------------------------------------------------------------------
# check_ntp() — pure logic
# ---------------------------------------------------------------------------

class TestCheckNtpSynced:
    def test_ok_finding(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=True, ntp_service="systemd-timesyncd")
        result = check_ntp(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.OK in levels

    def test_no_deduction(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=True, ntp_service="systemd-timesyncd")
        result = check_ntp(snap)
        assert result.deductions == []

    def test_ok_key(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=True, ntp_service="chrony")
        result = check_ntp(snap)
        assert result.findings[0].key == "ntp.synchronized"


class TestCheckNtpEnabledNotSynced:
    def test_warn_finding(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=False, ntp_service="systemd-timesyncd")
        result = check_ntp(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=False)
        result = check_ntp(snap)
        assert len(result.deductions) == 1
        assert result.deductions[0].points == 1

    def test_deduction_key(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=False)
        result = check_ntp(snap)
        assert result.deductions[0].key == "ntp.not_synchronized"

    def test_finding_key(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=False)
        result = check_ntp(snap)
        assert result.findings[0].key == "ntp.not_synchronized"

    def test_fix_cmd_present(self):
        snap = NtpSnapshot(ntp_enabled=True, ntp_synchronized=False)
        result = check_ntp(snap)
        assert result.findings[0].cmd != ""


class TestCheckNtpNotEnabled:
    def test_warn_finding(self):
        snap = NtpSnapshot(ntp_enabled=False, ntp_synchronized=False)
        result = check_ntp(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = NtpSnapshot(ntp_enabled=False)
        result = check_ntp(snap)
        assert len(result.deductions) == 1
        assert result.deductions[0].points == 1

    def test_deduction_key(self):
        snap = NtpSnapshot(ntp_enabled=False)
        result = check_ntp(snap)
        assert result.deductions[0].key == "ntp.not_enabled"

    def test_finding_key(self):
        snap = NtpSnapshot(ntp_enabled=False)
        result = check_ntp(snap)
        assert result.findings[0].key == "ntp.not_enabled"

    def test_fix_cmd_present(self):
        snap = NtpSnapshot(ntp_enabled=False)
        result = check_ntp(snap)
        assert "systemd-timesyncd" in result.findings[0].cmd

    def test_nature_improvement(self):
        snap = NtpSnapshot(ntp_enabled=False)
        result = check_ntp(snap)
        assert result.findings[0].nature == "improvement"
