"""Tests for CHECK 29 — Fail2ban intrusion prevention."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bob.checks.fail2ban import (
    Fail2banSnapshot,
    _parse_jails,
    check_fail2ban,
)
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# _parse_jails helper
# ---------------------------------------------------------------------------

class TestParseJails:
    def test_single_jail(self):
        out = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"
        assert _parse_jails(out) == ["sshd"]

    def test_multiple_jails(self):
        out = "Status\n|- Number of jail:\t3\n`- Jail list:\tsshd, nginx-http-auth, apache-auth\n"
        assert _parse_jails(out) == ["sshd", "nginx-http-auth", "apache-auth"]

    def test_empty_output(self):
        assert _parse_jails("") == []

    def test_no_jail_line(self):
        assert _parse_jails("Status\nsome other output\n") == []

    def test_case_insensitive_jail_list(self):
        # "Jail list" with capital J
        out = "Status\n`- Jail list:   sshd\n"
        assert _parse_jails(out) == ["sshd"]

    def test_strips_whitespace(self):
        out = "`- Jail list:   sshd , nginx-http-auth  \n"
        assert _parse_jails(out) == ["sshd", "nginx-http-auth"]


# ---------------------------------------------------------------------------
# Fail2banSnapshot dataclass defaults
# ---------------------------------------------------------------------------

class TestFail2banSnapshotDefaults:
    def test_installed_default_false(self):
        assert not Fail2banSnapshot().installed

    def test_service_active_default_false(self):
        assert not Fail2banSnapshot().service_active

    def test_active_jails_default_empty(self):
        assert Fail2banSnapshot().active_jails == []

    def test_ssh_jail_default_empty(self):
        assert Fail2banSnapshot().ssh_jail == ""


# ---------------------------------------------------------------------------
# Fail2banSnapshot.from_system() — not installed
# ---------------------------------------------------------------------------

class TestFail2banFromSystemNotInstalled:
    def test_installed_false_when_no_binary(self):
        with patch("bob.checks.fail2ban._command_exists", return_value=False):
            snap = Fail2banSnapshot.from_system()
        assert not snap.installed

    def test_service_active_false_when_not_installed(self):
        with patch("bob.checks.fail2ban._command_exists", return_value=False):
            snap = Fail2banSnapshot.from_system()
        assert not snap.service_active

    def test_no_jails_when_not_installed(self):
        with patch("bob.checks.fail2ban._command_exists", return_value=False):
            snap = Fail2banSnapshot.from_system()
        assert snap.active_jails == []


# ---------------------------------------------------------------------------
# Fail2banSnapshot.from_system() — installed, systemctl path
# ---------------------------------------------------------------------------

def _cmd_exists_all(name: str) -> bool:
    return True


def _make_run_stub(
    service_active: bool = True,
    status_out: str = "`- Jail list:\tsshd\n",
):
    def _run_stub(*args):
        if args[0] == "systemctl" and args[1] == "is-active":
            return "active\n" if service_active else "inactive\n"
        if args[0] == "fail2ban-client" and args[1] == "status":
            return status_out
        return ""
    return _run_stub


class TestFail2banFromSystemInstalled:
    def test_installed_true_when_binary_present(self):
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub()):
            snap = Fail2banSnapshot.from_system()
        assert snap.installed

    def test_service_active_true(self):
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub(service_active=True)):
            snap = Fail2banSnapshot.from_system()
        assert snap.service_active

    def test_service_inactive(self):
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub(service_active=False)):
            snap = Fail2banSnapshot.from_system()
        assert not snap.service_active

    def test_jails_parsed(self):
        status = "`- Jail list:\tsshd, nginx-http-auth\n"
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub(status_out=status)):
            snap = Fail2banSnapshot.from_system()
        assert snap.active_jails == ["sshd", "nginx-http-auth"]

    def test_ssh_jail_detected(self):
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub()):
            snap = Fail2banSnapshot.from_system()
        assert snap.ssh_jail == "sshd"

    def test_ssh_jail_not_set_without_ssh_jail(self):
        status = "`- Jail list:\tnginx-http-auth\n"
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub(status_out=status)):
            snap = Fail2banSnapshot.from_system()
        assert snap.ssh_jail == ""

    def test_no_jails_when_service_inactive(self):
        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists_all), \
             patch("bob.checks.fail2ban._run", side_effect=_make_run_stub(service_active=False)):
            snap = Fail2banSnapshot.from_system()
        assert snap.active_jails == []


# ---------------------------------------------------------------------------
# Fail2banSnapshot.from_system() — fallback (no systemctl, ping path)
# ---------------------------------------------------------------------------

class TestFail2banFromSystemFallback:
    def test_ping_fallback_active(self):
        def _cmd_exists(name):
            return name == "fail2ban-client"

        def _run_stub(*args):
            if args[0] == "fail2ban-client" and args[1] == "ping":
                return "Server replied: pong\n"
            if args[0] == "fail2ban-client" and args[1] == "status":
                return "`- Jail list:\tsshd\n"
            return ""

        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists), \
             patch("bob.checks.fail2ban._run", side_effect=_run_stub):
            snap = Fail2banSnapshot.from_system()
        assert snap.service_active
        assert snap.active_jails == ["sshd"]

    def test_ping_fallback_inactive(self):
        def _cmd_exists(name):
            return name == "fail2ban-client"

        def _run_stub(*args):
            return ""

        with patch("bob.checks.fail2ban._command_exists", side_effect=_cmd_exists), \
             patch("bob.checks.fail2ban._run", side_effect=_run_stub):
            snap = Fail2banSnapshot.from_system()
        assert not snap.service_active


# ---------------------------------------------------------------------------
# check_fail2ban() — not installed
# ---------------------------------------------------------------------------

class TestCheckFail2banNotInstalled:
    def test_info_finding(self):
        snap = Fail2banSnapshot(installed=False)
        result = check_fail2ban(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.INFO in levels

    def test_no_deduction(self):
        snap = Fail2banSnapshot(installed=False)
        result = check_fail2ban(snap)
        assert result.deductions == []

    def test_finding_key(self):
        snap = Fail2banSnapshot(installed=False)
        result = check_fail2ban(snap)
        assert result.findings[0].key == "fail2ban.not_installed"

    def test_install_cmd_present(self):
        snap = Fail2banSnapshot(installed=False)
        result = check_fail2ban(snap)
        assert "fail2ban" in result.findings[0].cmd


# ---------------------------------------------------------------------------
# check_fail2ban() — service inactive
# ---------------------------------------------------------------------------

class TestCheckFail2banServiceInactive:
    def test_warn_finding(self):
        snap = Fail2banSnapshot(installed=True, service_active=False)
        result = check_fail2ban(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = Fail2banSnapshot(installed=True, service_active=False)
        result = check_fail2ban(snap)
        assert len(result.deductions) == 1
        assert result.deductions[0].points == 1

    def test_deduction_key(self):
        snap = Fail2banSnapshot(installed=True, service_active=False)
        result = check_fail2ban(snap)
        assert result.deductions[0].key == "fail2ban.service_inactive"

    def test_finding_key(self):
        snap = Fail2banSnapshot(installed=True, service_active=False)
        result = check_fail2ban(snap)
        assert result.findings[0].key == "fail2ban.service_inactive"

    def test_enable_cmd_present(self):
        snap = Fail2banSnapshot(installed=True, service_active=False)
        result = check_fail2ban(snap)
        assert "fail2ban" in result.findings[0].cmd


# ---------------------------------------------------------------------------
# check_fail2ban() — running, no jails
# ---------------------------------------------------------------------------

class TestCheckFail2banNoJails:
    def test_warn_finding(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=[])
        result = check_fail2ban(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.WARN in levels

    def test_deduction_1pt(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=[])
        result = check_fail2ban(snap)
        assert len(result.deductions) == 1
        assert result.deductions[0].points == 1

    def test_deduction_key(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=[])
        result = check_fail2ban(snap)
        assert result.deductions[0].key == "fail2ban.no_jails"

    def test_finding_key(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=[])
        result = check_fail2ban(snap)
        assert result.findings[0].key == "fail2ban.no_jails"

    def test_no_jails_cmd_type_is_check(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=[])
        result = check_fail2ban(snap)
        f = next(f for f in result.findings if f.key == "fail2ban.no_jails")
        assert f.cmd_type == "check"


# ---------------------------------------------------------------------------
# check_fail2ban() — running with jails
# ---------------------------------------------------------------------------

class TestCheckFail2banActive:
    def test_ok_finding(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=["sshd"])
        result = check_fail2ban(snap)
        levels = [f.level for f in result.findings]
        assert FindingLevel.OK in levels

    def test_no_deduction(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=["sshd"])
        result = check_fail2ban(snap)
        assert result.deductions == []

    def test_active_finding_key(self):
        snap = Fail2banSnapshot(installed=True, service_active=True, active_jails=["sshd"])
        result = check_fail2ban(snap)
        assert result.findings[0].key == "fail2ban.active"

    def test_ssh_jail_finding_added(self):
        snap = Fail2banSnapshot(
            installed=True, service_active=True,
            active_jails=["sshd"], ssh_jail="sshd",
        )
        result = check_fail2ban(snap)
        keys = [f.key for f in result.findings]
        assert "fail2ban.ssh_jail_active" in keys

    def test_no_ssh_jail_finding_without_ssh_jail(self):
        snap = Fail2banSnapshot(
            installed=True, service_active=True,
            active_jails=["nginx-http-auth"], ssh_jail="",
        )
        result = check_fail2ban(snap)
        keys = [f.key for f in result.findings]
        assert "fail2ban.ssh_jail_active" not in keys

    def test_two_findings_with_ssh_jail(self):
        snap = Fail2banSnapshot(
            installed=True, service_active=True,
            active_jails=["sshd", "nginx-http-auth"], ssh_jail="sshd",
        )
        result = check_fail2ban(snap)
        assert len(result.findings) == 2

    def test_one_finding_without_ssh_jail(self):
        snap = Fail2banSnapshot(
            installed=True, service_active=True,
            active_jails=["nginx-http-auth"], ssh_jail="",
        )
        result = check_fail2ban(snap)
        assert len(result.findings) == 1
