"""
Unit tests for bob.checks.auditd module.

All tests use AuditdSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_auditd.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.auditd import (
    AuditdSnapshot,
    _count_rules,
    _parse_watched_files,
    _suggest_rules_cmd,
    check_auditd,
)
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(**overrides) -> AuditdSnapshot:
    defaults = dict(
        installed=True,
        service_active=True,
        watched_files={"/etc/passwd", "/etc/shadow", "/etc/sudoers"},
        rule_count=3,
    )
    defaults.update(overrides)
    return AuditdSnapshot(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


# ---------------------------------------------------------------------------
# Not installed
# ---------------------------------------------------------------------------

class TestNotInstalled:
    def test_info_when_not_installed(self):
        snap = AuditdSnapshot(installed=False)
        result = check_auditd(snap, t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_not_installed(self):
        snap = AuditdSnapshot(installed=False)
        result = check_auditd(snap, t=_t)
        assert total_deductions(result) == 0

    def test_key_when_not_installed(self):
        snap = AuditdSnapshot(installed=False)
        result = check_auditd(snap, t=_t)
        assert "auditd.not_installed" in finding_keys(result)

    def test_install_cmd_present(self):
        snap = AuditdSnapshot(installed=False)
        result = check_auditd(snap, t=_t)
        matches = [f for f in result.findings if f.key == "auditd.not_installed"]
        assert matches, "missing finding auditd.not_installed"
        assert "apt install" in (matches[0].cmd or "")


# ---------------------------------------------------------------------------
# Service inactive
# ---------------------------------------------------------------------------

class TestServiceInactive:
    def test_warn_when_service_inactive(self):
        snap = make_snap(service_active=False, watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_service_inactive(self):
        snap = make_snap(service_active=False, watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        assert total_deductions(result) == 1

    def test_key_when_service_inactive(self):
        snap = make_snap(service_active=False, watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        assert "auditd.service_inactive" in finding_keys(result)

    def test_enable_cmd_present(self):
        snap = make_snap(service_active=False, watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        matches = [f for f in result.findings if f.key == "auditd.service_inactive"]
        assert matches, "missing finding auditd.service_inactive"
        assert "systemctl enable" in (matches[0].cmd or "")


# ---------------------------------------------------------------------------
# No rules loaded
# ---------------------------------------------------------------------------

class TestNoRules:
    def test_warn_when_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        assert total_deductions(result) == 1

    def test_key_when_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        assert "auditd.no_rules" in finding_keys(result)

    def test_check_cmd_type_on_no_rules(self):
        """The fix command should be cmd_type='fix' (actionable rules)."""
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t)
        matches = [f for f in result.findings if f.key == "auditd.no_rules"]
        assert matches, "missing finding auditd.no_rules"
        assert matches[0].cmd_type == "fix"

    def test_info_on_desktop_when_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t, profile_name="desktop")
        assert has_level(result, "info")

    def test_no_deduction_on_desktop_when_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t, profile_name="desktop")
        assert total_deductions(result) == 0

    def test_workstation_alias_no_deduction_when_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t, profile_name="workstation")
        assert total_deductions(result) == 0

    def test_fix_cmd_present_on_desktop_no_rules(self):
        snap = make_snap(watched_files=set(), rule_count=0)
        result = check_auditd(snap, t=_t, profile_name="desktop")
        matches = [f for f in result.findings if f.key == "auditd.no_rules"]
        assert matches[0].cmd_type == "fix"


# ---------------------------------------------------------------------------
# Missing sensitive file rules
# ---------------------------------------------------------------------------

class TestMissingSensitiveRules:
    def test_warn_on_server_when_sensitive_missing(self):
        snap = make_snap(watched_files={"/etc/passwd"}, rule_count=1)
        result = check_auditd(snap, t=_t, profile_name="server")
        assert has_level(result, "warn")

    def test_deduction_on_server_when_sensitive_missing(self):
        snap = make_snap(watched_files={"/etc/passwd"}, rule_count=1)
        result = check_auditd(snap, t=_t, profile_name="server")
        assert total_deductions(result) == 1

    def test_info_on_desktop_when_sensitive_missing(self):
        snap = make_snap(watched_files={"/etc/passwd"}, rule_count=1)
        result = check_auditd(snap, t=_t, profile_name="desktop")
        assert has_level(result, "info")

    def test_no_deduction_on_desktop_when_sensitive_missing(self):
        snap = make_snap(watched_files={"/etc/passwd"}, rule_count=1)
        result = check_auditd(snap, t=_t, profile_name="desktop")
        assert total_deductions(result) == 0

    def test_workstation_alias_behaves_like_desktop(self):
        snap = make_snap(watched_files={"/etc/passwd"}, rule_count=1)
        result = check_auditd(snap, t=_t, profile_name="workstation")
        assert has_level(result, "info")
        assert total_deductions(result) == 0

    def test_missing_files_in_detail(self):
        received = {}

        def _capture(key, **kwargs):
            received[key] = kwargs
            return key

        snap = make_snap(watched_files={"/etc/passwd"}, rule_count=1)
        check_auditd(snap, t=_capture, profile_name="server")
        files_str = received.get("auditd.missing_sensitive_rules_detail", {}).get("files", "")
        assert "/etc/shadow" in files_str
        assert "/etc/sudoers" in files_str

    def test_no_warn_when_all_covered(self):
        snap = make_snap()
        result = check_auditd(snap, t=_t)
        assert not has_level(result, "warn")

    def test_no_deductions_when_all_covered(self):
        snap = make_snap()
        result = check_auditd(snap, t=_t)
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Clean system — all rules present
# ---------------------------------------------------------------------------

class TestCleanSystem:
    def test_ok_when_all_covered(self):
        result = check_auditd(make_snap(), t=_t)
        assert has_level(result, "ok")

    def test_two_ok_findings(self):
        """One OK for 'active', one OK for 'sensitive files watched'."""
        result = check_auditd(make_snap(), t=_t)
        ok_count = sum(1 for f in result.findings if f.level.value == "ok")
        assert ok_count == 2

    def test_active_key_present(self):
        result = check_auditd(make_snap(), t=_t)
        assert "auditd.active" in finding_keys(result)

    def test_sensitive_files_watched_key_present(self):
        result = check_auditd(make_snap(), t=_t)
        assert "auditd.sensitive_files_watched" in finding_keys(result)

    def test_rule_count_passed_to_t(self):
        received = {}

        def _capture(key, **kwargs):
            if "count" in kwargs:
                received.update(kwargs)
            return key

        check_auditd(make_snap(rule_count=7), t=_capture)
        assert received.get("count") == 7


# ---------------------------------------------------------------------------
# _parse_watched_files
# ---------------------------------------------------------------------------

class TestParseWatchedFiles:
    AUDITCTL_OUTPUT = (
        "-w /etc/passwd -p rwxa -k identity\n"
        "-w /etc/shadow -p rwxa -k identity\n"
        "-w /etc/sudoers -p rwxa -k identity\n"
        "-a always,exit -F arch=b64 -S execve -k exec\n"
    )

    def test_detects_passwd(self):
        assert "/etc/passwd" in _parse_watched_files(self.AUDITCTL_OUTPUT)

    def test_detects_shadow(self):
        assert "/etc/shadow" in _parse_watched_files(self.AUDITCTL_OUTPUT)

    def test_detects_sudoers(self):
        assert "/etc/sudoers" in _parse_watched_files(self.AUDITCTL_OUTPUT)

    def test_does_not_include_syscall_rules(self):
        """Lines starting with -a/-A (syscall rules) must not appear."""
        result = _parse_watched_files(self.AUDITCTL_OUTPUT)
        assert not any("execve" in p for p in result)

    def test_empty_string_returns_empty(self):
        assert _parse_watched_files("") == set()

    def test_no_rules_output_returns_empty(self):
        assert _parse_watched_files("No rules\n") == set()

    def test_trailing_slash_normalised(self):
        """Paths like /etc/sudoers.d/ should be normalised."""
        out = "-w /etc/sudoers.d/ -p rwxa -k sudoers\n"
        result = _parse_watched_files(out)
        assert "/etc/sudoers.d" in result

    def test_multiple_files(self):
        result = _parse_watched_files(self.AUDITCTL_OUTPUT)
        assert len(result) == 3

    def test_ignores_malformed_watch_lines(self):
        """Lines like '-w -p rwxa' with no path must not produce a result."""
        out = "-w -p rwxa\n"
        result = _parse_watched_files(out)
        assert result == set()


# ---------------------------------------------------------------------------
# _count_rules
# ---------------------------------------------------------------------------

class TestCountRules:
    def test_counts_watch_and_syscall_rules(self):
        # Counts both -w (watch) and -a/-A (syscall) rules — total rules loaded.
        out = (
            "-w /etc/passwd -p rwxa -k identity\n"
            "-w /etc/shadow -p rwxa -k identity\n"
            "-a always,exit -F arch=b64 -S execve -k exec\n"
        )
        assert _count_rules(out) == 3

    def test_no_rules_returns_zero(self):
        assert _count_rules("No rules\n") == 0

    def test_empty_returns_zero(self):
        assert _count_rules("") == 0

    def test_blank_lines_ignored(self):
        out = "\n-w /etc/passwd -p rwxa -k identity\n\n"
        assert _count_rules(out) == 1

    def test_header_lines_ignored(self):
        """Lines that are not -w/-a/-A must not be counted."""
        out = "## This is generated by augenrules\n-w /etc/passwd -p rwxa -k id\n"
        assert _count_rules(out) == 1

    def test_error_lines_ignored(self):
        """Unexpected text (e.g. auditctl errors) must not inflate the count."""
        out = "Error sending add rule data request (No such file or directory)\n"
        assert _count_rules(out) == 0


# ---------------------------------------------------------------------------
# _suggest_rules_cmd
# ---------------------------------------------------------------------------

class TestSuggestRulesCmd:
    def test_single_file(self):
        cmd = _suggest_rules_cmd(["/etc/shadow"])
        assert "/etc/shadow" in cmd

    def test_multiple_files_joined(self):
        cmd = _suggest_rules_cmd(["/etc/passwd", "/etc/shadow"])
        assert "/etc/passwd" in cmd
        assert "/etc/shadow" in cmd
        assert "&&" in cmd

    def test_includes_rwxa_permissions(self):
        cmd = _suggest_rules_cmd(["/etc/passwd"])
        assert "-p rwxa" in cmd

    def test_includes_key(self):
        cmd = _suggest_rules_cmd(["/etc/passwd"])
        assert "-k sensitive_files" in cmd

    def test_persistent_rules_file(self):
        """Command must write to /etc/audit/rules.d/ for persistence across reboots."""
        cmd = _suggest_rules_cmd(["/etc/passwd"])
        assert "/etc/audit/rules.d/" in cmd

    def test_reloads_via_augenrules(self):
        """Command must trigger augenrules --load to apply rules immediately."""
        cmd = _suggest_rules_cmd(["/etc/passwd"])
        assert "augenrules --load" in cmd
