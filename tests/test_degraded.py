"""
Degraded-mode tests for bob.

Tests cover behaviour when key system tools are unavailable or return nothing:
  - ss not available → PortsSnapshot with empty ports/ss_output
  - UFW rules output empty or without rule lines → check_rules input
  - UFW log file missing or empty → LogsSnapshot degraded states
  - Combined: multiple modules degraded simultaneously — no crash, no spurious findings

No subprocess calls are made — all snapshots are built directly.

Run with: python -m pytest tests/test_degraded.py -v
"""

from __future__ import annotations

import pytest

from datetime import datetime, timezone

from bob.checks.firewall import FirewallStatus, check_firewall, check_rules
from bob.checks.logs import LogEntry, LogsSnapshot, check_logs
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from bob.scoring import FindingLevel
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def has_level(result, level):
    return level in _levels(result)


def total_deductions(result):
    return sum(d.points for d in result.deductions)


def make_fw(installed=True, active=True, incoming_policy="deny",
            ufw_output="", numbered_output="", ipv4_rules_count=0, ipv6_rules_count=0):
    return FirewallStatus(
        installed=installed,
        active=active,
        incoming_policy=incoming_policy,
        ufw_output=ufw_output,
        numbered_output=numbered_output,
        ipv4_rules_count=ipv4_rules_count,
        ipv6_rules_count=ipv6_rules_count,
    )


def make_ports_snapshot(ports=None, ufw_rules="", ss_output=""):
    return PortsSnapshot(
        ports=ports if ports is not None else [],
        ufw_rules=ufw_rules,
        ss_output=ss_output,
    )


def make_logs_snapshot(entries=None, days_available=0, log_days=7, log_found=True):
    return LogsSnapshot(
        entries=entries if entries is not None else [],
        days_available=days_available,
        log_days=log_days,
        log_found=log_found,
    )


# ---------------------------------------------------------------------------
# ss not available → empty PortsSnapshot
# ---------------------------------------------------------------------------

class TestSSNotAvailable:
    """
    When `ss` is not installed or returns nothing, PortsSnapshot.from_system()
    produces an empty ports list and empty ss_output.  check_ports() must handle
    this gracefully: no crash, no deductions, an OK finding.
    """

    def test_no_ports_emits_ok(self):
        """Empty ports list → 'ports.all_covered' OK finding."""
        result = check_ports(make_ports_snapshot(), t=_t)
        assert has_level(result, "ok")

    def test_no_ports_zero_deductions(self):
        """Empty ports list → zero score deductions."""
        result = check_ports(make_ports_snapshot(), t=_t)
        assert total_deductions(result) == 0

    def test_no_ports_no_alert(self):
        """Empty ports list → no alert finding."""
        result = check_ports(make_ports_snapshot(), t=_t)
        assert not has_level(result, "alert")

    def test_ufw_rules_present_but_no_ports_still_ok(self):
        """UFW rules in snapshot but zero listening ports → still OK, zero deductions."""
        rules = "[ 1] 22/tcp    ALLOW IN    Anywhere\n[ 2] 80/tcp    ALLOW IN    Anywhere\n"
        result = check_ports(make_ports_snapshot(ufw_rules=rules), t=_t)
        assert has_level(result, "ok")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# UFW rules output empty or without rule lines
# ---------------------------------------------------------------------------

class TestCheckRulesEmptyOutput:
    """
    check_rules() receives `ufw_verbose` and `ufw_numbered` strings.
    When UFW is inactive or not installed, __main__.py passes empty strings.
    The function must not crash and must not emit spurious deductions.
    """

    def test_empty_strings_no_deductions(self):
        """check_rules('', '', t) → zero deductions."""
        result = check_rules("", "", _t)
        assert total_deductions(result) == 0

    def test_empty_strings_no_alert(self):
        """check_rules('', '', t) → no alert finding."""
        result = check_rules("", "", _t)
        assert not has_level(result, "alert")

    def test_whitespace_only_no_deductions(self):
        """Whitespace/newline-only input → zero deductions."""
        result = check_rules("  \n  \n", "  \n  \n", _t)
        assert total_deductions(result) == 0

    def test_header_lines_only_no_deductions(self):
        """
        Output with status header but no '[N] rule' lines
        (typical of `ufw status numbered` when UFW is inactive).
        """
        numbered = "Status: inactive\n"
        verbose  = "Status: inactive\n"
        result = check_rules(verbose, numbered, _t)
        assert total_deductions(result) == 0

    def test_header_lines_only_no_alert(self):
        """Status header without rule lines → no alert."""
        numbered = "Status: inactive\nDefault: deny (incoming)\n"
        result = check_rules("", numbered, _t)
        assert not has_level(result, "alert")


# ---------------------------------------------------------------------------
# UFW log file missing or unreadable
# ---------------------------------------------------------------------------

class TestLogFileDegraded:
    """
    Complements the existing test_logs.py coverage by asserting on score
    deductions for all degraded log states.
    """

    def test_missing_log_zero_deductions(self):
        """log_found=False → INFO finding, zero deductions."""
        result = check_logs(make_logs_snapshot(log_found=False), t=_t)
        assert total_deductions(result) == 0

    def test_missing_log_emits_info(self):
        """log_found=False → INFO (not WARN/ALERT)."""
        result = check_logs(make_logs_snapshot(log_found=False), t=_t)
        assert has_level(result, "info")
        assert not has_level(result, "alert")
        assert not has_level(result, "warn")

    def test_entries_below_bruteforce_threshold_no_warn(self):
        """
        A single valid LogEntry (far below the bruteforce threshold) must not
        produce a WARN or deduction — only informational findings at most.
        """
        single_entry = LogEntry(
            timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            src_ip="1.2.3.4",
            dst_port=22,
            proto="TCP",
        )
        snap = make_logs_snapshot(
            entries=[single_entry], days_available=1, log_found=True
        )
        result = check_logs(snap, t=_t)
        assert not has_level(result, "warn")
        assert not has_level(result, "alert")
        assert total_deductions(result) == 0

    def test_empty_log_zero_deductions(self):
        """log found but no entries → OK finding, zero deductions."""
        result = check_logs(
            make_logs_snapshot(log_found=True, entries=[], days_available=0),
            t=_t,
        )
        assert total_deductions(result) == 0

    def test_empty_log_emits_ok(self):
        """log found but no entries → OK (not WARN/ALERT)."""
        result = check_logs(
            make_logs_snapshot(log_found=True, entries=[], days_available=5),
            t=_t,
        )
        assert has_level(result, "ok")
        assert not has_level(result, "alert")


# ---------------------------------------------------------------------------
# Combined degradation — multiple modules degraded simultaneously
# ---------------------------------------------------------------------------

class TestCombinedDegradation:
    """
    Simulate a system where UFW is inactive, ss is unavailable, and
    no log file exists.  Each check must run independently without crashing,
    and degraded states must not compound into spurious deductions.
    """

    def test_empty_ports_and_empty_rules_no_crash(self):
        """check_ports + check_rules both run with empty input — no exception."""
        ports_result = check_ports(make_ports_snapshot(), t=_t)
        rules_result = check_rules("", "", _t)
        assert ports_result is not None
        assert rules_result is not None

    def test_empty_rules_and_missing_log_zero_combined_deductions(self):
        """check_rules(empty) + check_logs(missing) together → zero combined deductions."""
        rules_result = check_rules("", "", _t)
        logs_result  = check_logs(make_logs_snapshot(log_found=False), t=_t)
        combined = total_deductions(rules_result) + total_deductions(logs_result)
        assert combined == 0

    def test_all_three_degraded_no_crash(self):
        """
        All three degraded checks run sequentially — no exception raised.
        (UFW inactive is represented by empty rules strings; the firewall
        inactive finding itself is tested separately in test_firewall.py.)
        """
        rules_result = check_rules("", "", _t)
        ports_result = check_ports(make_ports_snapshot(), t=_t)
        logs_result  = check_logs(make_logs_snapshot(log_found=False), t=_t)
        # All return valid CheckResult objects
        assert all(r is not None for r in [rules_result, ports_result, logs_result])

    def test_degraded_ports_and_logs_zero_deductions(self):
        """Empty ports + missing log → combined deductions are zero."""
        ports_result = check_ports(make_ports_snapshot(), t=_t)
        logs_result  = check_logs(make_logs_snapshot(log_found=False), t=_t)
        combined = total_deductions(ports_result) + total_deductions(logs_result)
        assert combined == 0

    def test_firewall_inactive_and_empty_ports_no_conflict(self):
        """
        check_firewall(inactive) emits an ALERT; check_ports(empty) emits an OK.
        Running both must not raise and findings must not contradict each other.
        """
        fw_result    = check_firewall(make_fw(active=False), t=_t)
        ports_result = check_ports(make_ports_snapshot(), t=_t)
        assert fw_result is not None
        assert ports_result is not None
        # Firewall inactive → at least one ALERT
        assert has_level(fw_result, "alert")
        # Empty ports → OK, no alert
        assert has_level(ports_result, "ok")
        assert not has_level(ports_result, "alert")

    def test_firewall_inactive_and_empty_rules_consistent(self):
        """
        check_firewall(inactive) + check_rules(empty) — typical state when UFW
        has just been disabled.  Neither check should crash or emit deductions
        on top of the firewall-inactive finding.
        """
        fw_result    = check_firewall(make_fw(active=False), t=_t)
        rules_result = check_rules("", "", _t)
        # check_rules with no rules → zero deductions (firewall audit is separate)
        assert total_deductions(rules_result) == 0
        # check_firewall(inactive) carries its own deduction via score cap, not here
        assert fw_result is not None
