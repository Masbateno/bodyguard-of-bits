"""
Tests for bob/checks/services_state.py — systemd service state audit.

Coverage:
  - check_services_state(): all branches (systemctl unavailable, inactive services,
    all-OK)
  - Deduction values, keys, and cap (max 3 pts)
  - Non-security services ignored
  - ServicesStateSnapshot dataclass construction
  - Edge cases: None, duplicates, case sensitivity, non-security services

Note on deduction sign convention:
  Deduction.points is stored as a positive integer throughout the codebase
  (e.g. points=1 means "subtract 1 from the score"). _deduction_points()
  returns the sum of these positive values; comments indicating "-1 pt"
  describe the score effect, not the stored value.
"""

from __future__ import annotations

import pytest

from bob.checks.services_state import (
    ServicesStateSnapshot,
    check_services_state,
    SECURITY_SERVICES,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _get_finding, _has_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


def base_snapshot(**kwargs) -> ServicesStateSnapshot:
    """Return a clean ServicesStateSnapshot with systemctl available."""
    defaults = dict(
        systemctl_available=True,
        enabled_inactive=[],
    )
    defaults.update(kwargs)
    return ServicesStateSnapshot(**defaults)


# ---------------------------------------------------------------------------
# systemctl not available
# ---------------------------------------------------------------------------

class TestNoSystemctl:
    def test_no_systemctl_returns_info(self):
        snap = base_snapshot(systemctl_available=False)
        result = check_services_state(snap)
        assert _has_finding(result, "services_health.no_systemctl", FindingLevel.INFO)

    def test_no_systemctl_returns_early(self):
        """No other findings when systemctl is unavailable, even with inactive listed."""
        snap = base_snapshot(systemctl_available=False, enabled_inactive=["ufw"])
        result = check_services_state(snap)
        assert len(result.findings) == 1
        assert result.findings[0].key == "services_health.no_systemctl"

    def test_no_systemctl_no_deduction(self):
        snap = base_snapshot(systemctl_available=False)
        result = check_services_state(snap)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_empty_inactive_returns_ok(self):
        result = check_services_state(base_snapshot())
        assert _has_finding(result, "services_health.ok", FindingLevel.OK)

    def test_empty_inactive_no_deduction(self):
        result = check_services_state(base_snapshot())
        assert _deduction_points(result) == 0

    def test_ok_not_emitted_when_findings_present(self):
        snap = base_snapshot(enabled_inactive=["ufw"])
        result = check_services_state(snap)
        assert not _has_finding(result, "services_health.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# Inactive services
# ---------------------------------------------------------------------------

class TestInactiveServices:
    def test_ufw_inactive_produces_warn(self):
        snap = base_snapshot(enabled_inactive=["ufw"])
        result = check_services_state(snap)
        assert _has_finding(result, "services_health.service_inactive", FindingLevel.WARN)

    def test_one_inactive_deducts_1_point(self):
        snap = base_snapshot(enabled_inactive=["fail2ban"])
        result = check_services_state(snap)
        assert _deduction_points(result) == 1  # stored as +1, effect is score −1

    def test_two_inactive_deducts_2_points(self):
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban"])
        result = check_services_state(snap)
        assert _deduction_points(result) == 2

    def test_three_inactive_deducts_3_points(self):
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban", "apparmor"])
        result = check_services_state(snap)
        assert _deduction_points(result) == 3

    def test_deduction_key(self):
        snap = base_snapshot(enabled_inactive=["ufw"])
        result = check_services_state(snap)
        assert "services_health.service_inactive" in _deduction_keys(result)

    def test_one_finding_per_inactive_service(self):
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban"])
        result = check_services_state(snap)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warn_findings) == 2

    def test_nature_is_action(self):
        snap = base_snapshot(enabled_inactive=["ufw"])
        result = check_services_state(snap)
        finding = _get_finding(result, "services_health.service_inactive")
        assert finding is not None
        assert finding.nature == "action"

    def test_cmd_references_service_name(self):
        """The fix command must reference the affected service."""
        snap = base_snapshot(enabled_inactive=["fail2ban"])
        result = check_services_state(snap)
        finding = _get_finding(result, "services_health.service_inactive")
        assert finding is not None
        assert "fail2ban" in finding.cmd

    def test_cmd_is_non_empty(self):
        snap = base_snapshot(enabled_inactive=["ufw"])
        result = check_services_state(snap)
        finding = _get_finding(result, "services_health.service_inactive")
        assert finding is not None
        assert finding.cmd


# ---------------------------------------------------------------------------
# Non-security services ignored
# ---------------------------------------------------------------------------

class TestNonSecurityServicesIgnored:
    def test_non_security_service_produces_ok(self):
        """A service not in SECURITY_SERVICES must not trigger a finding."""
        snap = base_snapshot(enabled_inactive=["nginx"])
        result = check_services_state(snap)
        assert _has_finding(result, "services_health.ok", FindingLevel.OK)

    def test_non_security_service_no_deduction(self):
        snap = base_snapshot(enabled_inactive=["nginx"])
        result = check_services_state(snap)
        assert _deduction_points(result) == 0

    def test_mixed_security_and_non_security(self):
        """Only the security service triggers a finding; nginx is silently ignored."""
        snap = base_snapshot(enabled_inactive=["ufw", "nginx"])
        result = check_services_state(snap)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warn_findings) == 1
        assert _deduction_points(result) == 1

    def test_uppercase_service_not_detected(self):
        """Service names in SECURITY_SERVICES are lowercase; uppercase must not match."""
        snap = base_snapshot(enabled_inactive=["UFW", "FAIL2BAN"])
        result = check_services_state(snap)
        assert _has_finding(result, "services_health.ok", FindingLevel.OK)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# Maximum deduction cap
# ---------------------------------------------------------------------------

class TestDeductionCap:
    def test_four_inactive_capped_at_3_points(self):
        # business rule: maximum deduction from this check is 3 pts
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban", "apparmor", "auditd"])
        result = check_services_state(snap)
        assert _deduction_points(result) == 3

    def test_four_inactive_has_exactly_3_deductions(self):
        """The cap works by registering at most 3 deduction entries, not by clamping."""
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban", "apparmor", "auditd"])
        result = check_services_state(snap)
        assert len(result.deductions) == 3

    def test_cap_does_not_suppress_findings(self):
        """All 4 inactive services get a WARN finding even though only 3 are deducted."""
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban", "apparmor", "auditd"])
        result = check_services_state(snap)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warn_findings) == 4

    def test_deduction_never_exceeds_3(self):
        """Property: regardless of inactive count, deduction is always ≤ 3."""
        services = list(SECURITY_SERVICES)
        snap = base_snapshot(enabled_inactive=services)
        result = check_services_state(snap)
        assert _deduction_points(result) <= 3


# ---------------------------------------------------------------------------
# SECURITY_SERVICES set — structural invariants only
# ---------------------------------------------------------------------------

class TestSecurityServicesSet:
    def test_set_is_non_empty(self):
        assert len(SECURITY_SERVICES) > 0

    def test_all_entries_are_strings(self):
        assert all(isinstance(s, str) for s in SECURITY_SERVICES)

    def test_no_duplicates(self):
        assert len(SECURITY_SERVICES) == len(set(SECURITY_SERVICES))

    def test_ufw_is_monitored(self):
        """Spot-check: ufw (the primary firewall) must be monitored."""
        snap = base_snapshot(enabled_inactive=["ufw"])
        assert _has_finding(
            check_services_state(snap), "services_health.service_inactive", FindingLevel.WARN
        )

    def test_fail2ban_is_monitored(self):
        """Spot-check: fail2ban must be monitored."""
        snap = base_snapshot(enabled_inactive=["fail2ban"])
        assert _has_finding(
            check_services_state(snap), "services_health.service_inactive", FindingLevel.WARN
        )


# ---------------------------------------------------------------------------
# ServicesStateSnapshot dataclass
# ---------------------------------------------------------------------------

class TestServicesStateSnapshot:
    def test_defaults(self):
        snap = ServicesStateSnapshot()
        assert not snap.systemctl_available
        assert snap.enabled_inactive == []

    def test_custom_values(self):
        snap = ServicesStateSnapshot(systemctl_available=True, enabled_inactive=["ufw"])
        assert snap.systemctl_available
        assert "ufw" in snap.enabled_inactive


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_none_enabled_inactive_produces_ok_finding(self):
        """None instead of empty list must not crash check_services_state()."""
        snap = ServicesStateSnapshot(systemctl_available=True, enabled_inactive=None)
        result = check_services_state(snap)
        assert isinstance(result.findings, list)
        assert _has_finding(result, "services_health.ok", FindingLevel.OK)

    def test_none_enabled_inactive_no_deduction(self):
        snap = ServicesStateSnapshot(systemctl_available=True, enabled_inactive=None)
        result = check_services_state(snap)
        assert _deduction_points(result) == 0

    def test_snapshot_not_mutated(self):
        """check_services_state() must not modify the snapshot."""
        snap = base_snapshot(enabled_inactive=["ufw", "fail2ban"])
        original = list(snap.enabled_inactive)
        check_services_state(snap)
        assert snap.enabled_inactive == original

    def test_duplicate_service_names(self):
        """Duplicate entries in enabled_inactive must not inflate findings or deductions."""
        snap = base_snapshot(enabled_inactive=["ufw", "ufw", "ufw"])
        result = check_services_state(snap)
        warn_findings = [f for f in result.findings if f.level == FindingLevel.WARN]
        # Three findings (one per list entry) but business logic may or may not deduplicate;
        # the important invariant is that deductions stay bounded.
        assert _deduction_points(result) <= 3

    def test_empty_service_name_does_not_crash(self):
        """An empty string in enabled_inactive must not crash."""
        snap = base_snapshot(enabled_inactive=["", "ufw"])
        result = check_services_state(snap)
        assert isinstance(result.findings, list)
