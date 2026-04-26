"""
Tests for bob/checks/updates.py — system update status audit.

Coverage:
  - check_updates(): all branches (security pending, regular pending,
    unattended configured/not, apt unavailable, all-OK)
  - Deduction values and keys
  - Combined scenarios
  - UpdatesSnapshot dataclass construction
"""

from __future__ import annotations

import pytest

from bob.checks.updates import UpdatesSnapshot, check_updates
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _has_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


def base_snapshot(**kwargs) -> UpdatesSnapshot:
    """Return a clean UpdatesSnapshot with apt available and nothing pending."""
    defaults = dict(
        apt_available=True,
        pending_security=[],
        pending_regular=[],
        unattended_installed=True,
        unattended_enabled=True,
    )
    defaults.update(kwargs)
    return UpdatesSnapshot(**defaults)


# ---------------------------------------------------------------------------
# apt not available
# ---------------------------------------------------------------------------

class TestNoApt:
    def test_no_apt_returns_info(self):
        snap = base_snapshot(apt_available=False)
        result = check_updates(snap)
        assert _has_finding(result, "updates.no_apt", FindingLevel.INFO)

    def test_no_apt_returns_early(self):
        """No other findings emitted when apt is unavailable."""
        snap = base_snapshot(apt_available=False,
                             pending_security=["libssl3"],
                             unattended_installed=False)
        result = check_updates(snap)
        assert len(result.findings) == 1
        assert result.findings[0].key == "updates.no_apt"

    def test_no_apt_no_deduction(self):
        snap = base_snapshot(apt_available=False)
        result = check_updates(snap)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_up_to_date_returns_ok(self):
        result = check_updates(base_snapshot())
        assert _has_finding(result, "updates.ok", FindingLevel.OK)

    def test_up_to_date_no_deduction(self):
        result = check_updates(base_snapshot())
        assert _deduction_points(result) == 0

    def test_ok_only_when_no_findings(self):
        """OK finding is only appended when result.findings is empty."""
        snap = base_snapshot(pending_regular=["vim"])
        result = check_updates(snap)
        assert not _has_finding(result, "updates.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# Security packages pending
# ---------------------------------------------------------------------------

class TestSecurityPending:
    def test_security_pending_produces_warn(self):
        snap = base_snapshot(pending_security=["libssl3"])
        result = check_updates(snap)
        assert _has_finding(result, "updates.security_pending", FindingLevel.WARN)

    def test_security_pending_deducts_2_points(self):
        snap = base_snapshot(pending_security=["libssl3"])
        result = check_updates(snap)
        assert _deduction_points(result) == 2

    def test_security_pending_deduction_key(self):
        snap = base_snapshot(pending_security=["libssl3"])
        result = check_updates(snap)
        assert "updates.security_pending" in _deduction_keys(result)

    def test_security_pending_flat_deduction_regardless_of_count(self):
        """10 security packages → still only -2 pts (flat deduction)."""
        pkgs = [f"pkg{i}" for i in range(10)]
        snap = base_snapshot(pending_security=pkgs)
        result = check_updates(snap)
        assert _deduction_points(result) == 2

    def test_security_pending_no_ok(self):
        snap = base_snapshot(pending_security=["libssl3"])
        result = check_updates(snap)
        assert not _has_finding(result, "updates.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# Regular packages pending
# ---------------------------------------------------------------------------

class TestRegularPending:
    def test_regular_pending_produces_info(self):
        snap = base_snapshot(pending_regular=["vim", "curl"])
        result = check_updates(snap)
        assert _has_finding(result, "updates.regular_pending", FindingLevel.INFO)

    def test_regular_pending_no_deduction(self):
        snap = base_snapshot(pending_regular=["vim", "curl"])
        result = check_updates(snap)
        assert _deduction_points(result) == 0

    def test_regular_pending_no_ok(self):
        """INFO finding → result.findings not empty → OK not appended."""
        snap = base_snapshot(pending_regular=["vim"])
        result = check_updates(snap)
        assert not _has_finding(result, "updates.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# unattended-upgrades
# ---------------------------------------------------------------------------

class TestUnattended:
    def test_not_configured_up_to_date_produces_info(self):
        snap = base_snapshot(unattended_installed=False, unattended_enabled=False)
        result = check_updates(snap)
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.INFO)

    def test_not_configured_up_to_date_no_deduction(self):
        snap = base_snapshot(unattended_installed=False, unattended_enabled=False)
        result = check_updates(snap)
        assert _deduction_points(result) == 0

    def test_not_configured_with_security_pending_produces_warn(self):
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.WARN)

    def test_not_configured_with_security_pending_deducts_1_point(self):
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        assert "updates.unattended_not_configured" in _deduction_keys(result)
        uu_pts = next(
            d.points for d in result.deductions
            if d.key == "updates.unattended_not_configured"
        )
        assert uu_pts == 1

    def test_installed_but_not_enabled_treated_as_not_configured(self):
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=True,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.WARN)

    def test_configured_no_warning(self):
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=True,
            unattended_enabled=True,
        )
        result = check_updates(snap)
        assert not _has_finding(
            result, "updates.unattended_not_configured", FindingLevel.WARN
        )


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_security_and_no_unattended_total_deduction(self):
        """Security pending (-2) + unattended not configured (-1) = -3 pts."""
        snap = base_snapshot(
            pending_security=["libssl3", "openssl"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        assert _deduction_points(result) == 3

    def test_security_and_regular_and_no_unattended(self):
        snap = base_snapshot(
            pending_security=["libssl3"],
            pending_regular=["vim"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        infos = [f for f in result.findings if f.level == FindingLevel.INFO]
        assert len(warns) == 2   # security_pending + unattended_not_configured
        assert len(infos) == 1   # regular_pending
        assert _deduction_points(result) == 3

    def test_regular_only_with_unattended_ok(self):
        snap = base_snapshot(pending_regular=["vim"])
        result = check_updates(snap)
        assert _deduction_points(result) == 0
        assert _has_finding(result, "updates.regular_pending", FindingLevel.INFO)
        assert not _has_finding(result, "updates.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# UpdatesSnapshot dataclass
# ---------------------------------------------------------------------------

class TestUpdatesSnapshot:
    def test_defaults(self):
        snap = UpdatesSnapshot()
        assert not snap.apt_available
        assert snap.pending_security == []
        assert snap.pending_regular == []
        assert not snap.unattended_installed
        assert not snap.unattended_enabled


# ---------------------------------------------------------------------------
# Edge cases and invariants (quality pass)
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_no_updates_but_unattended_missing(self):
        """Up-to-date system without unattended-upgrades emits INFO, not OK."""
        snap = base_snapshot(unattended_installed=False, unattended_enabled=False)
        result = check_updates(snap)
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.INFO)
        assert not _has_finding(result, "updates.ok", FindingLevel.OK)

    def test_findings_order_independent(self):
        """Finding keys are present regardless of emission order."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        keys = set(_finding_keys(result))
        assert "updates.security_pending" in keys
        assert "updates.unattended_not_configured" in keys

    def test_ignores_empty_package_names(self):
        """A list containing an empty string is still truthy — WARN is emitted."""
        snap = base_snapshot(pending_security=["", "libssl3"])
        result = check_updates(snap)
        assert _has_finding(result, "updates.security_pending", FindingLevel.WARN)
        assert _deduction_points(result) == 2

    def test_duplicate_packages_do_not_change_score(self):
        """Repeated package names in pending_security still yield -2 pts (flat)."""
        snap = base_snapshot(pending_security=["a", "a", "a"])
        result = check_updates(snap)
        assert _deduction_points(result) == 2

    def test_no_apt_ignores_all_other_inputs(self):
        """When apt is unavailable, no deductions are made regardless of other fields."""
        snap = base_snapshot(
            apt_available=False,
            pending_security=["libssl3"],
            pending_regular=["vim"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        assert len(result.findings) == 1
        assert result.findings[0].key == "updates.no_apt"
        assert _deduction_points(result) == 0

    def test_security_pending_only_one_finding(self):
        """Security pending with unattended configured → exactly one WARN finding."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=True,
            unattended_enabled=True,
        )
        result = check_updates(snap)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 1
        assert warns[0].key == "updates.security_pending"

    def test_unattended_severity_changes_with_security_updates(self):
        """unattended_not_configured is INFO without security pending, WARN with it."""
        snap_no_sec = base_snapshot(unattended_installed=False, unattended_enabled=False)
        result_no_sec = check_updates(snap_no_sec)
        assert _has_finding(result_no_sec, "updates.unattended_not_configured", FindingLevel.INFO)

        snap_sec = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result_sec = check_updates(snap_sec)
        assert _has_finding(result_sec, "updates.unattended_not_configured", FindingLevel.WARN)

    def test_snapshot_not_mutated(self):
        """check_updates() must not modify the snapshot passed to it."""
        snap = base_snapshot(pending_security=["libssl3"])
        original_security = list(snap.pending_security)
        check_updates(snap)
        assert snap.pending_security == original_security

    def test_none_lists_handled(self):
        """None instead of an empty list must not crash check_updates()."""
        snap = UpdatesSnapshot(
            apt_available=True,
            pending_security=None,
            pending_regular=None,
            unattended_installed=True,
            unattended_enabled=True,
        )
        result = check_updates(snap)
        assert result is not None

    def test_total_deduction_never_exceeds_three(self):
        """Maximum total deduction is -3 pts (security -2 + unattended -1)."""
        snap = base_snapshot(
            pending_security=["libssl3", "openssl", "curl", "wget"],
            pending_regular=["vim", "nano"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap)
        assert _deduction_points(result) <= 3


# ---------------------------------------------------------------------------
# Desktop profile — unattended-upgrades demoted to INFO
# ---------------------------------------------------------------------------

class TestDesktopProfile:
    def test_desktop_unattended_with_security_is_info(self):
        """Compound risk is demoted to INFO on desktop profile."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap, profile_name="desktop")
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.INFO)

    def test_desktop_unattended_with_security_no_extra_deduction(self):
        """Desktop: compound risk produces no extra deduction beyond -2 pts."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap, profile_name="desktop")
        assert _deduction_points(result) == 2

    def test_desktop_no_warn_for_unattended(self):
        """WARN must not be emitted for unattended on desktop profile."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap, profile_name="desktop")
        assert not _has_finding(
            result, "updates.unattended_not_configured", FindingLevel.WARN
        )

    def test_server_profile_still_warns(self):
        """Default server profile still produces WARN + deduction."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap, profile_name="server")
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.WARN)
        assert _deduction_points(result) == 3

    def test_desktop_up_to_date_unattended_still_info(self):
        """On desktop with no security pending, unattended not configured → INFO."""
        snap = base_snapshot(unattended_installed=False, unattended_enabled=False)
        result = check_updates(snap, profile_name="desktop")
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.INFO)
        assert _deduction_points(result) == 0

    def test_workstation_alias_behaves_like_desktop(self):
        """'workstation' alias must produce same result as 'desktop'."""
        snap = base_snapshot(
            pending_security=["libssl3"],
            unattended_installed=False,
            unattended_enabled=False,
        )
        result = check_updates(snap, profile_name="workstation")
        assert _has_finding(result, "updates.unattended_not_configured", FindingLevel.INFO)
