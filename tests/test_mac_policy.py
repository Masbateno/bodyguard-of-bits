"""
Unit tests for bob.checks.mac_policy (CHECK 34).

Covers:
  - AppArmor enforcing → OK
  - AppArmor active, no enforce profiles → WARN (server) / INFO (desktop)
  - AppArmor installed but inactive → WARN −1
  - SELinux enforcing → OK (short-circuit)
  - SELinux permissive without AppArmor → WARN −1
  - No MAC found → WARN −1
  - Profile-aware behaviour (server vs desktop)
  - _parse_aa_count helper
  - Deduction invariants

All tests use MacPolicySnapshot instances built directly — no subprocess calls.

Run with: python3 -m pytest tests/test_mac_policy.py -v
"""

from __future__ import annotations

import pytest

from bob.checks.mac_policy import (
    MacPolicySnapshot,
    _parse_aa_count,
    check_mac_policy,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _finding_level, _keys, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snap(
    *,
    aa_installed: bool = False,
    aa_active: bool = False,
    aa_enforcing: int = 0,
    aa_complain: int = 0,
    se_installed: bool = False,
    se_mode: str = "",
) -> MacPolicySnapshot:
    return MacPolicySnapshot(
        apparmor_installed=aa_installed,
        apparmor_active=aa_active,
        apparmor_enforcing=aa_enforcing,
        apparmor_complain=aa_complain,
        selinux_installed=se_installed,
        selinux_mode=se_mode,
    )



# ---------------------------------------------------------------------------
# _parse_aa_count
# ---------------------------------------------------------------------------

class TestParseAaCount:
    _AA_OUTPUT = (
        "apparmor module is loaded.\n"
        "105 profiles are loaded.\n"
        "104 profiles are in enforce mode.\n"
        "   /usr/sbin/sshd\n"
        "1 profiles are in complain mode.\n"
        "   /usr/bin/man\n"
    )

    def test_parses_enforce_count(self):
        assert _parse_aa_count(self._AA_OUTPUT, "enforce") == 104

    def test_parses_complain_count(self):
        assert _parse_aa_count(self._AA_OUTPUT, "complain") == 1

    def test_returns_zero_for_missing_mode(self):
        assert _parse_aa_count(self._AA_OUTPUT, "audit") == 0

    def test_empty_output_returns_zero(self):
        assert _parse_aa_count("", "enforce") == 0

    def test_singular_count_with_plural_form(self):
        """aa-status always uses 'profiles are' even for count=1."""
        output = "1 profiles are in enforce mode.\n"
        assert _parse_aa_count(output, "enforce") == 1

    def test_parse_with_leading_trailing_spaces(self):
        output = "  12 profiles are in enforce mode.  \n"
        assert _parse_aa_count(output, "enforce") == 12

    def test_parse_non_numeric_fails_gracefully(self):
        output = "many profiles are in enforce mode.\n"
        assert _parse_aa_count(output, "enforce") == 0


# ---------------------------------------------------------------------------
# No MAC framework
# ---------------------------------------------------------------------------

class TestNoMac:
    def test_no_mac_returns_warn(self):
        snap = _snap()
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.no_mac" in _keys(result)
        assert _finding_level(result, "mac_policy.no_mac") == FindingLevel.WARN

    def test_no_mac_deduction_1pt(self):
        snap = _snap()
        result = check_mac_policy(snap, t=_t)
        assert _deduction_points(result) == 1

    def test_no_mac_deduction_key(self):
        snap = _snap()
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.no_mac" in _deduction_keys(result)

    def test_no_mac_has_install_cmd(self):
        snap = _snap()
        result = check_mac_policy(snap, t=_t)
        finding = next(f for f in result.findings if f.key == "mac_policy.no_mac")
        assert "apparmor" in finding.cmd

    def test_no_mac_same_on_desktop(self):
        snap = _snap()
        result = check_mac_policy(snap, t=_t, profile_name="desktop")
        assert "mac_policy.no_mac" in _keys(result)
        assert _deduction_points(result) == 1


# ---------------------------------------------------------------------------
# AppArmor installed but inactive
# ---------------------------------------------------------------------------

class TestAppArmorInactive:
    def test_inactive_returns_warn(self):
        snap = _snap(aa_installed=True, aa_active=False)
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.apparmor_inactive" in _keys(result)
        assert _finding_level(result, "mac_policy.apparmor_inactive") == FindingLevel.WARN

    def test_inactive_deduction_1pt(self):
        snap = _snap(aa_installed=True, aa_active=False)
        result = check_mac_policy(snap, t=_t)
        assert _deduction_points(result) == 1

    def test_inactive_has_enable_cmd(self):
        snap = _snap(aa_installed=True, aa_active=False)
        result = check_mac_policy(snap, t=_t)
        finding = next(f for f in result.findings if f.key == "mac_policy.apparmor_inactive")
        assert "systemctl" in finding.cmd
        assert "apparmor" in finding.cmd

    def test_inactive_same_on_desktop(self):
        snap = _snap(aa_installed=True, aa_active=False)
        result = check_mac_policy(snap, t=_t, profile_name="desktop")
        assert _deduction_points(result) == 1


# ---------------------------------------------------------------------------
# AppArmor active, no enforce profiles
# ---------------------------------------------------------------------------

class TestAppArmorNoEnforce:
    def test_server_no_enforce_returns_warn(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=5)
        result = check_mac_policy(snap, t=_t, profile_name="server")
        assert "mac_policy.apparmor_no_enforce" in _keys(result)
        assert _finding_level(result, "mac_policy.apparmor_no_enforce") == FindingLevel.WARN

    def test_server_no_enforce_deduction_1pt(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=5)
        result = check_mac_policy(snap, t=_t, profile_name="server")
        assert _deduction_points(result) == 1

    def test_desktop_no_enforce_returns_info(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=5)
        result = check_mac_policy(snap, t=_t, profile_name="desktop")
        assert "mac_policy.apparmor_no_enforce" in _keys(result)
        assert _finding_level(result, "mac_policy.apparmor_no_enforce") == FindingLevel.INFO

    def test_desktop_no_enforce_no_deduction(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=5)
        result = check_mac_policy(snap, t=_t, profile_name="desktop")
        assert _deduction_points(result) == 0

    def test_no_enforce_has_aa_enforce_cmd(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=3)
        result = check_mac_policy(snap, t=_t, profile_name="server")
        finding = next(f for f in result.findings if f.key == "mac_policy.apparmor_no_enforce")
        assert "aa-enforce" in finding.cmd

    def test_active_with_zero_profiles_at_all(self):
        """Active AppArmor with 0 enforce and 0 complain → still no_enforce."""
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=0)
        result = check_mac_policy(snap, t=_t, profile_name="server")
        assert "mac_policy.apparmor_no_enforce" in _keys(result)


# ---------------------------------------------------------------------------
# AppArmor enforcing
# ---------------------------------------------------------------------------

class TestAppArmorEnforcing:
    def test_enforcing_returns_ok(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=104, aa_complain=1)
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.apparmor_ok" in _keys(result)
        assert _finding_level(result, "mac_policy.apparmor_ok") == FindingLevel.OK

    def test_enforcing_no_deduction(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=104, aa_complain=1)
        result = check_mac_policy(snap, t=_t)
        assert _deduction_points(result) == 0

    def test_enforcing_same_on_desktop(self):
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=80, aa_complain=0)
        result = check_mac_policy(snap, t=_t, profile_name="desktop")
        assert "mac_policy.apparmor_ok" in _keys(result)
        assert _deduction_points(result) == 0

    def test_enforcing_with_selinux_permissive_adds_info(self):
        """AppArmor OK + SELinux permissive → OK + INFO note about SELinux."""
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=50,
                     se_installed=True, se_mode="Permissive")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.apparmor_ok" in _keys(result)
        assert "mac_policy.selinux_permissive" in _keys(result)

    def test_apparmor_active_without_installed_flag_still_reports_ok(self):
        """Active + enforcing with installed=False: active state wins, OK returned."""
        snap = _snap(aa_installed=False, aa_active=True, aa_enforcing=5)
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.apparmor_ok" in _keys(result)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# SELinux
# ---------------------------------------------------------------------------

class TestSELinux:
    def test_selinux_enforcing_returns_ok(self):
        snap = _snap(se_installed=True, se_mode="Enforcing")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.selinux_enforcing" in _keys(result)
        assert _finding_level(result, "mac_policy.selinux_enforcing") == FindingLevel.OK

    def test_selinux_enforcing_no_deduction(self):
        snap = _snap(se_installed=True, se_mode="Enforcing")
        result = check_mac_policy(snap, t=_t)
        assert _deduction_points(result) == 0

    def test_selinux_enforcing_short_circuits(self):
        """SELinux enforcing is OK even if AppArmor is inactive."""
        snap = _snap(aa_installed=True, aa_active=False,
                     se_installed=True, se_mode="Enforcing")
        result = check_mac_policy(snap, t=_t)
        assert _keys(result) == ["mac_policy.selinux_enforcing"]

    def test_selinux_permissive_no_apparmor_warns(self):
        snap = _snap(se_installed=True, se_mode="Permissive")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.no_enforce" in _keys(result)
        assert _finding_level(result, "mac_policy.no_enforce") == FindingLevel.WARN
        assert _deduction_points(result) == 1

    def test_selinux_permissive_also_shows_info(self):
        snap = _snap(se_installed=True, se_mode="Permissive")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.selinux_permissive" in _keys(result)

    def test_selinux_disabled_gets_dedicated_finding(self):
        """SELinux installed but disabled → selinux_disabled, NOT no_mac."""
        snap = _snap(se_installed=True, se_mode="Disabled")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.selinux_disabled" in _keys(result)
        assert "mac_policy.no_mac" not in _keys(result)

    def test_selinux_disabled_deduction_1pt(self):
        snap = _snap(se_installed=True, se_mode="Disabled")
        result = check_mac_policy(snap, t=_t)
        assert _deduction_points(result) == 1

    def test_selinux_disabled_has_setenforce_cmd(self):
        snap = _snap(se_installed=True, se_mode="Disabled")
        result = check_mac_policy(snap, t=_t)
        finding = next(f for f in result.findings if f.key == "mac_policy.selinux_disabled")
        assert "setenforce" in finding.cmd

    def test_selinux_mode_disabled_case_insensitive(self):
        """'disabled' (lower-case) should also hit the selinux_disabled branch."""
        snap = _snap(se_installed=True, se_mode="disabled")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.selinux_disabled" in _keys(result)

    def test_selinux_not_installed_disabled_mode_falls_to_no_mac(self):
        """se_installed=False with mode='Disabled' (inconsistent) → no_mac."""
        snap = _snap(se_installed=False, se_mode="Disabled")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.no_mac" in _keys(result)

    def test_selinux_mode_case_insensitive(self):
        snap = _snap(se_installed=True, se_mode="enforcing")
        result = check_mac_policy(snap, t=_t)
        assert "mac_policy.selinux_enforcing" in _keys(result)

    def test_selinux_and_apparmor_both_enforcing_prefers_selinux(self):
        """SELinux enforcing short-circuits even when AppArmor is also enforcing."""
        snap = _snap(aa_installed=True, aa_active=True, aa_enforcing=10,
                     se_installed=True, se_mode="Enforcing")
        result = check_mac_policy(snap, t=_t)
        assert _keys(result) == ["mac_policy.selinux_enforcing"]


# ---------------------------------------------------------------------------
# MacPolicySnapshot dataclass
# ---------------------------------------------------------------------------

class TestMacPolicySnapshot:
    def test_defaults(self):
        snap = MacPolicySnapshot()
        assert not snap.apparmor_installed
        assert not snap.apparmor_active
        assert snap.apparmor_enforcing == 0
        assert snap.apparmor_complain == 0
        assert not snap.selinux_installed
        assert snap.selinux_mode == ""

    def test_custom_values(self):
        snap = MacPolicySnapshot(
            apparmor_installed=True,
            apparmor_active=True,
            apparmor_enforcing=10,
        )
        assert snap.apparmor_enforcing == 10


# ---------------------------------------------------------------------------
# Deduction invariants
# ---------------------------------------------------------------------------

class TestDeductionInvariants:
    @pytest.mark.parametrize("snap,profile", [
        (_snap(), "server"),
        (_snap(aa_installed=True, aa_active=False), "server"),
        (_snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=3), "server"),
        (_snap(se_installed=True, se_mode="Permissive"), "server"),
    ])
    def test_max_deduction_is_1(self, snap, profile):
        result = check_mac_policy(snap, t=_t, profile_name=profile)
        assert _deduction_points(result) <= 1

    @pytest.mark.parametrize("snap,profile", [
        (_snap(aa_installed=True, aa_active=True, aa_enforcing=5), "server"),
        (_snap(se_installed=True, se_mode="Enforcing"), "server"),
        (_snap(aa_installed=True, aa_active=True, aa_enforcing=0, aa_complain=3), "desktop"),
    ])
    def test_ok_cases_have_no_deduction(self, snap, profile):
        result = check_mac_policy(snap, t=_t, profile_name=profile)
        assert _deduction_points(result) == 0
