"""
Unit tests for bob.checks.password_policy module.

All tests use PasswordPolicySnapshot instances built directly — no filesystem
reads. The check logic is exercised in isolation.

Run with: python -m pytest tests/test_password_policy.py -v
"""

import pytest
from bob.checks.password_policy import (
    PasswordPolicySnapshot,
    check_password_policy,
    _MAX_DAYS_THRESHOLD,
    _MIN_LEN_THRESHOLD,
    _DEDUCTION_NO_QUALITY_MODULE,
    _DEDUCTION_WEAK_MINLEN,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _t(key, **kwargs):
    """Minimal translation: return key + space-joined kwarg values."""
    if kwargs:
        return key + " " + " ".join(str(v) for v in kwargs.values())
    return key


def make_snap(**kwargs) -> PasswordPolicySnapshot:
    defaults = dict(
        login_defs_readable=True,
        pass_max_days=90,
        pass_min_days=1,
        pam_quality_module="pam_pwquality",
        pam_minlen=None,
    )
    defaults.update(kwargs)
    return PasswordPolicySnapshot(**defaults)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def finding_keys(result):
    return [f.key for f in result.findings]


def deduction_keys(result):
    return [d.key for d in result.deductions]


# ---------------------------------------------------------------------------
# Snapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_login_defs_readable_default_false(self):
        s = PasswordPolicySnapshot()
        assert not s.login_defs_readable

    def test_pass_max_days_default_none(self):
        s = PasswordPolicySnapshot()
        assert s.pass_max_days is None

    def test_pass_min_days_default_none(self):
        s = PasswordPolicySnapshot()
        assert s.pass_min_days is None

    def test_pam_quality_module_default_none(self):
        s = PasswordPolicySnapshot()
        assert s.pam_quality_module is None

    def test_pam_minlen_default_none(self):
        s = PasswordPolicySnapshot()
        assert s.pam_minlen is None


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_ok_when_fully_configured(self):
        result = check_password_policy(make_snap(), t=_t)
        assert has_level(result, "ok")

    def test_no_deduction_when_ok(self):
        result = check_password_policy(make_snap(), t=_t)
        assert total_deductions(result) == 0

    def test_ok_key(self):
        result = check_password_policy(make_snap(), t=_t)
        assert "password_policy.ok" in finding_keys(result)

    def test_no_ok_when_finding(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        assert "password_policy.ok" not in finding_keys(result)

    def test_ok_with_pam_cracklib(self):
        result = check_password_policy(make_snap(pam_quality_module="pam_cracklib"), t=_t)
        assert has_level(result, "ok")

    def test_ok_with_minlen_at_threshold(self):
        result = check_password_policy(
            make_snap(pam_minlen=_MIN_LEN_THRESHOLD), t=_t
        )
        assert has_level(result, "ok")

    def test_ok_with_minlen_above_threshold(self):
        result = check_password_policy(make_snap(pam_minlen=12), t=_t)
        assert has_level(result, "ok")


# ---------------------------------------------------------------------------
# No PAM quality module
# ---------------------------------------------------------------------------

class TestNoQualityModule:
    def test_warn_when_no_module(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        assert has_level(result, "warn")

    def test_deduction_points(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        assert total_deductions(result) == _DEDUCTION_NO_QUALITY_MODULE

    def test_finding_key(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        assert "password_policy.no_quality_module" in finding_keys(result)

    def test_deduction_key(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        assert "password_policy.no_quality_module" in deduction_keys(result)

    def test_nature_is_action(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        warn = next(f for f in result.findings if f.key == "password_policy.no_quality_module")
        assert warn.nature == "action"

    def test_cmd_present(self):
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        warn = next(f for f in result.findings if f.key == "password_policy.no_quality_module")
        assert warn.cmd


# ---------------------------------------------------------------------------
# Weak minlen
# ---------------------------------------------------------------------------

class TestWeakMinlen:
    def test_minlen_7_flagged(self):
        """minlen=7 is exactly one below threshold — must be flagged."""
        result = check_password_policy(make_snap(pam_minlen=7), t=_t)
        assert "password_policy.weak_minlen" in finding_keys(result)

    def test_warn_when_minlen_below_threshold(self):
        result = check_password_policy(make_snap(pam_minlen=6), t=_t)
        assert has_level(result, "warn")

    def test_deduction_points(self):
        result = check_password_policy(make_snap(pam_minlen=6), t=_t)
        assert total_deductions(result) == _DEDUCTION_WEAK_MINLEN

    def test_finding_key(self):
        result = check_password_policy(make_snap(pam_minlen=6), t=_t)
        assert "password_policy.weak_minlen" in finding_keys(result)

    def test_deduction_key(self):
        result = check_password_policy(make_snap(pam_minlen=6), t=_t)
        assert "password_policy.weak_minlen" in deduction_keys(result)

    def test_minlen_in_message(self):
        result = check_password_policy(make_snap(pam_minlen=6), t=_t)
        warn = next(f for f in result.findings if f.key == "password_policy.weak_minlen")
        assert "6" in warn.message

    def test_minlen_1_flagged(self):
        result = check_password_policy(make_snap(pam_minlen=1), t=_t)
        assert "password_policy.weak_minlen" in finding_keys(result)

    def test_no_warn_when_minlen_none(self):
        """None = using module default (8) — not a finding."""
        result = check_password_policy(make_snap(pam_quality_module="pam_pwquality", pam_minlen=None), t=_t)
        assert "password_policy.weak_minlen" not in finding_keys(result)

    def test_no_weak_minlen_when_no_module(self):
        """When no module, report no_quality_module — not both."""
        result = check_password_policy(make_snap(pam_quality_module=None, pam_minlen=4), t=_t)
        assert "password_policy.weak_minlen" not in finding_keys(result)
        assert "password_policy.no_quality_module" in finding_keys(result)

    def test_nature_is_action(self):
        result = check_password_policy(make_snap(pam_minlen=6), t=_t)
        warn = next(f for f in result.findings if f.key == "password_policy.weak_minlen")
        assert warn.nature == "action"


# ---------------------------------------------------------------------------
# Password expiry (PASS_MAX_DAYS)
# ---------------------------------------------------------------------------

class TestPassMaxDays:
    def test_info_when_never_expires(self):
        result = check_password_policy(make_snap(pass_max_days=_MAX_DAYS_THRESHOLD + 1), t=_t)
        assert has_level(result, "info")

    def test_info_key(self):
        result = check_password_policy(make_snap(pass_max_days=_MAX_DAYS_THRESHOLD + 1), t=_t)
        assert "password_policy.no_expiry" in finding_keys(result)

    def test_no_deduction_for_max_days(self):
        result = check_password_policy(make_snap(pass_max_days=_MAX_DAYS_THRESHOLD + 1), t=_t)
        assert total_deductions(result) == 0

    def test_days_in_message(self):
        result = check_password_policy(make_snap(pass_max_days=_MAX_DAYS_THRESHOLD + 1), t=_t)
        info = next(f for f in result.findings if f.key == "password_policy.no_expiry")
        assert str(_MAX_DAYS_THRESHOLD + 1) in info.message

    def test_no_info_when_max_days_low(self):
        result = check_password_policy(make_snap(pass_max_days=90), t=_t)
        assert "password_policy.no_expiry" not in finding_keys(result)

    def test_threshold_boundary_flagged(self):
        result = check_password_policy(make_snap(pass_max_days=_MAX_DAYS_THRESHOLD), t=_t)
        assert "password_policy.no_expiry" in finding_keys(result)

    def test_below_threshold_not_flagged(self):
        result = check_password_policy(make_snap(pass_max_days=_MAX_DAYS_THRESHOLD - 1), t=_t)
        assert "password_policy.no_expiry" not in finding_keys(result)

    def test_none_max_days_no_crash(self):
        result = check_password_policy(make_snap(pass_max_days=None), t=_t)
        assert result is not None
        assert "password_policy.no_expiry" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_no_module_and_no_expiry(self):
        result = check_password_policy(
            make_snap(pam_quality_module=None, pass_max_days=_MAX_DAYS_THRESHOLD + 1), t=_t
        )
        keys = finding_keys(result)
        assert "password_policy.no_quality_module" in keys
        assert "password_policy.no_expiry" in keys
        assert total_deductions(result) == _DEDUCTION_NO_QUALITY_MODULE

    def test_weak_minlen_and_no_expiry(self):
        result = check_password_policy(
            make_snap(pam_minlen=4, pass_max_days=_MAX_DAYS_THRESHOLD + 1), t=_t
        )
        keys = finding_keys(result)
        assert "password_policy.weak_minlen" in keys
        assert "password_policy.no_expiry" in keys
        assert total_deductions(result) == _DEDUCTION_WEAK_MINLEN

    def test_max_combined_deduction(self):
        """no_module alone gives max deduction; weak_minlen is mutually exclusive."""
        result = check_password_policy(make_snap(pam_quality_module=None), t=_t)
        assert total_deductions(result) == _DEDUCTION_NO_QUALITY_MODULE


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_login_defs_unreadable_no_crash(self):
        """login_defs_readable=False — no crash, no expiry finding."""
        result = check_password_policy(
            make_snap(login_defs_readable=False, pass_max_days=None), t=_t
        )
        assert result is not None
        assert "password_policy.no_expiry" not in finding_keys(result)

    def test_pass_min_days_does_not_affect_findings(self):
        """pass_min_days is collected but not scored."""
        result = check_password_policy(make_snap(pass_min_days=0), t=_t)
        keys = finding_keys(result)
        assert "password_policy.ok" in keys

    def test_no_t_does_not_crash(self):
        """check_password_policy without t= uses identity fallback."""
        result = check_password_policy(make_snap())
        assert result is not None

    def test_pam_cracklib_ok_finding(self):
        """pam_cracklib is an accepted quality module — result is ok."""
        result = check_password_policy(
            make_snap(pam_quality_module="pam_cracklib"), t=_t
        )
        assert "password_policy.ok" in finding_keys(result)

    def test_unknown_module_treated_as_configured(self):
        """Any non-None module value means a module is configured — no warning."""
        result = check_password_policy(
            make_snap(pam_quality_module="pam_something_custom"), t=_t
        )
        assert "password_policy.no_quality_module" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_max_days_threshold(self):
        assert _MAX_DAYS_THRESHOLD == 365

    def test_min_len_threshold(self):
        assert _MIN_LEN_THRESHOLD == 8

    def test_deduction_no_module(self):
        assert _DEDUCTION_NO_QUALITY_MODULE == 1

    def test_deduction_weak_minlen(self):
        assert _DEDUCTION_WEAK_MINLEN == 1
