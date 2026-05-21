"""
Unit tests for bob.checks.secure_boot module.

All tests use SecureBootSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_secure_boot.py -v
"""

from __future__ import annotations

import pytest
from bob.checks.secure_boot import (
    SecureBootSnapshot,
    check_secure_boot,
    _STATE_ENABLED,
    _STATE_DISABLED,
    _STATE_SETUP_MODE,
    _STATE_NO_UEFI,
    _STATE_UNKNOWN,
)
from tests.helpers import _levels, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_snap(state: str = _STATE_ENABLED) -> SecureBootSnapshot:
    return SecureBootSnapshot(state=state)


def has_level(result, level: str) -> bool:
    return level in _levels(result)


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


# ---------------------------------------------------------------------------
# Secure Boot enabled
# ---------------------------------------------------------------------------

class TestEnabled:
    def test_ok_when_enabled(self):
        result = check_secure_boot(make_snap(_STATE_ENABLED), t=_t)
        assert has_level(result, "ok")

    def test_no_deduction_when_enabled(self):
        result = check_secure_boot(make_snap(_STATE_ENABLED), t=_t)
        assert total_deductions(result) == 0

    def test_key_when_enabled(self):
        result = check_secure_boot(make_snap(_STATE_ENABLED), t=_t)
        assert "secure_boot.enabled" in finding_keys(result)


# ---------------------------------------------------------------------------
# Secure Boot disabled — desktop profile
# ---------------------------------------------------------------------------

class TestDisabledDesktop:
    def test_warn_on_desktop_when_disabled(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="desktop")
        assert has_level(result, "warn")

    def test_deduction_on_desktop_when_disabled(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="desktop")
        assert total_deductions(result) == 1

    def test_key_disabled(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="desktop")
        assert "secure_boot.disabled" in finding_keys(result)

    def test_workstation_alias_warns(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="workstation")
        assert has_level(result, "warn")
        assert total_deductions(result) == 1


# ---------------------------------------------------------------------------
# Secure Boot disabled — server profile
# ---------------------------------------------------------------------------

class TestDisabledServer:
    def test_info_on_server_when_disabled(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="server")
        assert has_level(result, "info")

    def test_no_deduction_on_server_when_disabled(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="server")
        assert total_deductions(result) == 0

    def test_no_warn_on_server_when_disabled(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="server")
        assert not has_level(result, "warn")


# ---------------------------------------------------------------------------
# Setup Mode — SB enabled but no Platform Key enrolled
# ---------------------------------------------------------------------------

class TestSetupMode:
    def test_warn_when_setup_mode(self):
        result = check_secure_boot(make_snap(_STATE_SETUP_MODE), t=_t)
        assert has_level(result, "warn")

    def test_deduction_when_setup_mode(self):
        result = check_secure_boot(make_snap(_STATE_SETUP_MODE), t=_t)
        assert total_deductions(result) == 1

    def test_key_when_setup_mode(self):
        result = check_secure_boot(make_snap(_STATE_SETUP_MODE), t=_t)
        assert "secure_boot.setup_mode" in finding_keys(result)

    def test_setup_mode_warns_regardless_of_profile(self):
        """Setup Mode is actively misconfigured — warn on both server and desktop."""
        for profile in ("server", "desktop"):
            result = check_secure_boot(make_snap(_STATE_SETUP_MODE), t=_t, profile_name=profile)
            assert has_level(result, "warn"), f"expected warn for profile={profile}"
            assert total_deductions(result) == 1

    def test_setup_mode_is_not_ok(self):
        result = check_secure_boot(make_snap(_STATE_SETUP_MODE), t=_t)
        assert not has_level(result, "ok")


# ---------------------------------------------------------------------------
# No UEFI (legacy BIOS)
# ---------------------------------------------------------------------------

class TestNoUefi:
    def test_info_when_no_uefi(self):
        result = check_secure_boot(make_snap(_STATE_NO_UEFI), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_no_uefi(self):
        result = check_secure_boot(make_snap(_STATE_NO_UEFI), t=_t)
        assert total_deductions(result) == 0

    def test_key_when_no_uefi(self):
        result = check_secure_boot(make_snap(_STATE_NO_UEFI), t=_t)
        assert "secure_boot.no_uefi" in finding_keys(result)

    def test_no_uefi_same_on_desktop_and_server(self):
        """BIOS detection must not trigger a deduction regardless of profile."""
        for profile in ("server", "desktop"):
            result = check_secure_boot(make_snap(_STATE_NO_UEFI), t=_t, profile_name=profile)
            assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Unknown state
# ---------------------------------------------------------------------------

class TestUnknown:
    def test_info_when_unknown(self):
        result = check_secure_boot(make_snap(_STATE_UNKNOWN), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_unknown(self):
        result = check_secure_boot(make_snap(_STATE_UNKNOWN), t=_t)
        assert total_deductions(result) == 0

    def test_key_when_unknown(self):
        result = check_secure_boot(make_snap(_STATE_UNKNOWN), t=_t)
        assert "secure_boot.unknown" in finding_keys(result)


# ---------------------------------------------------------------------------
# Profile case-insensitivity
# ---------------------------------------------------------------------------

class TestProfileCaseInsensitive:
    def test_desktop_uppercase_warns(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="Desktop")
        assert has_level(result, "warn")

    def test_server_uppercase_no_deduction(self):
        result = check_secure_boot(make_snap(_STATE_DISABLED), t=_t, profile_name="Server")
        assert total_deductions(result) == 0


# ---------------------------------------------------------------------------
# Snapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_default_state_is_unknown(self):
        snap = SecureBootSnapshot()
        assert snap.state == _STATE_UNKNOWN

