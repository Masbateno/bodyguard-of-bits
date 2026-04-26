"""
Unit tests for bob.checks.user_accounts module.

All tests use UserAccountsSnapshot instances built directly — no filesystem
reads. The check logic is exercised in isolation.

Run with: python -m pytest tests/test_user_accounts.py -v
"""

import pytest
from bob.checks.user_accounts import (
    UserAccountsSnapshot,
    check_user_accounts,
    _is_no_login_shell,
    _MAX_DEDUCTION_UID_ZERO,
    _MAX_DEDUCTION_EMPTY_PASSWORD,
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


def make_snap(**kwargs) -> UserAccountsSnapshot:
    defaults = dict(
        shadow_readable=True,
        uid_zero_accounts=[],
        empty_password_accounts=[],
        expired_accounts={},
    )
    defaults.update(kwargs)
    return UserAccountsSnapshot(**defaults)


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
    def test_shadow_readable_default_false(self):
        s = UserAccountsSnapshot()
        assert not s.shadow_readable

    def test_uid_zero_default_empty(self):
        s = UserAccountsSnapshot()
        assert s.uid_zero_accounts == []

    def test_empty_password_default_empty(self):
        s = UserAccountsSnapshot()
        assert s.empty_password_accounts == []

    def test_expired_default_empty(self):
        s = UserAccountsSnapshot()
        assert s.expired_accounts == {}


# ---------------------------------------------------------------------------
# Shadow not readable
# ---------------------------------------------------------------------------

class TestShadowNotReadable:
    def test_info_when_shadow_not_readable(self):
        result = check_user_accounts(make_snap(shadow_readable=False), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_when_shadow_not_readable(self):
        result = check_user_accounts(make_snap(shadow_readable=False), t=_t)
        assert total_deductions(result) == 0

    def test_info_key(self):
        result = check_user_accounts(make_snap(shadow_readable=False), t=_t)
        assert "user_accounts.no_shadow" in finding_keys(result)

    def test_uid_zero_still_reported_without_shadow(self):
        """UID 0 detection is independent of shadow readability."""
        result = check_user_accounts(
            make_snap(shadow_readable=False, uid_zero_accounts=["backdoor"]),
            t=_t,
        )
        assert has_level(result, "alert")


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_ok_finding_when_clean(self):
        result = check_user_accounts(make_snap(), t=_t)
        assert has_level(result, "ok")

    def test_no_deduction_when_clean(self):
        result = check_user_accounts(make_snap(), t=_t)
        assert total_deductions(result) == 0

    def test_ok_key(self):
        result = check_user_accounts(make_snap(), t=_t)
        assert "user_accounts.ok" in finding_keys(result)

    def test_no_ok_when_finding(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["bad"]), t=_t)
        assert "user_accounts.ok" not in finding_keys(result)


# ---------------------------------------------------------------------------
# UID 0 accounts
# ---------------------------------------------------------------------------

class TestUidZero:
    def test_alert_when_uid_zero(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        assert has_level(result, "alert")

    def test_deduction_points(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        assert total_deductions(result) == _MAX_DEDUCTION_UID_ZERO

    def test_deduction_key(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        assert "user_accounts.uid_zero" in deduction_keys(result)

    def test_finding_key(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        assert "user_accounts.uid_zero" in finding_keys(result)

    def test_username_in_message(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "ghost" in alert.message

    def test_multiple_uid_zero_single_deduction(self):
        """Flat deduction regardless of how many UID 0 accounts exist."""
        result = check_user_accounts(
            make_snap(uid_zero_accounts=["a", "b", "c"]), t=_t
        )
        assert total_deductions(result) == _MAX_DEDUCTION_UID_ZERO

    def test_cmd_contains_username(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        alert = next(f for f in result.findings if f.key == "user_accounts.uid_zero")
        assert "ghost" in (alert.cmd or "")

    def test_nature_is_action(self):
        result = check_user_accounts(make_snap(uid_zero_accounts=["ghost"]), t=_t)
        alert = next(f for f in result.findings if f.key == "user_accounts.uid_zero")
        assert alert.nature == "action"

    def test_duplicates_deduplicated(self):
        result = check_user_accounts(
            make_snap(uid_zero_accounts=["ghost", "ghost"]), t=_t
        )
        alerts = [f for f in result.findings if f.key == "user_accounts.uid_zero"]
        assert len(alerts) == 1

    def test_snapshot_not_mutated(self):
        snap = make_snap(uid_zero_accounts=["ghost"])
        original = list(snap.uid_zero_accounts)
        check_user_accounts(snap, t=_t)
        assert snap.uid_zero_accounts == original


# ---------------------------------------------------------------------------
# Empty passwords
# ---------------------------------------------------------------------------

class TestEmptyPassword:
    def test_alert_when_empty_password(self):
        result = check_user_accounts(make_snap(empty_password_accounts=["user1"]), t=_t)
        assert has_level(result, "alert")

    def test_deduction_points(self):
        result = check_user_accounts(make_snap(empty_password_accounts=["user1"]), t=_t)
        assert total_deductions(result) == _MAX_DEDUCTION_EMPTY_PASSWORD

    def test_deduction_key(self):
        result = check_user_accounts(make_snap(empty_password_accounts=["user1"]), t=_t)
        assert "user_accounts.empty_password" in deduction_keys(result)

    def test_finding_key(self):
        result = check_user_accounts(make_snap(empty_password_accounts=["user1"]), t=_t)
        assert "user_accounts.empty_password" in finding_keys(result)

    def test_username_in_message(self):
        result = check_user_accounts(make_snap(empty_password_accounts=["user1"]), t=_t)
        alert = next(f for f in result.findings if f.key == "user_accounts.empty_password")
        assert "user1" in alert.message

    def test_multiple_empty_passwords_single_deduction(self):
        """Flat deduction regardless of how many accounts have empty passwords."""
        result = check_user_accounts(
            make_snap(empty_password_accounts=["a", "b"]), t=_t
        )
        assert total_deductions(result) == _MAX_DEDUCTION_EMPTY_PASSWORD

    def test_nature_is_action(self):
        result = check_user_accounts(make_snap(empty_password_accounts=["user1"]), t=_t)
        alert = next(f for f in result.findings if f.key == "user_accounts.empty_password")
        assert alert.nature == "action"


# ---------------------------------------------------------------------------
# Expired accounts
# ---------------------------------------------------------------------------

class TestExpiredAccounts:
    def test_info_when_expired(self):
        result = check_user_accounts(make_snap(expired_accounts={"olduser": "2023-01-01"}), t=_t)
        assert has_level(result, "info")

    def test_no_deduction_for_expired(self):
        result = check_user_accounts(make_snap(expired_accounts={"olduser": "2023-01-01"}), t=_t)
        assert total_deductions(result) == 0

    def test_finding_key(self):
        result = check_user_accounts(make_snap(expired_accounts={"olduser": "2023-01-01"}), t=_t)
        assert "user_accounts.expired_account" in finding_keys(result)

    def test_username_in_message(self):
        result = check_user_accounts(make_snap(expired_accounts={"olduser": "2023-01-01"}), t=_t)
        info = next(f for f in result.findings if f.key == "user_accounts.expired_account")
        assert "olduser" in info.message

    def test_date_in_message(self):
        result = check_user_accounts(make_snap(expired_accounts={"olduser": "2023-06-15"}), t=_t)
        info = next(f for f in result.findings if f.key == "user_accounts.expired_account")
        assert "2023-06-15" in info.message

    def test_multiple_expired_all_in_message(self):
        result = check_user_accounts(
            make_snap(expired_accounts={"alice": "2022-01-01", "bob": "2023-03-15"}), t=_t
        )
        info = next(f for f in result.findings if f.key == "user_accounts.expired_account")
        assert "alice" in info.message
        assert "bob" in info.message

    def test_no_ok_when_expired(self):
        result = check_user_accounts(make_snap(expired_accounts={"olduser": "2023-01-01"}), t=_t)
        assert "user_accounts.ok" not in finding_keys(result)


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_uid_zero_and_empty_password_combined(self):
        result = check_user_accounts(
            make_snap(uid_zero_accounts=["ghost"], empty_password_accounts=["user1"]),
            t=_t,
        )
        assert total_deductions(result) == _MAX_DEDUCTION_UID_ZERO + _MAX_DEDUCTION_EMPTY_PASSWORD
        assert "user_accounts.uid_zero" in finding_keys(result)
        assert "user_accounts.empty_password" in finding_keys(result)

    def test_all_three_issues(self):
        result = check_user_accounts(
            make_snap(
                uid_zero_accounts=["ghost"],
                empty_password_accounts=["user1"],
                expired_accounts={"olduser": "2023-01-01"},
            ),
            t=_t,
        )
        keys = finding_keys(result)
        assert "user_accounts.uid_zero" in keys
        assert "user_accounts.empty_password" in keys
        assert "user_accounts.expired_account" in keys

    def test_expired_does_not_add_to_deduction(self):
        result = check_user_accounts(
            make_snap(uid_zero_accounts=["ghost"], expired_accounts={"old": "2022-12-31"}),
            t=_t,
        )
        assert total_deductions(result) == _MAX_DEDUCTION_UID_ZERO

    def test_no_shadow_plus_uid_zero(self):
        result = check_user_accounts(
            make_snap(shadow_readable=False, uid_zero_accounts=["ghost"]),
            t=_t,
        )
        keys = finding_keys(result)
        assert "user_accounts.no_shadow" in keys
        assert "user_accounts.uid_zero" in keys
        assert total_deductions(result) == _MAX_DEDUCTION_UID_ZERO


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_none_uid_zero_produces_ok(self):
        snap = make_snap()
        snap.uid_zero_accounts = None  # type: ignore[assignment]
        result = check_user_accounts(snap, t=_t)
        assert has_level(result, "ok")

    def test_none_empty_password_produces_ok(self):
        snap = make_snap()
        snap.empty_password_accounts = None  # type: ignore[assignment]
        result = check_user_accounts(snap, t=_t)
        assert has_level(result, "ok")

    def test_none_expired_produces_ok(self):
        snap = make_snap()
        snap.expired_accounts = None  # type: ignore[assignment]
        result = check_user_accounts(snap, t=_t)
        assert has_level(result, "ok")

    def test_empty_dict_expired_produces_ok(self):
        result = check_user_accounts(make_snap(expired_accounts={}), t=_t)
        assert has_level(result, "ok")

    def test_empty_username_in_list_does_not_crash(self):
        result = check_user_accounts(
            make_snap(uid_zero_accounts=[""]), t=_t
        )
        # Empty string deduplicated — still produces a finding with empty name
        assert result is not None

    def test_ok_present_when_only_shadow_not_readable(self):
        """shadow unreadable + no other issues → ok AND no_shadow both present."""
        result = check_user_accounts(make_snap(shadow_readable=False), t=_t)
        keys = finding_keys(result)
        assert "user_accounts.ok" in keys
        assert "user_accounts.no_shadow" in keys

    def test_no_shadow_and_expired_both_reported(self):
        """no_shadow info + expired info — independent, both shown."""
        result = check_user_accounts(
            make_snap(shadow_readable=False, expired_accounts={"olduser": "2023-01-01"}), t=_t
        )
        keys = finding_keys(result)
        assert "user_accounts.no_shadow" in keys
        assert "user_accounts.expired_account" in keys
        assert total_deductions(result) == 0

    def test_no_shadow_info_absent_when_readable(self):
        """shadow_readable=True (default) — no no_shadow info finding."""
        result = check_user_accounts(make_snap(shadow_readable=True), t=_t)
        assert "user_accounts.no_shadow" not in finding_keys(result)

    def test_snapshot_not_mutated_empty_password(self):
        snap = make_snap(empty_password_accounts=["user1"])
        original = list(snap.empty_password_accounts)
        check_user_accounts(snap, t=_t)
        assert snap.empty_password_accounts == original

    def test_snapshot_not_mutated_expired(self):
        snap = make_snap(expired_accounts={"olduser": "2023-01-01"})
        original = dict(snap.expired_accounts)
        check_user_accounts(snap, t=_t)
        assert snap.expired_accounts == original

    def test_no_t_does_not_crash(self):
        """check_user_accounts without t= uses identity fallback."""
        result = check_user_accounts(make_snap())
        assert result is not None

    def test_max_uid_zero_deduction_constant(self):
        assert _MAX_DEDUCTION_UID_ZERO == 3

    def test_max_empty_password_deduction_constant(self):
        assert _MAX_DEDUCTION_EMPTY_PASSWORD == 2


# ---------------------------------------------------------------------------
# _is_no_login_shell helper
# ---------------------------------------------------------------------------

class TestIsNoLoginShell:
    def test_standard_nologin(self):
        assert _is_no_login_shell("/usr/sbin/nologin")

    def test_sbin_nologin(self):
        assert _is_no_login_shell("/sbin/nologin")

    def test_custom_path_nologin(self):
        """Custom install paths like /usr/local/sbin/nologin must be caught."""
        assert _is_no_login_shell("/usr/local/sbin/nologin")

    def test_bin_false(self):
        assert _is_no_login_shell("/bin/false")

    def test_usr_bin_false(self):
        assert _is_no_login_shell("/usr/bin/false")

    def test_bash_is_login_shell(self):
        assert not _is_no_login_shell("/bin/bash")

    def test_sh_is_login_shell(self):
        assert not _is_no_login_shell("/bin/sh")

    def test_none_is_login_shell(self):
        assert not _is_no_login_shell(None)

    def test_empty_string_is_login_shell(self):
        assert not _is_no_login_shell("")
