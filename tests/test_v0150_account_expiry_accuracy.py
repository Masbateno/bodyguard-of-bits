"""
v0.15.0 — an account locked out today was reported as fine, and an ambiguous
expiry was resolved silently.

Both expectations come from shadow's own tooling, run against a synthetic
/etc/shadow under a user namespace:

    field 8 = 0      chage: "Account expires: Jan 01, 1970"
    field 8 = 20000  chage: "Account expires: Oct 04, 2024"
    field 8 = today  chage: "Account expires: <today>"
    field 8 = ""     chage: "Account expires: never"

**The off-by-one.** BOB tested `0 < expire_days < today_days`. chage(1) defines
the field as "the date ... **on which** the user's account will no longer be
accessible", so an account expiring today is already locked out. The strict `<`
reported it as fine on the one day the operator most needs to hear about it.

**The zero.** BOB skipped `expire_raw == "0"` outright. shadow(5) says the value
"should not be used as it is interpreted as either an account with no
expiration, or as an expiration on Jan 1, 1970" — and chage on this system reads
it the second way. A configuration whose effect depends on the implementation is
a finding in itself, not something to resolve silently in either direction, so
it is now reported as ambiguous with both readings named.
"""

from __future__ import annotations

import datetime

import pytest

import bob.checks.user_accounts as ua
from bob.checks.user_accounts import UserAccountsSnapshot, check_user_accounts

_EPOCH = datetime.date(1970, 1, 1)
_TODAY = (datetime.date.today() - _EPOCH).days


@pytest.fixture
def shadow(tmp_path, monkeypatch):
    """Build /etc/passwd + /etc/shadow with one user at a given expiry field."""
    def _build(expire_field: str, uid: int = 1001, shell: str = "/bin/bash"):
        passwd = tmp_path / "passwd"
        shadowf = tmp_path / "shadow"
        passwd.write_text(
            "root:x:0:0:root:/root:/bin/sh\n"
            f"u1:x:{uid}:{uid}::/home/u1:{shell}\n")
        shadowf.write_text(
            "root:*:19000:0:99999:7:::\n"
            f"u1:$6$x$y:19000:0:99999:7::{expire_field}:\n")
        monkeypatch.setattr(ua, "_PASSWD_PATH", passwd)
        monkeypatch.setattr(ua, "_SHADOW_PATH", shadowf)
        return UserAccountsSnapshot.from_system()
    return _build


class TestExpiryBoundary:
    def test_an_account_expiring_today_is_reported(self, shadow):
        """chage says the account is inaccessible on that date, not after it."""
        snap = shadow(str(_TODAY))
        assert "u1" in snap.expired_accounts

    def test_an_account_that_expired_yesterday_is_reported(self, shadow):
        snap = shadow(str(_TODAY - 1))
        assert "u1" in snap.expired_accounts

    def test_an_account_expiring_tomorrow_is_not_reported(self, shadow):
        snap = shadow(str(_TODAY + 1))
        assert snap.expired_accounts == {}

    def test_an_empty_field_never_expires(self, shadow):
        snap = shadow("")
        assert snap.expired_accounts == {}
        assert snap.ambiguous_expiry_accounts == []

    def test_the_reported_date_matches_the_field(self, shadow):
        snap = shadow("20000")   # chage: Oct 04, 2024
        assert snap.expired_accounts["u1"] == "2024-10-04"


class TestAmbiguousZero:
    def test_zero_is_surfaced_rather_than_skipped(self, shadow):
        snap = shadow("0")
        assert snap.ambiguous_expiry_accounts == ["u1"]

    def test_zero_is_not_silently_filed_as_expired(self, shadow):
        """Picking the other reading would be just as unverified."""
        snap = shadow("0")
        assert snap.expired_accounts == {}

    def test_it_produces_its_own_finding(self, shadow):
        result = check_user_accounts(shadow("0"))
        keys = {f.key for f in result.findings}
        assert "user_accounts.ambiguous_expiry" in keys
        assert "user_accounts.ok" not in keys

    def test_it_carries_no_deduction(self, shadow):
        assert check_user_accounts(shadow("0")).deductions == []


class TestSystemAccountsStillExcluded:
    @pytest.mark.parametrize("field", ["0", "20000", str(_TODAY)])
    def test_a_uid_below_1000_is_ignored_either_way(self, shadow, field):
        """Package-managed accounts are not the admin's business — the rule
        applied to expiry before and must apply to the ambiguous case too."""
        snap = shadow(field, uid=120)
        assert snap.expired_accounts == {}
        assert snap.ambiguous_expiry_accounts == []


class TestUnchangedBehaviour:
    def test_a_negative_field_is_still_ignored(self, shadow):
        assert shadow("-1").expired_accounts == {}
        assert shadow("-1").ambiguous_expiry_accounts == []

    def test_a_non_numeric_field_does_not_raise(self, shadow):
        snap = shadow("not-a-number")
        assert snap.expired_accounts == {}
        assert snap.ambiguous_expiry_accounts == []

    def test_a_clean_account_still_reports_ok(self, shadow):
        result = check_user_accounts(shadow(""))
        assert {f.key for f in result.findings} == {"user_accounts.ok"}
