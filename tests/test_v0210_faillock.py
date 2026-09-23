"""v0.21.0 — PAM account-lockout check (pam_faillock), CIS §5.3, profile-aware.

Distinct from fail2ban (network IP ban): pam_faillock locks the account after N
failed authentications, covering local logins, su, sudo. Absence is WARN on a
server (real brute-force surface) and INFO on a desktop (physical-access threat
smaller, lockout is a DoS lever). Unreadable PAM stack is unknown, not clean.
"""

from __future__ import annotations

import bob.checks.faillock as fl
from bob.checks.faillock import FaillockSnapshot, check_faillock
from bob.scoring import FindingLevel
from tests.helpers import _keys, _get_finding


def test_unreadable_is_unknown():
    assert _keys(check_faillock(FaillockSnapshot(readable=False))) == ["faillock.unknown"]


class TestConfigured:
    def test_faillock_configured_is_ok(self):
        snap = FaillockSnapshot(readable=True, module="faillock", deny=5)
        r = check_faillock(snap, profile_name="server")
        assert _keys(r) == ["faillock.configured"]
        assert not r.deductions

    def test_tally2_configured_is_ok(self):
        snap = FaillockSnapshot(readable=True, module="tally2", deny=3)
        assert _keys(check_faillock(snap, profile_name="server")) == ["faillock.configured"]


class TestNotConfigured:
    def test_server_warns_and_deducts(self):
        """The mutation guard: no lockout on a server must WARN + deduct."""
        snap = FaillockSnapshot(readable=True, module="")
        r = check_faillock(snap, profile_name="server")
        assert FindingLevel.WARN in [f.level for f in r.findings
                                     if f.key == "faillock.not_configured"]
        assert sum(d.points for d in r.deductions) >= 1

    def test_desktop_is_info_no_deduction(self):
        snap = FaillockSnapshot(readable=True, module="")
        r = check_faillock(snap, profile_name="desktop")
        f = _get_finding(r, "faillock.not_configured")
        assert f is not None and f.level == FindingLevel.INFO
        assert not r.deductions

    def test_workstation_is_info(self):
        snap = FaillockSnapshot(readable=True, module="")
        r = check_faillock(snap, profile_name="workstation")
        assert _get_finding(r, "faillock.not_configured").level == FindingLevel.INFO


class TestFromSystem:
    def test_detects_faillock_and_deny_from_conf(self, monkeypatch):
        def exists(p):
            s = str(p)
            return s.endswith("common-auth") or s.endswith("faillock.conf")
        monkeypatch.setattr(fl, "path_exists", exists)
        def read(p, **kw):
            s = str(p)
            if s.endswith("common-auth"):
                return "auth required pam_faillock.so preauth\nauth [default=die] pam_faillock.so authfail\n"
            if s.endswith("faillock.conf"):
                return "# comment\ndeny = 4\nunlock_time = 600\n"
            raise OSError
        monkeypatch.setattr(fl, "read_text_capped", read)
        snap = FaillockSnapshot.from_system()
        assert snap.module == "faillock"
        assert snap.deny == 4

    def test_no_module_when_stack_has_none(self, monkeypatch):
        monkeypatch.setattr(fl, "path_exists", lambda p: str(p).endswith("common-auth"))
        monkeypatch.setattr(fl, "read_text_capped",
                            lambda p, **kw: "auth required pam_unix.so\n")
        snap = FaillockSnapshot.from_system()
        assert snap.module == "" and snap.readable is True

    def test_commented_faillock_line_ignored(self, monkeypatch):
        monkeypatch.setattr(fl, "path_exists", lambda p: str(p).endswith("common-auth"))
        monkeypatch.setattr(fl, "read_text_capped",
                            lambda p, **kw: "# auth required pam_faillock.so preauth\n")
        assert FaillockSnapshot.from_system().module == ""

    def test_no_pam_files_is_unreadable(self, monkeypatch):
        monkeypatch.setattr(fl, "path_exists", lambda p: False)
        assert FaillockSnapshot.from_system().readable is False
