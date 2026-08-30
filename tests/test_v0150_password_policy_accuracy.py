"""
v0.15.0 — verdict-accuracy guards for the password-policy check.

Three configuration files, three different owners, and BOB disagreed with all
three. The expectations below were measured, not reasoned:

  - ``PASS_MAX_DAYS`` precedence: ``useradd --prefix`` run against a login.defs
    holding the key twice, then reading the field shadow actually wrote.
  - ``minlen`` precedence and the drop-in directory: libpwquality 1.4.5 called
    through ctypes, under a mount namespace with a synthetic /etc/security.
  - PAM line continuation: ``pam.conf(5)``, whose own worked example is a
    wrapped ``pam_pwquality.so`` line.

The unifying error is reading the *first* match. Both login.defs and
pwquality.conf are last-one-wins, so appending the hardened value to the end of
the file — the way every hardening guide writes it, and the way `echo >>`
works — left BOB reporting the value the operator had just overridden.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bob.checks.password_policy as pp


@pytest.fixture
def policy(tmp_path, monkeypatch):
    """Point the snapshot at a synthetic /etc and collect it."""
    confd = tmp_path / "pwquality.conf.d"
    confd.mkdir()
    for name in ("login.defs", "common-password", "pwquality.conf"):
        (tmp_path / name).write_text("")
    monkeypatch.setattr(pp, "_LOGIN_DEFS_PATH", tmp_path / "login.defs")
    monkeypatch.setattr(pp, "_COMMON_PASSWORD", tmp_path / "common-password")
    monkeypatch.setattr(pp, "_PWQUALITY_CONF", tmp_path / "pwquality.conf")
    monkeypatch.setattr(pp, "_PWQUALITY_CONF_D", confd)

    def _collect(*, login_defs=None, pam=None, pwquality=None, dropins=None):
        if login_defs is not None:
            (tmp_path / "login.defs").write_text(login_defs)
        if pam is not None:
            (tmp_path / "common-password").write_text(pam)
        if pwquality is not None:
            (tmp_path / "pwquality.conf").write_text(pwquality)
        for name, body in (dropins or {}).items():
            (confd / name).write_text(body)
        return pp.PasswordPolicySnapshot.from_system()
    return _collect


class TestLoginDefsIsLastOneWins:
    """Verified with shadow's own useradd: given the key twice, the account it
    creates carries the value from the *last* line."""

    def test_hardening_appended_to_the_end_is_seen(self, policy):
        snap = policy(login_defs="PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 90\n")
        assert snap.pass_max_days == 90, \
            "reading the first match reported the distro default the operator overrode"

    def test_a_weakening_appended_to_the_end_is_not_hidden(self, policy):
        """The dangerous direction: BOB would have reported the hardened value
        while the system used the weak one."""
        snap = policy(login_defs="PASS_MAX_DAYS 90\nPASS_MAX_DAYS 99999\n")
        assert snap.pass_max_days == 99999

    def test_min_days_follows_the_same_rule(self, policy):
        snap = policy(login_defs="PASS_MIN_DAYS 0\nPASS_MIN_DAYS 7\n")
        assert snap.pass_min_days == 7

    def test_a_commented_line_is_still_ignored(self, policy):
        snap = policy(login_defs="PASS_MAX_DAYS 90\n# PASS_MAX_DAYS 99999\n")
        assert snap.pass_max_days == 90

    def test_a_single_occurrence_is_unaffected(self, policy):
        snap = policy(login_defs="PASS_MAX_DAYS 60\n")
        assert snap.pass_max_days == 60


class TestPwqualityMatchesTheLibrary:
    def test_duplicate_minlen_takes_the_last(self, policy):
        snap = policy(pwquality="minlen = 8\nminlen = 14\n")
        assert snap.pam_minlen == 14

    def test_a_drop_in_is_read_at_all(self, policy):
        """Debian ships pwquality.conf with every setting commented out, so the
        drop-in directory is where hardening actually lands — and BOB did not
        open it."""
        snap = policy(dropins={"50-hardening.conf": "minlen = 14\n"})
        assert snap.pam_minlen == 14

    def test_the_main_file_overrides_a_drop_in(self, policy):
        """libpwquality reads conf.d *first*, then the main file, so the main
        file wins where both set a value. Measured, not inferred: the man page
        wording admits both readings."""
        snap = policy(pwquality="minlen = 8\n",
                      dropins={"50-hardening.conf": "minlen = 14\n"})
        assert snap.pam_minlen == 8

    def test_drop_ins_are_read_in_ascii_order(self, policy):
        snap = policy(dropins={"10-a.conf": "minlen = 10\n",
                               "90-z.conf": "minlen = 20\n"})
        assert snap.pam_minlen == 20

    def test_a_non_conf_file_in_the_directory_is_ignored(self, policy):
        snap = policy(dropins={"backup.conf.bak": "minlen = 99\n",
                               "50-real.conf": "minlen = 12\n"})
        assert snap.pam_minlen == 12


class TestPamContinuations:
    def test_a_wrapped_module_line_keeps_its_minlen(self, policy):
        """The exact shape pam.conf(5) uses as its own example."""
        snap = policy(pam="password requisite pam_pwquality.so retry=3 \\\n"
                          "         minlen=14 difok=4 ucredit=-1\n")
        assert snap.pam_quality_module == "pam_pwquality"
        assert snap.pam_minlen == 14

    def test_an_unwrapped_line_still_works(self, policy):
        snap = policy(pam="password requisite pam_pwquality.so retry=3 minlen=12\n")
        assert snap.pam_minlen == 12

    def test_a_commented_module_line_is_ignored(self, policy):
        snap = policy(pam="# password requisite pam_pwquality.so minlen=14\n")
        assert snap.pam_quality_module is None
