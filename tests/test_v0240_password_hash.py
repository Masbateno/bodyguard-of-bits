"""Password-hashing algorithm — login.defs ENCRYPT_METHOD and the pam_unix option.

Two paths write /etc/shadow hashes: useradd/chpasswd/newusers follow
``ENCRYPT_METHOD`` in login.defs, ``passwd`` follows the hash option on the
``pam_unix.so`` password line. A weak value on either one leaves crackable
hashes for the accounts that path touches. The guard pins:

  1. MD5, DES and bigcrypt on either source are a WARN with a deduction;
  2. SHA256 is reported (INFO), not scored — acceptable, not what CIS asks for;
  3. SHA512 / yescrypt / bcrypt are OK;
  4. neither source naming an algorithm is "unknown" — never inferred as DES,
     never read as strong;
  5. a value BOB does not recognise is not a verdict either way;
  6. ``from_system`` reads the *last* ENCRYPT_METHOD (last-one-wins), ignores
     comments, and picks the hash option off the pam_unix line even though the
     quality-module loop stops before reaching it.
"""

from __future__ import annotations

import pytest

import bob.checks.password_policy as pp
from bob.checks.password_policy import (
    PasswordPolicySnapshot,
    check_password_policy,
)
from tests.helpers import _t


def _snap(**kw):
    base = dict(login_defs_readable=True, pass_max_days=90, pass_min_days=1,
                pam_quality_module="pam_pwquality")
    base.update(kw)
    return PasswordPolicySnapshot(**base)


def _keys(result):
    return [f.key for f in result.findings]


def _hash_points(result):
    return sum(d.points for d in result.deductions
               if d.key == "password_policy.weak_hash")


@pytest.mark.parametrize("field", ["encrypt_method", "pam_unix_hash"])
@pytest.mark.parametrize("algo", ["MD5", "DES", "BIGCRYPT"])
def test_weak_algorithm_on_either_source_deducts(field, algo):
    r = check_password_policy(_snap(**{field: algo}), t=_t)
    assert "password_policy.weak_hash" in _keys(r)
    assert _hash_points(r) == 1


def test_weak_wins_over_a_strong_other_source():
    """passwd hashing with yescrypt does not fix accounts useradd creates with MD5."""
    r = check_password_policy(_snap(encrypt_method="MD5", pam_unix_hash="YESCRYPT"), t=_t)
    assert "password_policy.weak_hash" in _keys(r)
    assert "password_policy.hash_strong" not in _keys(r)


def test_sha256_is_reported_not_scored():
    r = check_password_policy(_snap(encrypt_method="SHA256"), t=_t)
    assert "password_policy.hash_acceptable" in _keys(r)
    assert _hash_points(r) == 0


@pytest.mark.parametrize("algo", ["SHA512", "YESCRYPT", "GOST_YESCRYPT", "BLOWFISH", "BCRYPT"])
def test_strong_algorithm_is_ok(algo):
    r = check_password_policy(_snap(encrypt_method=algo), t=_t)
    assert "password_policy.hash_strong" in _keys(r)
    assert _hash_points(r) == 0


def test_neither_source_is_unknown_not_des_and_not_strong():
    r = check_password_policy(_snap(), t=_t)
    keys = _keys(r)
    assert "password_policy.hash_unknown" in keys
    assert "password_policy.weak_hash" not in keys
    assert "password_policy.hash_strong" not in keys
    assert _hash_points(r) == 0


def test_unrecognised_value_is_not_a_verdict():
    r = check_password_policy(_snap(encrypt_method="ROT13"), t=_t)
    keys = _keys(r)
    assert "password_policy.hash_unrecognised" in keys
    assert "password_policy.hash_strong" not in keys
    assert _hash_points(r) == 0


# ---- from_system ------------------------------------------------------------

@pytest.fixture
def collect(tmp_path, monkeypatch):
    confd = tmp_path / "pwquality.conf.d"
    confd.mkdir()
    (tmp_path / "pwquality.conf").write_text("")
    monkeypatch.setattr(pp, "_LOGIN_DEFS_PATH", tmp_path / "login.defs")
    monkeypatch.setattr(pp, "_LOGIN_DEFS_VENDOR", tmp_path / "vendor.login.defs")
    monkeypatch.setattr(pp, "_PWQUALITY_CONF", tmp_path / "pwquality.conf")
    monkeypatch.setattr(pp, "_PWQUALITY_CONF_D", confd)
    # Never the host's own passwd: CI integration runs on Alpine (BusyBox).
    monkeypatch.setattr(pp, "_PASSWD_BINARIES", (str(tmp_path / "no-passwd"),))

    def _collect(login_defs: str, pam: str) -> PasswordPolicySnapshot:
        (tmp_path / "login.defs").write_text(login_defs)
        (tmp_path / "common-password").write_text(pam)
        return PasswordPolicySnapshot.from_system(
            _pam_paths=(tmp_path / "common-password",))
    return _collect


def test_from_system_reads_last_encrypt_method_and_skips_comments(collect):
    snap = collect("# You should use ENCRYPT_METHOD.\n"
                   "ENCRYPT_METHOD SHA512\n"
                   "#ENCRYPT_METHOD DES\n"
                   "ENCRYPT_METHOD md5\n", "")
    assert snap.encrypt_method == "MD5"


def test_from_system_unset_encrypt_method_stays_none(collect):
    snap = collect("PASS_MAX_DAYS 90\n", "")
    assert snap.encrypt_method is None


def test_from_system_reads_pam_unix_hash_after_quality_module(collect):
    """Debian's stock common-password: pwquality first, pam_unix after it."""
    pam = ("password requisite pam_pwquality.so retry=3\n"
           "password [success=1 default=ignore] pam_unix.so obscure use_authtok "
           "try_first_pass yescrypt\n")
    snap = collect("", pam)
    assert snap.pam_quality_module == "pam_pwquality"
    assert snap.pam_unix_hash == "YESCRYPT"


def test_from_system_commented_pam_unix_line_is_ignored(collect):
    snap = collect("", "#password sufficient pam_unix.so md5\n"
                       "password sufficient pam_unix.so sha512\n")
    assert snap.pam_unix_hash == "SHA512"


def test_from_system_pam_unix_without_hash_option_stays_none(collect):
    snap = collect("", "password sufficient pam_unix.so obscure use_authtok\n")
    assert snap.pam_unix_hash is None


# ---- stress-test finding (Mint, 2026-10-04): login.defs present but unread -------

def test_unreadable_login_defs_withholds_strong_and_says_so(collect, tmp_path):
    import os
    fifo = tmp_path / "login.defs"
    snap = collect("", "password sufficient pam_unix.so yescrypt\n")
    fifo.unlink()
    os.mkfifo(fifo)
    snap = PasswordPolicySnapshot.from_system(_pam_paths=(tmp_path / "common-password",))
    assert snap.login_defs_unreadable and not snap.login_defs_readable
    keys = _keys(check_password_policy(snap, t=_t))
    assert "password_policy.login_defs_unreadable" in keys
    assert "password_policy.hash_strong" not in keys
    assert "password_policy.hash_unknown" not in keys


def test_absent_login_defs_is_not_unreadable(collect, tmp_path):
    collect("", "password sufficient pam_unix.so yescrypt\n")
    (tmp_path / "login.defs").unlink()
    snap = PasswordPolicySnapshot.from_system(_pam_paths=(tmp_path / "common-password",))
    assert not snap.login_defs_unreadable
    assert "password_policy.hash_strong" in _keys(check_password_policy(snap, t=_t))


def test_weakest_pam_unix_wins_across_stacks(tmp_path, monkeypatch):
    """Fedora reads system-auth (local passwd) and password-auth (remote): md5 in
    the first must not be hidden by yescrypt in the second (real Fedora 44)."""
    monkeypatch.setattr(pp, "_LOGIN_DEFS_PATH", tmp_path / "login.defs")
    monkeypatch.setattr(pp, "_LOGIN_DEFS_VENDOR", tmp_path / "vendor.login.defs")
    monkeypatch.setattr(pp, "_PWQUALITY_CONF", tmp_path / "pwquality.conf")
    monkeypatch.setattr(pp, "_PWQUALITY_CONF_D", tmp_path / "pwq.d")
    (tmp_path / "system-auth").write_text("password sufficient pam_unix.so md5 shadow\n")
    (tmp_path / "password-auth").write_text("password sufficient pam_unix.so yescrypt shadow\n")
    snap = PasswordPolicySnapshot.from_system(
        _pam_paths=(tmp_path / "system-auth", tmp_path / "password-auth"))
    assert snap.pam_unix_hash == "MD5"
    assert "password_policy.weak_hash" in _keys(check_password_policy(snap, t=_t))


def test_unreadable_etc_override_is_reported_even_if_vendor_read(collect, tmp_path):
    """openSUSE: /usr/etc/login.defs read, /etc/login.defs (the admin's override)
    present but a FIFO — the vendor values say nothing about the override."""
    import os
    collect("", "password sufficient pam_unix.so\n")
    (tmp_path / "vendor.login.defs").write_text("ENCRYPT_METHOD SHA512\n")
    (tmp_path / "login.defs").unlink()
    os.mkfifo(tmp_path / "login.defs")
    snap = PasswordPolicySnapshot.from_system(_pam_paths=(tmp_path / "common-password",))
    assert snap.login_defs_readable and snap.login_defs_unreadable
    keys = _keys(check_password_policy(snap, t=_t))
    assert "password_policy.login_defs_unreadable" in keys
    assert "password_policy.hash_strong" not in keys


# ---- BusyBox passwd (real Alpine 3.24, 2026-10-04) --------------------------------

def test_busybox_passwd_is_builtin_not_unknown():
    from bob.visibility import is_visibility_key
    keys = _keys(check_password_policy(_snap(passwd_busybox=True), t=_t))
    assert "password_policy.hash_builtin" in keys
    assert "password_policy.hash_unknown" not in keys
    assert not is_visibility_key("password_policy.hash_builtin")


def test_busybox_passwd_detected_through_the_symlink(collect, tmp_path, monkeypatch):
    bb = tmp_path / "bbsuid"
    bb.write_text("")
    (tmp_path / "passwd").symlink_to(bb)
    monkeypatch.setattr(pp, "_PASSWD_BINARIES", (str(tmp_path / "passwd"),))
    snap = collect("", "")
    assert snap.passwd_busybox


def test_a_named_algorithm_still_wins_over_busybox():
    """shadow installed beside BusyBox: login.defs names the method — use it."""
    keys = _keys(check_password_policy(_snap(passwd_busybox=True, encrypt_method="MD5"), t=_t))
    assert "password_policy.weak_hash" in keys
