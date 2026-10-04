"""su restriction, interactive homes and dotfiles, duplicate identifiers.

The guard pins:

  1. pam_wheel is a restriction only on an ``auth`` line whose control fails
     the stack, without ``deny`` — ``sufficient ... trust`` grants su, it
     restricts nobody; a commented example (Fedora ships two) is nothing;
  2. /etc/pam.d/su replaces the vendor copy, it does not merge with it, and an
     unreadable /etc copy is "unknown", never "fall back to the vendor one";
  3. an unrestricted su is scored only when root has a usable password: a
     locked root ('!' or '*') is not a finding, an unread shadow is unknown;
  4. homes: writable by others or owned by another account is a WARN; a .netrc
     group/other can read is a WARN; legacy trust files are INFO; nothing is
     ever opened (a FIFO named .netrc cannot hang the audit); a home on a
     network filesystem is not stat()ed at all and is reported uninspected;
  5. only interactive accounts are examined — root and UID ≥ 1000 with a login
     shell — so `sync` (shell /bin/sync, home /bin) is not "foreign-owned";
  6. duplicate UIDs and names are INFO, never scored.
"""

from __future__ import annotations

import os

import pytest

import bob.checks.user_accounts as ua
from bob.checks.user_accounts import (
    UserAccountsSnapshot,
    _su_restriction,
    check_user_accounts,
)
from tests.helpers import _t


def _keys(result):
    return [f.key for f in result.findings]


def _points(result, key):
    return sum(d.points for d in result.deductions if d.key == key)


# ---- pam_wheel parsing ---------------------------------------------------------

@pytest.mark.parametrize("text,group", [
    ("auth required pam_wheel.so use_uid\n", "wheel"),
    ("auth requisite pam_wheel.so group=sugroup\n", "sugroup"),
    ("-auth required /usr/lib64/security/pam_wheel.so use_uid group=admins\n", "admins"),
    ("auth [success=ignore default=die] pam_wheel.so use_uid\n", "wheel"),
    ("auth required \\\n     pam_wheel.so group=sugroup\n", "sugroup"),
])
def test_restricting_lines(text, group):
    assert _su_restriction(text) == group


@pytest.mark.parametrize("text", [
    # Fedora's stock /etc/pam.d/su: both examples commented out.
    "#auth sufficient pam_wheel.so trust use_uid\n#auth required pam_wheel.so use_uid\n",
    "auth sufficient pam_wheel.so trust use_uid\n",
    "auth required pam_wheel.so deny group=nosu\n",
    "account required pam_wheel.so\n",
    "auth [success=ok default=ignore] pam_wheel.so\n",
    "auth sufficient pam_rootok.so\n@include common-auth\n",
])
def test_non_restricting_lines(text):
    assert _su_restriction(text) is None


# ---- su verdicts -----------------------------------------------------------------

def _su_snap(**kw):
    base = dict(shadow_readable=True, su_pam_established=True)
    base.update(kw)
    return UserAccountsSnapshot(**base)


def test_restricted_is_ok():
    r = check_user_accounts(_su_snap(su_group="sugroup", root_locked=False), t=_t)
    assert "user_accounts.su_restricted" in _keys(r)
    assert _points(r, "user_accounts.su_unrestricted") == 0


def test_unrestricted_with_root_password_deducts():
    r = check_user_accounts(_su_snap(root_locked=False), t=_t)
    assert "user_accounts.su_unrestricted" in _keys(r)
    assert _points(r, "user_accounts.su_unrestricted") == 1


def test_unrestricted_with_locked_root_is_not_a_finding():
    r = check_user_accounts(_su_snap(root_locked=True), t=_t)
    assert "user_accounts.su_root_locked" in _keys(r)
    assert "user_accounts.ok" in _keys(r)
    assert _points(r, "user_accounts.su_unrestricted") == 0


def test_unrestricted_with_unread_shadow_is_unknown():
    r = check_user_accounts(_su_snap(root_locked=None), t=_t)
    assert "user_accounts.su_root_unknown" in _keys(r)
    assert "user_accounts.ok" not in _keys(r)
    assert _points(r, "user_accounts.su_unrestricted") == 0


def test_no_su_pam_file_is_unknown():
    r = check_user_accounts(_su_snap(su_pam_established=False), t=_t)
    assert "user_accounts.su_unknown" in _keys(r)
    assert "user_accounts.ok" not in _keys(r)


# ---- from_system -------------------------------------------------------------------

@pytest.fixture
def host(tmp_path, monkeypatch):
    """A synthetic /etc/passwd, /etc/shadow, su PAM file and mount table."""
    me = os.getuid()
    etc = tmp_path / "etc"
    etc.mkdir()
    su_etc, su_vendor = etc / "su", tmp_path / "vendor-su"
    mounts = tmp_path / "mounts"
    mounts.write_text("")
    monkeypatch.setattr(ua, "_PASSWD_PATH", etc / "passwd")
    monkeypatch.setattr(ua, "_SHADOW_PATH", etc / "shadow")
    monkeypatch.setattr(ua, "_SU_PAM_PATHS", (su_etc, su_vendor))
    su_bin = tmp_path / "su-binary"
    su_bin.write_text("")
    su_bin.chmod(0o755)
    monkeypatch.setattr(ua, "_SU_BINARIES", (str(su_bin),))
    monkeypatch.setattr(ua, "_MOUNTS_PATH", mounts)

    class Host:
        root = tmp_path
        uid = me if me >= 1000 else 1000

        def home(self, name, mode=0o750):
            h = tmp_path / "home" / name
            h.mkdir(parents=True)
            h.chmod(mode)
            return h

        def collect(self, passwd, shadow="root:*:19000:0:99999:7:::\n",
                    su="auth sufficient pam_rootok.so\n", vendor=None, mount_table=""):
            (etc / "passwd").write_text(passwd)
            (etc / "shadow").write_text(shadow)
            if su is not None:
                su_etc.write_text(su)
            if vendor is not None:
                su_vendor.write_text(vendor)
            mounts.write_text(mount_table)
            return UserAccountsSnapshot.from_system()
    return Host()


def _line(user, uid, home, shell="/bin/bash"):
    return f"{user}:x:{uid}:{uid}::{home}:{shell}\n"


class TestSuCollection:
    def test_etc_replaces_vendor_it_does_not_merge(self, host):
        snap = host.collect("", su="auth sufficient pam_rootok.so\n",
                            vendor="auth required pam_wheel.so use_uid\n")
        assert snap.su_pam_established is True
        assert snap.su_group is None

    def test_vendor_used_when_etc_absent(self, host):
        snap = host.collect("", su=None, vendor="auth required pam_wheel.so use_uid\n")
        assert snap.su_group == "wheel"

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads a 0000 file")
    def test_unreadable_etc_is_unknown_not_vendor(self, host):
        snap = host.collect("", su="auth sufficient pam_rootok.so\n",
                            vendor="auth required pam_wheel.so use_uid\n")
        os.chmod(ua._SU_PAM_PATHS[0], 0)
        try:
            snap = UserAccountsSnapshot.from_system()
        finally:
            os.chmod(ua._SU_PAM_PATHS[0], 0o644)
        assert snap.su_pam_established is False
        assert snap.su_group is None

    def test_su_binary_not_executable_by_others_is_a_restriction(self, host):
        import grp
        (host.root / "su-binary").chmod(0o4750)
        snap = host.collect("")
        assert snap.su_binary_group == grp.getgrgid(os.getgid()).gr_name
        r = check_user_accounts(snap, t=_t)
        assert "user_accounts.su_restricted_by_mode" in _keys(r)
        assert _points(r, "user_accounts.su_unrestricted") == 0

    def test_su_binary_executable_by_others_is_not(self, host):
        snap = host.collect("", shadow="root:$6$x$y:19000:0:99999:7:::\n")
        assert snap.su_binary_group is None
        assert _points(check_user_accounts(snap, t=_t), "user_accounts.su_unrestricted") == 1

    @pytest.mark.parametrize("hash_,locked", [("*", True), ("!", True),
                                              ("!$6$x$y", True), ("$6$x$y", False)])
    def test_root_lock_state(self, host, hash_, locked):
        snap = host.collect("", shadow=f"root:{hash_}:19000:0:99999:7:::\n")
        assert snap.root_locked is locked


class TestHomes:
    def test_world_writable_home(self, host):
        h = host.home("alice", 0o757)
        snap = host.collect(_line("alice", host.uid, h))
        assert snap.unsafe_homes == [("alice", str(h), "world_writable")]

    def test_home_owned_by_another_account(self, host):
        h = host.home("bob")
        snap = host.collect(_line("bob", host.uid + 1, h))
        assert snap.unsafe_homes == [("bob", str(h), "foreign_owner")]

    def test_clean_home(self, host):
        h = host.home("carol")
        snap = host.collect(_line("carol", host.uid, h))
        assert snap.unsafe_homes == []
        assert snap.homes_uninspected == []

    @pytest.mark.parametrize("mode,exposed", [(0o600, False), (0o640, True), (0o604, True)])
    def test_netrc_mode(self, host, mode, exposed):
        h = host.home("dave")
        (h / ".netrc").write_text("machine x login y password z\n")
        (h / ".netrc").chmod(mode)
        snap = host.collect(_line("dave", host.uid, h))
        assert snap.exposed_netrc == ([str(h / ".netrc")] if exposed else [])

    def test_netrc_fifo_is_not_opened(self, host):
        h = host.home("erin")
        os.mkfifo(h / ".netrc", 0o644)
        snap = host.collect(_line("erin", host.uid, h))   # would hang if opened
        assert snap.exposed_netrc == []

    def test_legacy_dotfiles(self, host):
        h = host.home("frank")
        for name in (".rhosts", ".forward"):
            (h / name).write_text("")
        snap = host.collect(_line("frank", host.uid, h))
        assert snap.legacy_dotfiles == [str(h / ".rhosts"), str(h / ".forward")]

    def test_network_home_is_not_statted(self, host, monkeypatch):
        h = host.home("gina", 0o777)
        real_stat = os.stat

        def _stat(path, *a, **kw):
            assert not str(path).startswith(str(h)), "stat() on a network home"
            return real_stat(path, *a, **kw)
        monkeypatch.setattr(ua.os, "stat", _stat)
        snap = host.collect(_line("gina", host.uid, h),
                            mount_table=f"srv:/home {h.parent} nfs4 rw 0 0\n")
        assert snap.homes_uninspected == ["gina"]
        assert snap.unsafe_homes == []

    def test_only_interactive_accounts(self, host):
        h = host.home("svc", 0o777)
        snap = host.collect(
            _line("sync", 4, h, shell="/bin/sync")
            + _line("daemonish", host.uid, h, shell="/usr/sbin/nologin")
            + _line("nobody", 65534, h))
        assert snap.unsafe_homes == []

    def test_missing_home_is_not_a_finding(self, host):
        snap = host.collect(_line("hank", host.uid, host.root / "nope"))
        assert snap.unsafe_homes == [] and snap.homes_uninspected == []


class TestHomeVerdicts:
    def test_unsafe_home_deducts(self):
        r = check_user_accounts(UserAccountsSnapshot(
            shadow_readable=True, unsafe_homes=[("a", "/home/a", "world_writable")]), t=_t)
        assert _points(r, "user_accounts.home_unsafe") == 1
        assert "user_accounts.ok" not in _keys(r)

    def test_exposed_netrc_deducts(self):
        r = check_user_accounts(UserAccountsSnapshot(
            shadow_readable=True, exposed_netrc=["/home/a/.netrc"]), t=_t)
        assert _points(r, "user_accounts.netrc_exposed") == 1

    def test_info_findings_never_deduct(self):
        r = check_user_accounts(UserAccountsSnapshot(
            shadow_readable=True, legacy_dotfiles=["/home/a/.rhosts"],
            homes_uninspected=["b"], duplicate_uids=["uid 1001: a, b"],
            duplicate_names=["c"]), t=_t)
        assert {"user_accounts.legacy_dotfiles", "user_accounts.homes_uninspected",
                "user_accounts.duplicate_ids"} <= set(_keys(r))
        assert r.deductions == []
        assert "user_accounts.ok" not in _keys(r)


class TestDuplicates:
    def test_duplicate_uid_and_name(self, host):
        snap = host.collect(
            "root:x:0:0::/nonexistent:/bin/sh\n"
            "a:x:1001:1001::/nonexistent:/bin/sh\n"
            "b:x:1001:1001::/nonexistent:/bin/sh\n"
            "a:x:1002:1002::/nonexistent:/bin/sh\n")
        assert snap.duplicate_uids == ["uid 1001: a, b"]
        assert snap.duplicate_names == ["a"]

    def test_uid_zero_duplicate_is_left_to_uid_zero(self, host):
        snap = host.collect("root:x:0:0::/nonexistent:/bin/sh\n"
                            "toor:x:0:0::/nonexistent:/bin/sh\n")
        assert snap.duplicate_uids == []
        assert snap.uid_zero_accounts == ["toor"]


# ---- BusyBox su (real Alpine 3.24, 2026-10-04) ----------------------------------

@pytest.fixture
def busybox_su(host, monkeypatch):
    bb = host.root / "bbsuid"
    bb.write_text("")
    bb.chmod(0o4111)                     # Alpine's /bin/bbsuid mode, as measured
    link = host.root / "su"
    link.symlink_to(bb)
    monkeypatch.setattr(ua, "_SU_BINARIES", (str(link),))
    return bb


def test_busybox_su_ignores_a_pam_wheel_line(host, busybox_su):
    """linux-pam ships /usr/lib/pam.d/su on Alpine; BusyBox su never reads it, so
    a pam_wheel line there must not turn into 'su restricted' (the false OK)."""
    snap = host.collect("", shadow="root:$6$x$y:19000:0:99999:7:::\n",
                        su=None, vendor="auth required pam_wheel.so use_uid\n")
    assert snap.su_busybox
    r = check_user_accounts(snap, t=lambda key, **kw: key)
    assert "user_accounts.su_restricted" not in _keys(r)
    assert _points(r, "user_accounts.su_unrestricted") == 1
    assert any(f.message == "user_accounts.su_unrestricted_busybox" for f in r.findings)


def test_busybox_su_without_any_pam_is_not_unknown(host, busybox_su):
    """Alpine without linux-pam: no su PAM file is no blind spot for BusyBox su."""
    snap = host.collect("", shadow="root:*:19000:0:99999:7:::\n", su=None)
    r = check_user_accounts(snap, t=_t)
    assert "user_accounts.su_unknown" not in _keys(r)
    assert "user_accounts.su_root_locked" in _keys(r)


def test_busybox_su_restricted_by_mode_still_counts(host, busybox_su):
    busybox_su.chmod(0o4110)
    snap = host.collect("", shadow="root:$6$x$y:19000:0:99999:7:::\n", su=None)
    assert "user_accounts.su_restricted_by_mode" in _keys(check_user_accounts(snap, t=_t))
