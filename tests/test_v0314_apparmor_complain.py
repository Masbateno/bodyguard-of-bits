"""v0.31.4 — AppArmor profiles in complain mode: no mass enforce, snap profiles said.

`mac_policy.apparmor_complain_profiles` printed `sudo aa-enforce /etc/apparmor.d/*`
as its fix. Measured on Ubuntu Server 26.04 (AppArmor 5.0.2), 9 November 2026
(~/.cache/bob-fieldtest/netnsbench/aa0314/aa-survey-ubuntu.txt): aa-enforce was
not installed ("command not found"); with apparmor-utils, run on a copy of
/etc/apparmor.d with --no-reload, it set 97 files to enforce, 74 of them shipped
with flags=(unconfined) on purpose (1password, Discord, MongoDB Compass…), and
did not touch the 78 snap profiles that made 78 of the 80 counted — snapd keeps
them under /var/lib/snapd/apparmor/profiles (all four snaps were classic). The
other two, Xorg and Xorg_wrap, are shipped flags=(complain). The finding now
gives a check (`sudo aa-status`), says how many of the profiles are snapd's and
names the others, and the detail gives the measured reason not to enforce all.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import mac_policy as mp

#: The kernel's list, as measured on Ubuntu (a few lines of it).
_PROFILES = """\
snap.microk8s.microk8s (complain)
snap.powershell.powershell (complain)
Xorg (complain)
Xorg_wrap (complain)
/usr/sbin/cupsd (enforce)
1password (unconfined)
"""


def _snap(names, complain=80):
    return mp.MacPolicySnapshot(apparmor_installed=True, apparmor_active=True, apparmor_enforcing=222,
                                apparmor_complain=complain, apparmor_complain_names=names)


def _finding(snap, t=lambda k, **kw: k + (" " + repr(sorted(kw.items())) if kw else "")):
    res = mp.check_mac_policy(snap, t=t)
    return next(f for f in res.findings if f.key == "mac_policy.apparmor_complain_profiles")


class TestTheCommand:
    def test_no_mass_enforce_a_check_that_lists_them(self):
        f = _finding(_snap(["Xorg", "snap.microk8s.microk8s"]))
        assert f.cmd == "sudo aa-status" and f.cmd_type == "check"
        assert "aa-enforce /etc/apparmor.d/*" not in (f.cmd or "")

    def test_the_same_when_the_names_are_unknown(self):
        f = _finding(_snap(None))
        assert f.cmd == "sudo aa-status"


class TestTheSplit:
    def test_snap_profiles_counted_the_others_named(self):
        f = _finding(_snap(["Xorg", "Xorg_wrap", "snap.microk8s.microk8s", "snap.powershell.powershell"]))
        assert "mac_policy.apparmor_complain_split" in f.detail
        assert "('snap', 2)" in f.detail and "'Xorg, Xorg_wrap'" in f.detail

    def test_only_snap_profiles(self):
        f = _finding(_snap(["snap.microk8s.microk8s"]))
        assert "('snap', 1)" in f.detail and "('others', '—')" in f.detail

    def test_unknown_names_no_split(self):
        assert "apparmor_complain_split" not in _finding(_snap(None)).detail


class TestTheKernelList:
    def test_the_names_in_complain_mode(self, tmp_path, monkeypatch):
        p = tmp_path / "profiles"
        p.write_text(_PROFILES)
        monkeypatch.setattr(mp, "_KERNEL_PROFILES", p)
        assert mp._apparmor_complain_names() == ["Xorg", "Xorg_wrap", "snap.microk8s.microk8s",
                                                 "snap.powershell.powershell"]

    def test_unreadable_is_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mp, "_KERNEL_PROFILES", tmp_path / "absent")
        assert mp._apparmor_complain_names() is None


@pytest.mark.parametrize("lang, words", [
    ("en", "one at a time, not /etc/apparmor.d/*: measured on Ubuntu Server 26.04, that set 97 files to enforce, 74 of them shipped unconfined on purpose"),
    ("fr", "un à la fois, pas /etc/apparmor.d/* : mesuré sur Ubuntu Server 26.04, cela a passé 97 fichiers en enforce, dont 74 livrés non confinés exprès")],
    ids=["en", "fr"])
def test_the_detail_gives_the_measured_reason(lang, words):
    i18n.init(lang)
    try:
        f = _finding(_snap(["Xorg", "snap.microk8s.microk8s"]), t=i18n.t)
    finally:
        i18n.init(lang="en")
    assert words in f.detail


def test_from_system_reads_the_names(tmp_path, monkeypatch):
    monkeypatch.setattr(mp, "_command_exists", lambda c: False)
    monkeypatch.setattr(mp, "_AA_MODULE_DIR", tmp_path)
    monkeypatch.setattr(mp, "_apparmor_live_in_kernel", lambda: True)
    monkeypatch.setattr(mp, "_apparmor_profiles_from_kernel", lambda: (5, 3, 2))
    monkeypatch.setattr(mp, "_apparmor_complain_names", lambda: ["Xorg", "snap.x.y"])
    snap = mp.MacPolicySnapshot.from_system()
    assert snap.apparmor_complain == 2 and snap.apparmor_complain_names == ["Xorg", "snap.x.y"]
