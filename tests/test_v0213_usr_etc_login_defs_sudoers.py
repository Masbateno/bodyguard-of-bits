"""login.defs and sudoers must honour the /usr/etc vendor layout (openSUSE).

Same root cause as the SSH /usr/etc gap: openSUSE Leap 16 ships login.defs and
sudoers under /usr/etc, with /etc as the optional override. BOB read only the
/etc paths, so on openSUSE it reported the default PASS_MAX_DAYS and never
audited the vendor sudoers. /etc wins when present (unchanged elsewhere); when
/etc is absent, the /usr/etc file is read.
"""

from __future__ import annotations

from pathlib import Path

from bob.checks import file_perms, password_policy
from bob.checks.file_perms import _collect_nopasswd_entries


# --- login.defs -------------------------------------------------------------

def test_login_defs_read_from_vendor_when_etc_absent(tmp_path, monkeypatch):
    etc = tmp_path / "etc_login.defs"  # not created
    vendor = tmp_path / "usr_etc_login.defs"
    vendor.write_text("PASS_MAX_DAYS 30\nPASS_MIN_DAYS 7\n", encoding="utf-8")
    monkeypatch.setattr(password_policy, "_LOGIN_DEFS_PATH", etc)
    monkeypatch.setattr(password_policy, "_LOGIN_DEFS_VENDOR", vendor)

    snap = password_policy.PasswordPolicySnapshot.from_system(_pam_paths=())

    assert snap.login_defs_readable is True
    assert snap.pass_max_days == 30
    assert snap.pass_min_days == 7


def test_login_defs_etc_wins_over_vendor(tmp_path, monkeypatch):
    etc = tmp_path / "etc_login.defs"
    etc.write_text("PASS_MAX_DAYS 90\n", encoding="utf-8")
    vendor = tmp_path / "usr_etc_login.defs"
    vendor.write_text("PASS_MAX_DAYS 30\n", encoding="utf-8")
    monkeypatch.setattr(password_policy, "_LOGIN_DEFS_PATH", etc)
    monkeypatch.setattr(password_policy, "_LOGIN_DEFS_VENDOR", vendor)

    snap = password_policy.PasswordPolicySnapshot.from_system(_pam_paths=())

    assert snap.pass_max_days == 90  # /etc override wins


# --- sudoers ----------------------------------------------------------------

def test_sudoers_nopasswd_read_from_vendor_when_etc_absent(tmp_path, monkeypatch):
    """/etc/sudoers absent, the /usr/etc vendor file carries NOPASSWD:ALL — it
    must be seen, not silently missed."""
    etc = tmp_path / "etc_sudoers"          # not created
    etc_d = tmp_path / "etc_sudoers_d"       # not created
    vendor = tmp_path / "usr_etc_sudoers"
    vendor.write_text("baduser ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    vendor_d = tmp_path / "usr_etc_sudoers_d"  # not created (no drop-ins)
    monkeypatch.setattr(file_perms, "_SUDOERS", etc)
    monkeypatch.setattr(file_perms, "_SUDOERS_D", etc_d)
    monkeypatch.setattr(file_perms, "_SUDOERS_VENDOR", vendor)
    monkeypatch.setattr(file_perms, "_SUDOERS_D_VENDOR", vendor_d)

    nopasswd_all, _specific, readable = _collect_nopasswd_entries()

    assert readable is True
    assert any("baduser" in line for line in nopasswd_all)


def test_sudoers_vendor_dropin_dir_is_read(tmp_path, monkeypatch):
    """The vendor sudoers @includedir's /usr/etc/sudoers.d too — a NOPASSWD rule
    there must be caught."""
    etc = tmp_path / "etc_sudoers"           # not created
    etc_d = tmp_path / "etc_sudoers_d"        # not created
    vendor = tmp_path / "usr_etc_sudoers"     # not created
    vendor_d = tmp_path / "usr_etc_sudoers_d"
    vendor_d.mkdir()
    (vendor_d / "90-bad").write_text("eve ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    monkeypatch.setattr(file_perms, "_SUDOERS", etc)
    monkeypatch.setattr(file_perms, "_SUDOERS_D", etc_d)
    monkeypatch.setattr(file_perms, "_SUDOERS_VENDOR", vendor)
    monkeypatch.setattr(file_perms, "_SUDOERS_D_VENDOR", vendor_d)

    nopasswd_all, _specific, readable = _collect_nopasswd_entries()

    assert any("eve" in line for line in nopasswd_all)
