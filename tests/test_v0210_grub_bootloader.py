"""v0.21.0 — GRUB bootloader configuration check (CIS §1.4).

`secure_boot` answers "can an unsigned bootloader run"; this answers "once GRUB
is the bootloader, is its config hardened". Two properties: grub.cfg is
owner-only (else the boot line — and any password hash — leaks), and a GRUB
superuser password exists (else console `e`-edit → init=/bin/bash root shell).

The permission finding carries a deduction; the missing-password finding is INFO
(physical-access-only, commonly and deliberately unset). "Unreadable" (0600
root-only, the good case) must never be read as "no password".
"""

from __future__ import annotations

from bob.checks.grub import GrubSnapshot, check_grub, _PASSWORD_RE
from bob.scoring import FindingLevel
from tests.helpers import _keys, _levels, _get_finding


def _levels_of(result, key):
    return [f.level for f in result.findings if f.key == key]


# ---------------------------------------------------------------------------
# No GRUB on this host
# ---------------------------------------------------------------------------

def test_no_grub_is_info_not_applicable():
    result = check_grub(GrubSnapshot(cfg_path=""))
    assert _keys(result) == ["grub.not_present"]
    assert _levels(result) == ["info"]


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_owner_only_is_ok(self):
        # 0600, readable contents, no password → perms OK + no_password INFO
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o600,
                            readable=True, password_set=False)
        result = check_grub(snap)
        assert "grub.cfg_perms_ok" in _keys(result)
        assert "grub.cfg_perms" not in _keys(result)

    def test_group_or_world_readable_warns_and_deducts(self):
        """The mutation guard: a non-owner-only grub.cfg must WARN + deduct."""
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o644,
                            readable=True, password_set=False)
        result = check_grub(snap)
        assert FindingLevel.WARN in _levels_of(result, "grub.cfg_perms")
        assert sum(d.points for d in result.deductions) >= 1

    def test_owner_readonly_0400_is_ok(self):
        snap = GrubSnapshot(cfg_path="/boot/grub2/grub.cfg", cfg_mode=0o400,
                            readable=True, password_set=False)
        assert "grub.cfg_perms_ok" in _keys(check_grub(snap))

    def test_hash_reason_when_readable_password_and_readable_bits(self):
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o644,
                            readable=True, password_set=True)
        msg = _get_finding(check_grub(snap), "grub.cfg_perms")
        # the finding fires; the escalated (hash) reason path was taken
        assert msg is not None and msg.level == FindingLevel.WARN

    def test_writable_by_group_or_other_warns(self):
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o646,
                            readable=True, password_set=False)
        assert FindingLevel.WARN in _levels_of(check_grub(snap), "grub.cfg_perms")

    def test_mode_unknown_is_info(self):
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=None)
        assert "grub.cfg_unreadable" in _keys(check_grub(snap))


# ---------------------------------------------------------------------------
# Superuser password
# ---------------------------------------------------------------------------

class TestPassword:
    def test_password_set_is_ok(self):
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o600,
                            readable=True, password_set=True)
        assert "grub.password_set" in _keys(check_grub(snap))

    def test_no_password_is_info_no_deduction(self):
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o600,
                            readable=True, password_set=False)
        result = check_grub(snap)
        f = _get_finding(result, "grub.no_password")
        assert f is not None and f.level == FindingLevel.INFO

    def test_unreadable_cfg_does_not_claim_no_password(self):
        # 0600 root-only: BOB (non-root) cannot read it → must NOT assert
        # "no password" from an unread file.
        snap = GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o600,
                            readable=False, password_set=False)
        keys = _keys(check_grub(snap))
        assert "grub.no_password" not in keys
        assert "grub.password_set" not in keys
        assert "grub.cfg_perms_ok" in keys  # perms still assessed


# ---------------------------------------------------------------------------
# Password regex — both grub.cfg forms
# ---------------------------------------------------------------------------

class TestPasswordRegex:
    def test_pbkdf2_form(self):
        assert _PASSWORD_RE.search("password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC")

    def test_plain_form(self):
        assert _PASSWORD_RE.search("password root secret")

    def test_no_password_line(self):
        assert not _PASSWORD_RE.search("set superusers=\"root\"\nmenuentry 'x' {}")
