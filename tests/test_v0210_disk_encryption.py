"""v0.21.0 — storage-encryption (LUKS/dm-crypt) check, profile-gated.

Reports whether the root filesystem is backed by an encrypted device. Never
binary: desktop/workstation → WARN on a plain root (portable, physically
exposed), server → INFO (locked rack, no boot console), container → not
applicable, unresolved root → unknown (not clean). Detection walks the
device-mapper stack so LVM-on-LUKS is recognised, not just a bare crypt mount.
"""

from __future__ import annotations

import os

import bob.checks.disk_encryption as de
from bob.checks.disk_encryption import DiskEncryptionSnapshot, check_disk_encryption
from bob.scoring import FindingLevel
from tests.helpers import _keys, _get_finding


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

class TestVerdict:
    def test_encrypted_root_is_ok(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=True)
        r = check_disk_encryption(snap, profile_name="desktop")
        assert _keys(r) == ["disk_encryption.root_encrypted"]
        assert not r.deductions

    def test_desktop_plain_root_warns_and_deducts(self):
        """The mutation guard: a plain root on a portable host WARNs + deducts."""
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=False)
        r = check_disk_encryption(snap, profile_name="desktop")
        f = _get_finding(r, "disk_encryption.root_unencrypted")
        assert f is not None and f.level == FindingLevel.WARN
        assert sum(d.points for d in r.deductions) >= 1

    def test_workstation_plain_root_warns(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=False)
        r = check_disk_encryption(snap, profile_name="workstation")
        assert _get_finding(r, "disk_encryption.root_unencrypted").level == FindingLevel.WARN

    def test_server_plain_root_is_info_no_deduction(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=False)
        r = check_disk_encryption(snap, profile_name="server")
        f = _get_finding(r, "disk_encryption.root_unencrypted_server")
        assert f is not None and f.level == FindingLevel.INFO
        assert not r.deductions

    def test_container_is_not_applicable(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=False)
        r = check_disk_encryption(snap, profile_name="container")
        assert _keys(r) == ["disk_encryption.container_na"]
        assert not r.deductions

    def test_unreadable_is_unknown(self):
        r = check_disk_encryption(DiskEncryptionSnapshot(readable=False),
                                  profile_name="desktop")
        assert _keys(r) == ["disk_encryption.unknown"]
        assert not r.deductions

    def test_unresolved_root_is_unknown(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=None)
        assert _keys(check_disk_encryption(snap, profile_name="desktop")) \
            == ["disk_encryption.unknown"]

    def test_unresolved_root_with_volumes_reports_partial(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=None,
                                      crypt_volumes=["data"])
        r = check_disk_encryption(snap, profile_name="desktop")
        assert _keys(r) == ["disk_encryption.volumes_present_root_unknown"]
        assert not r.deductions

    def test_desktop_plain_root_mentions_other_volumes(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=False,
                                      crypt_volumes=["backup"])
        r = check_disk_encryption(snap, profile_name="desktop")
        assert _get_finding(r, "disk_encryption.root_unencrypted") is not None


# ---------------------------------------------------------------------------
# from_system — device-mapper stack walk
# ---------------------------------------------------------------------------

def _fake_system(monkeypatch, *, sys_block, uuids, names, mounts,
                 links=None, slaves=None):
    """Wire up a fake /sys + /proc + /dev/mapper for from_system()."""
    links = links or {}
    slaves = slaves or {}

    def fake_listdir(path):
        p = str(path)
        if p == de._SYS_BLOCK:
            return list(sys_block)
        for node, sl in slaves.items():
            if p == f"{de._SYS_BLOCK}/{node}/slaves":
                return list(sl)
        raise OSError("no such dir")

    def fake_readlink(path):
        p = str(path)
        if p in links:
            return links[p]
        raise OSError("not a link")

    def fake_read(path, **kw):
        p = str(path)
        if p == de._MOUNTS:
            return mounts
        for node, u in uuids.items():
            if p == f"{de._SYS_BLOCK}/{node}/dm/uuid":
                return u
        for node, n in names.items():
            if p == f"{de._SYS_BLOCK}/{node}/dm/name":
                return n
        raise OSError("no such file")

    monkeypatch.setattr(os, "listdir", fake_listdir)
    monkeypatch.setattr(os, "readlink", fake_readlink)
    monkeypatch.setattr(de, "read_text_capped", fake_read)
    monkeypatch.setattr(de, "path_exists", lambda p: False)


class TestFromSystem:
    def test_plain_root_is_false(self, monkeypatch):
        """A raw partition backing / is a firm 'not encrypted'."""
        _fake_system(
            monkeypatch,
            sys_block=["sda"],
            uuids={}, names={},
            mounts="/dev/sda2 / ext4 rw,relatime 0 0\n",
        )
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.root_encrypted is False
        assert snap.crypt_volumes == []

    def test_luks_direct_root_is_true(self, monkeypatch):
        _fake_system(
            monkeypatch,
            sys_block=["dm-0", "sda"],
            uuids={"dm-0": "CRYPT-LUKS2-abcd-cryptroot"},
            names={"dm-0": "cryptroot"},
            mounts="/dev/mapper/cryptroot / ext4 rw 0 0\n",
            links={"/dev/mapper/cryptroot": "../dm-0"},
            slaves={"dm-0": ["sda2"]},
        )
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.root_encrypted is True
        assert snap.crypt_volumes == ["cryptroot"]

    def test_lvm_on_luks_root_is_true(self, monkeypatch):
        """The stack walk: root is a linear dm sitting on a crypt dm."""
        _fake_system(
            monkeypatch,
            sys_block=["dm-0", "dm-1", "sda"],
            uuids={"dm-0": "CRYPT-LUKS2-abcd-crypt",
                   "dm-1": "LVM-xxxx"},
            names={"dm-0": "crypt", "dm-1": "vg-root"},
            mounts="/dev/mapper/vg-root / ext4 rw 0 0\n",
            links={"/dev/mapper/vg-root": "../dm-1"},
            slaves={"dm-1": ["dm-0"], "dm-0": ["sda2"]},
        )
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.root_encrypted is True

    def test_lvm_without_luks_root_is_false(self, monkeypatch):
        """Plain LVM (no crypt anywhere in the stack) is not encrypted."""
        _fake_system(
            monkeypatch,
            sys_block=["dm-1", "sda"],
            uuids={"dm-1": "LVM-xxxx"},
            names={"dm-1": "vg-root"},
            mounts="/dev/mapper/vg-root / ext4 rw 0 0\n",
            links={"/dev/mapper/vg-root": "../dm-1"},
            slaves={"dm-1": ["sda2"]},
        )
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.root_encrypted is False

    def test_overlay_root_is_unknown(self, monkeypatch):
        """A container/overlay root cannot be judged — None, not False."""
        _fake_system(
            monkeypatch,
            sys_block=[], uuids={}, names={},
            mounts="overlay / overlay rw 0 0\n",
        )
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.root_encrypted is None

    def test_unreadable_mounts_is_not_readable(self, monkeypatch):
        def fake_read(path, **kw):
            raise OSError("denied")
        monkeypatch.setattr(os, "listdir", lambda p: [])
        monkeypatch.setattr(de, "read_text_capped", fake_read)
        monkeypatch.setattr(de, "path_exists", lambda p: False)
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.readable is False

    def test_crypt_volume_found_but_root_plain(self, monkeypatch):
        """A data disk is LUKS but root is plain — volumes seen, root False."""
        _fake_system(
            monkeypatch,
            sys_block=["dm-0", "sda"],
            uuids={"dm-0": "CRYPT-LUKS2-eeee-backup"},
            names={"dm-0": "backup"},
            mounts="/dev/sda2 / ext4 rw 0 0\n",
            slaves={"dm-0": ["sdb1"]},
        )
        snap = DiskEncryptionSnapshot.from_system()
        assert snap.root_encrypted is False
        assert snap.crypt_volumes == ["backup"]
