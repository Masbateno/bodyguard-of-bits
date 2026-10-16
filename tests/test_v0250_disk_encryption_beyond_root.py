"""v0.25.0 — the data beside an encrypted root: other filesystems and swap.

Until v0.25.0 BOB said "Root filesystem is on an encrypted volume" and stopped.
A separate /home on a plain partition, a data disk added later, or a swap
partition left in clear kept their contents readable to whoever held the disk —
for /home, the users' files; for swap, whatever was in memory, passphrases
included — and the report read as an encrypted machine.
"""

from __future__ import annotations

import pytest

import bob.checks.disk_encryption as de
from bob.checks.disk_encryption import DiskEncryptionSnapshot, check_disk_encryption
from bob.scoring import FindingLevel
from tests.helpers import _get_finding, _keys
from tests.test_v0210_disk_encryption import _fake_system

_HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"

#: LVM-on-LUKS root (vg-root on crypt dm-0 on vda2), as on the bench.
_LUKS_ROOT = dict(
    sys_block=["dm-0", "dm-1", "vda"],
    uuids={"dm-0": "CRYPT-LUKS2-abcd-crypt", "dm-1": "LVM-xxxx"},
    names={"dm-0": "crypt", "dm-1": "vg-root"},
    links={"/dev/mapper/vg-root": "../dm-1"},
    slaves={"dm-1": ["dm-0"], "dm-0": ["vda2"]},
)


def _system(monkeypatch, mounts, swaps="", **layout):
    _fake_system(monkeypatch, mounts=mounts, **{**_LUKS_ROOT, **layout})
    inner = de.read_text_capped

    def read(path, **kw):
        if str(path) == de._SWAPS:
            if swaps is None:
                raise OSError("unreadable")
            return _HEADER + swaps
        return inner(path, **kw)
    monkeypatch.setattr(de, "read_text_capped", read)
    return DiskEncryptionSnapshot.from_system()


_ROOT = "/dev/mapper/vg-root / ext4 rw 0 0\n"


class TestWhatIsLookedAt:
    def test_a_plain_home_and_a_plain_swap(self, monkeypatch):
        snap = _system(monkeypatch, _ROOT + "/dev/vdb1 /home ext4 rw 0 0\n",
                       swaps="/dev/vdc1                               partition\t1048572\t\t0\t\t-2\n")
        assert snap.root_encrypted is True
        assert snap.extra_volumes == [("/home", "/dev/vdb1", False), ("swap", "/dev/vdc1", False)]

    def test_what_is_not_data_at_rest_on_this_disk(self, monkeypatch):
        snap = _system(monkeypatch, _ROOT
                       + "/dev/vda1 /boot ext4 rw 0 0\n"
                       + "/dev/vda1 /boot/efi vfat rw 0 0\n"
                       + "/dev/loop3 /snap/core22/1 squashfs ro 0 0\n"
                       + "/dev/sdb1 /run/media/so6/KEY vfat rw 0 0\n"
                       + "tmpfs /tmp tmpfs rw 0 0\n"
                       + "server:/export /srv/nfs nfs4 rw 0 0\n"
                       + "/dev/mapper/vg-root /var/lib/containers ext4 rw 0 0\n",
                       swaps="/dev/zram0                              partition\t8388604\t\t0\t\t100\n")
        assert snap.extra_volumes == []

    def test_a_bind_mount_is_one_volume(self, monkeypatch):
        snap = _system(monkeypatch, _ROOT + "/dev/vdb1 /home ext4 rw 0 0\n"
                       "/dev/vdb1 /var/lib/flatpak-home ext4 rw 0 0\n")
        assert [v[0] for v in snap.extra_volumes] == ["/home"]

    def test_a_swap_file_is_judged_by_its_filesystem(self, monkeypatch):
        snap = _system(monkeypatch, _ROOT + "/dev/vdb1 /data ext4 rw 0 0\n",
                       swaps="/swapfile                               file\t\t1048572\t\t0\t\t-2\n"
                             "/data/swap\\040file                       file\t\t1048572\t\t0\t\t-3\n")
        assert ("swap", "/swapfile", True) in snap.extra_volumes
        assert ("swap", "/data/swap file", False) in snap.extra_volumes

    def test_an_encrypted_home(self, monkeypatch):
        snap = _system(monkeypatch, _ROOT + "/dev/mapper/home /home ext4 rw 0 0\n",
                       sys_block=["dm-0", "dm-1", "dm-2", "vda"],
                       uuids={**_LUKS_ROOT["uuids"], "dm-2": "CRYPT-LUKS2-ef01-home"},
                       names={**_LUKS_ROOT["names"], "dm-2": "home"},
                       links={**_LUKS_ROOT["links"], "/dev/mapper/home": "../dm-2"})
        assert snap.extra_volumes == [("/home", "/dev/mapper/home", True)]

    def test_unreadable_swaps_add_nothing(self, monkeypatch):
        assert _system(monkeypatch, _ROOT, swaps=None).extra_volumes == []


class TestVerdict:
    def _snap(self, *extra):
        return DiskEncryptionSnapshot(readable=True, root_encrypted=True, extra_volumes=list(extra))

    def test_a_portable_host_with_data_in_clear(self):
        r = check_disk_encryption(self._snap(("/home", "/dev/vdb1", False), ("swap", "/dev/vdc1", False)),
                                  profile_name="desktop")
        f = _get_finding(r, "disk_encryption.data_unencrypted")
        assert f.level == FindingLevel.WARN
        assert f.template_vars == {"volumes": "/home (/dev/vdb1), swap (/dev/vdc1)"}
        assert [d.points for d in r.deductions] == [1]
        assert _get_finding(r, "disk_encryption.root_encrypted").level == FindingLevel.OK

    def test_a_server_is_told_not_scored(self):
        r = check_disk_encryption(self._snap(("/srv", "/dev/sdb1", False)), profile_name="server")
        assert _get_finding(r, "disk_encryption.data_unencrypted_server").level == FindingLevel.INFO
        assert not r.deductions

    def test_everything_encrypted(self):
        r = check_disk_encryption(self._snap(("/home", "/dev/mapper/home", True)), profile_name="desktop")
        assert _keys(r) == ["disk_encryption.root_encrypted"]

    def test_undecided_is_said(self):
        r = check_disk_encryption(self._snap(("/data", "/dev/md0", None)), profile_name="desktop")
        assert _get_finding(r, "disk_encryption.data_unknown").level == FindingLevel.INFO
        assert not r.deductions

    def test_undecided_counts_as_reduced_visibility(self):
        from bob.visibility import VISIBILITY_KEYS
        assert "disk_encryption.data_unknown" in VISIBILITY_KEYS

    def test_a_plain_root_keeps_its_own_finding(self):
        """The root finding already says the disk is in clear; no second one."""
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=False,
                                      extra_volumes=[("/home", "/dev/vdb1", False)])
        r = check_disk_encryption(snap, profile_name="desktop")
        assert _keys(r) == ["disk_encryption.root_unencrypted"]



class TestInsideAContainer:
    """Measured in python:3.14-slim under podman, default (server) profile: the
    overlay root read as "Root device could not be resolved"."""

    def test_detected_container_is_not_applicable(self):
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=None, in_container="podman")
        r = check_disk_encryption(snap, profile_name="server")
        assert _keys(r) == ["disk_encryption.container_na"]

    def test_the_snapshot_asks(self, monkeypatch):
        monkeypatch.setattr(de, "_detect_container", lambda: "docker")
        monkeypatch.setattr(de, "read_text_capped", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        monkeypatch.setattr(de.os, "listdir", lambda p: [])
        assert DiskEncryptionSnapshot.from_system().in_container == "docker"

@pytest.mark.parametrize("lang, needle", [("en", "other data on this host is not"),
                                          ("fr", "d'autres données de cet hôte ne le sont pas")])
def test_the_rendered_message(lang, needle):
    from bob import i18n
    i18n.init(lang)
    try:
        snap = DiskEncryptionSnapshot(readable=True, root_encrypted=True,
                                      extra_volumes=[("swap", "/dev/vdc1", False)])
        msg = _get_finding(check_disk_encryption(snap, t=i18n.t, profile_name="desktop"),
                           "disk_encryption.data_unencrypted").message
    finally:
        i18n.init(lang="en")
    assert needle in msg and "swap (/dev/vdc1)" in msg
