"""
v0.15.0 — the disk audit skipped ZFS roots entirely, and truncated mount points
containing a space.

Checked against `os.statvfs`, the syscall `df` itself calls, BOB's percentages
were exact on every partition of this host. The defects were both in *which*
lines it kept and *how much* of each line it read.

**ZFS.** The filter was `device.startswith("/dev/")`, under a comment claiming
it captured the pseudo-filesystem list. It over-captured: a ZFS dataset is named
`rpool/ROOT/pve-1`, not `/dev/…`. On any ZFS-root host — Proxmox by default,
Ubuntu as an installer option — the root filesystem was dropped, so a pool at
93% produced no finding at all. The filter now works on the filesystem *type*,
which is what the docstring always claimed.

**Spaces.** `df` prints mount points unescaped, and `line.split()[5]` takes one
word of them. A drive mounted at `/media/so6/My Passport` was reported as
`/media/so6/My` — a path that does not exist, in a finding telling the operator
it is 95% full.
"""

from __future__ import annotations

import os

import pytest

import bob.checks.disk as d
from bob.checks.disk import _read_partition_usage

_HEADER = "Filesystem     Type     1G-blocks  Used Available Use% Mounted on\n"


@pytest.fixture
def df(monkeypatch):
    def _set(body: str):
        monkeypatch.setattr(d, "_run", lambda *a, **k: _HEADER + body)
        return {p.mountpoint: p for p in _read_partition_usage()}
    return _set


class TestRealFilesystemsAreKept:
    def test_a_zfs_root_is_audited(self, df):
        parts = df("rpool/ROOT/pve-1 zfs   100    93         7  93% /\n")
        assert "/" in parts, "a ZFS root filesystem was dropped from the audit"
        assert parts["/"].used_pct == 93

    @pytest.mark.parametrize("fstype", ["ext4", "xfs", "btrfs", "zfs", "f2fs",
                                        "vfat", "exfat", "ntfs3", "bcachefs"])
    def test_every_real_local_type_is_kept(self, df, fstype):
        """A deny-list is used precisely so a filesystem type nobody thought of
        is still audited — the allow-list is what failed here."""
        parts = df(f"somedev {fstype}   100    90        10  90% /data\n")
        assert "/data" in parts

    def test_a_device_mapper_path_is_kept(self, df):
        parts = df("/dev/mapper/vg-root ext4  100  50  50  50% /\n")
        assert "/" in parts


class TestPseudoAndNetworkAreSkipped:
    @pytest.mark.parametrize("fstype", ["tmpfs", "devtmpfs", "overlay",
                                        "squashfs", "proc", "sysfs",
                                        "efivarfs", "cgroup2"])
    def test_pseudo_filesystems_are_skipped(self, df, fstype):
        assert df(f"none {fstype}  8  0  8  0% /somewhere\n") == {}

    @pytest.mark.parametrize("fstype", ["nfs", "nfs4", "cifs", "ceph", "9p"])
    def test_network_filesystems_are_skipped(self, df, fstype):
        """Deliberate, not an omission: a full NFS share is a real problem, but
        it is not this host's disk."""
        assert df(f"srv:/export {fstype}  1000  990  10  99% /mnt/nas\n") == {}

    def test_a_fuse_mounted_appimage_is_skipped(self, df):
        body = "none fuse.kDrive-3.8.2.6-amd64.AppImage  1  1  1  100% /tmp/.mount_x\n"
        assert df(body) == {}


class TestMountPointsWithSpaces:
    def test_the_whole_path_is_kept(self, df):
        parts = df("/dev/sdb1 ext4  500  475  25  95% /media/so6/My Passport\n")
        assert "/media/so6/My Passport" in parts
        assert "/media/so6/My" not in parts

    def test_several_spaces_survive(self, df):
        parts = df("/dev/sdc1 ext4  10  5  5  50% /media/so6/Sauvegarde Disque Externe\n")
        assert "/media/so6/Sauvegarde Disque Externe" in parts

    def test_an_ordinary_path_is_unchanged(self, df):
        parts = df("/dev/sda1 ext4  100  50  50  50% /home\n")
        assert list(parts) == ["/home"]


class TestAgainstTheKernel:
    def test_every_reported_mount_point_actually_exists(self):
        """The live check the space defect would fail: a truncated path does not
        stat. Percentages are compared against statvfs, which is what `df`
        calls."""
        for part in _read_partition_usage():
            st = os.statvfs(part.mountpoint)
            used = (st.f_blocks - st.f_bfree) * st.f_frsize
            avail = st.f_bavail * st.f_frsize
            real = round(100 * used / (used + avail)) if (used + avail) else 0
            assert abs(real - part.used_pct) <= 1, \
                f"{part.mountpoint}: df says {part.used_pct}%, statvfs says {real}%"
