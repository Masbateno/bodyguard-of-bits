"""World-writable / unowned sweep (--exhaustive, INFO-only).

The guard pins:

  1. only local on-disk filesystems are swept — proc, sysfs, tmpfs (/tmp and
     /dev/shm are world-writable by design), overlay, squashfs, network and
     FUSE filesystems are not;
  2. a world-writable *sticky* directory (/tmp's shape) is not reported, one
     without the sticky bit is; container storage is pruned;
  3. BusyBox find (no -printf / -nouser) still sweeps, and says the unowned
     part was not assessed instead of reporting none;
  4. nothing deducts; a partial sweep, an unassessed part, a timeout or no
     find at all withholds the OK;
  5. the sweep is killed at its ceiling rather than hanging the audit.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

import bob.checks.world_writable as ww
from bob.checks.world_writable import (
    WorldWritableSnapshot,
    build_command,
    check_world_writable,
)
from tests.helpers import _t


def _keys(r):
    return [f.key for f in r.findings]


# ---- mount selection --------------------------------------------------------------

def test_only_local_disk_filesystems_are_roots(tmp_path, monkeypatch):
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "/dev/sda1 / ext4 rw 0 0\n"
        "proc /proc proc rw 0 0\n"
        "tmpfs /tmp tmpfs rw 0 0\n"
        "/dev/sda2 /home xfs rw 0 0\n"
        "srv:/x /mnt/nfs nfs4 rw 0 0\n"
        "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n"
        "/dev/loop0 /snap/core/1 squashfs ro 0 0\n"
        "h:/ /mnt/s fuse.sshfs rw 0 0\n"
        "/dev/sda3 /mnt/my\\040disk btrfs rw 0 0\n"
        "/dev/sda1 /boot/efi vfat rw 0 0\n")
    monkeypatch.setattr(ww, "_MOUNTS", mounts)
    assert ww._local_roots() == ["/", "/home", "/mnt/my disk", "/boot/efi"]


def test_unreadable_mount_table_falls_back_to_root(tmp_path, monkeypatch):
    monkeypatch.setattr(ww, "_MOUNTS", tmp_path / "absent")
    assert ww._local_roots() == ["/"]


# ---- the real find --------------------------------------------------------------

@pytest.fixture
def local_parents(tmp_path, monkeypatch):
    """Judge traversal only inside tmp_path: pytest's own base directory is 0700."""
    real = ww._traversable
    monkeypatch.setattr(ww, "_traversable",
                        lambda d: real(d) if d.startswith(str(tmp_path)) else True)


def _tree(tmp_path):
    tmp_path.chmod(0o755)       # pytest creates it 0700: others could not reach anything
    (tmp_path / "ww_file").write_text("x")
    os.chmod(tmp_path / "ww_file", 0o666)
    (tmp_path / "ok_file").write_text("x")
    (tmp_path / "ww_dir").mkdir()
    os.chmod(tmp_path / "ww_dir", 0o777)
    (tmp_path / "sticky").mkdir()
    os.chmod(tmp_path / "sticky", 0o1777)
    c = tmp_path / "u" / ".local" / "share" / "containers"
    c.mkdir(parents=True)
    (c / "layer_tmp").write_text("x")
    os.chmod(c / "layer_tmp", 0o666)
    return tmp_path


def _gnu(find):
    r = subprocess.run([find, "--version"], capture_output=True, text=True)
    return r.returncode == 0 and "GNU" in r.stdout


@pytest.mark.skipif(not shutil.which("find") or not _gnu(shutil.which("find")),
                    reason="needs GNU find")
@pytest.mark.parametrize("gnu", [True, False])
def test_sweep_finds_the_right_things(tmp_path, monkeypatch, gnu, local_parents):
    root = _tree(tmp_path)
    monkeypatch.setattr(ww, "_local_roots", lambda: [str(root)])
    monkeypatch.setattr(ww, "_is_gnu_find", lambda f: gnu)   # False = the BusyBox path
    snap = WorldWritableSnapshot.from_system()
    assert snap.ww_files == [str(root / "ww_file")]
    assert snap.ww_dirs == [str(root / "ww_dir")]
    assert snap.unowned_assessed is gnu


def test_busybox_command_uses_no_gnu_only_primary():
    cmd = build_command("find", ["/"], gnu=False)
    assert "-printf" not in cmd and "-nouser" not in cmd and "-nogroup" not in cmd
    assert "-xdev" in cmd and "-prune" in cmd


def test_gnu_command_sweeps_unowned():
    cmd = build_command("find", ["/", "/home"], gnu=True)
    assert "-nouser" in cmd and "-nogroup" in cmd
    assert cmd[1:3] == ["/", "/home"]


def test_parse_gnu_tags():
    s = WorldWritableSnapshot()
    s._parse(b"F /a b\0D /d\0U /u\0", gnu=True)
    assert (s.ww_files, s.ww_dirs, s.unowned) == (["/a b"], ["/d"], ["/u"])


def test_sweep_is_killed_at_its_ceiling(monkeypatch):
    monkeypatch.setattr(ww, "build_command", lambda *a: ["sh", "-c", "sleep 30"])
    monkeypatch.setattr(ww, "_TIMEOUT", 1)
    monkeypatch.setattr(ww, "_is_gnu_find", lambda f: True)
    snap = WorldWritableSnapshot.from_system()
    assert snap.timed_out


# ---- verdicts -----------------------------------------------------------------------

def test_findings_are_info_only():
    r = check_world_writable(WorldWritableSnapshot(ww_files=["/a"], ww_dirs=["/d"],
                                                   unowned=["/u"]), t=_t)
    assert {"world_writable.files", "world_writable.dirs", "world_writable.unowned"} <= set(_keys(r))
    assert r.deductions == []
    assert "world_writable.ok" not in _keys(r)


@pytest.mark.parametrize("kw,key", [
    (dict(partial=True), "world_writable.partial"),
    (dict(unowned_assessed=False), "world_writable.unowned_not_assessed"),
    (dict(timed_out=True), "world_writable.timed_out"),
    (dict(no_find=True), "world_writable.unknown"),
])
def test_incomplete_sweep_withholds_ok(kw, key):
    r = check_world_writable(WorldWritableSnapshot(**kw), t=_t)
    assert key in _keys(r)
    assert "world_writable.ok" not in _keys(r)


def test_clean_complete_sweep_is_ok():
    assert _keys(check_world_writable(WorldWritableSnapshot(), t=_t)) == ["world_writable.ok"]


# ---- reachability (v0.24.0 critique fix) ---------------------------------------

def test_path_behind_untraversable_parent_is_latent(tmp_path, local_parents):
    home = tmp_path / "home"
    home.mkdir()
    home.chmod(0o750)                       # others may not traverse
    f = home / "conf"
    f.write_text("x")
    f.chmod(0o666)
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    open_dir.chmod(0o755)
    g = open_dir / "conf"
    g.write_text("x")
    g.chmod(0o666)
    tmp_path.chmod(0o755)
    s = WorldWritableSnapshot(ww_files=[str(f), str(g)])
    s._split_unreachable()
    assert s.ww_files == [str(g)]
    assert s.latent == [str(f)]


def test_unknown_parent_is_never_claimed_shut():
    s = WorldWritableSnapshot(ww_dirs=["/nonexistent-bob-parent/d"])
    s._split_unreachable()
    assert s.ww_dirs == ["/nonexistent-bob-parent/d"] and s.latent == []


def test_latent_is_info_and_withholds_ok():
    r = check_world_writable(WorldWritableSnapshot(latent=["/home/a/x"]), t=_t)
    assert "world_writable.latent" in _keys(r)
    assert "world_writable.ok" not in _keys(r)
    assert r.deductions == []
