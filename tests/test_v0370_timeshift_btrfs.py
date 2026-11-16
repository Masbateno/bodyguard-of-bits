"""v0.37.0 — Timeshift in BTRFS mode: its snapshots listed, not mounted.

Until 0.37.0 BTRFS mode was said and not read — and with a schedule on, BOB
counted Timeshift as an active backup whatever the snapshots were: none at all,
or one months old. Measured on a Fedora 43 VM whose subvolumes were renamed to
Timeshift's layout (@, @home), Timeshift 25.12.4, configuration as its window
writes it (btrfs_mode, backup_device_uuid, schedule_daily) (a10370, 14 November
2026): `timeshift --create` made the subvolume
<FS_TREE>/timeshift-btrfs/snapshots/2026-11-14_11-25-10/@ and left nothing
mounted; the root is mounted as subvol=/@, so the device is mounted, but not
with its own root — `btrfs subvolume list -a /` lists the snapshots, read-only.
"""

from __future__ import annotations

import json

import pytest

from bob.checks import backup as b

_UUID = "55773572-92c8-4d7e-bafd-3f4943a2f380"
_LIST = """ID 256 gen 29 top level 5 path <FS_TREE>/@
ID 257 gen 27 top level 5 path <FS_TREE>/@home
ID 258 gen 29 top level 5 path <FS_TREE>/var
ID 259 gen 29 top level 5 path <FS_TREE>/timeshift-btrfs/snapshots/2026-11-14_11-25-10/@
ID 260 gen 31 top level 5 path <FS_TREE>/timeshift-btrfs/snapshots/2026-11-15_11-00-01/@
ID 261 gen 31 top level 5 path <FS_TREE>/timeshift-btrfs/snapshots/2026-11-15_11-00-01/@home
ID 262 gen 31 top level 5 path <FS_TREE>/timeshift-btrfs/snapshots/not-a-date/@
"""


@pytest.fixture
def vm(tmp_path, monkeypatch):
    dev = tmp_path / "vda4"
    dev.write_text("")
    byuuid = tmp_path / "by-uuid"
    byuuid.mkdir()
    (byuuid / _UUID).symlink_to(dev)
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"30 1 0:35 /@ / rw,relatime shared:1 - btrfs {dev} rw,subvol=/@\n")
    cfg = tmp_path / "timeshift.json"
    cfg.write_text(json.dumps({"btrfs_mode": "true", "backup_device_uuid": _UUID, "schedule_daily": "true"}))
    monkeypatch.setattr(b, "_DISK_BY_UUID", byuuid)
    monkeypatch.setattr(b, "_MOUNTINFO", mountinfo)
    monkeypatch.setattr(b, "_TIMESHIFT_CONFIG", cfg)
    monkeypatch.setattr(b, "_command_exists", lambda name: True)
    calls = []

    class R:
        def __init__(self, ok, stdout):
            self.ok, self.stdout = ok, stdout

    def run(*args, timeout=None):
        calls.append(args)
        return R(True, _LIST)
    monkeypatch.setattr(b, "run_result", run)
    return dev, calls, monkeypatch, R


def test_the_snapshots_are_the_subvolumes_btrfs_lists(vm):
    dev, calls, _mp, _R = vm
    sched, snaps, why, where = b._read_timeshift()
    assert (sched, snaps, why) == (["daily"], ["2026-11-14_11-25-10", "2026-11-15_11-00-01"], "")
    assert where == f"{dev}: timeshift-btrfs/snapshots"
    assert calls == [("btrfs", "subvolume", "list", "-a", "/")]


def test_a_failed_listing_stays_unread(vm):
    _dev, _calls, mp, R = vm
    mp.setattr(b, "run_result", lambda *a, timeout=None: R(False, ""))
    assert b._read_timeshift()[1:3] == (None, "btrfs")


def test_no_snapshot_in_btrfs_mode_is_said():
    snap = b.BackupSnapshot(installed_tools=["timeshift"], timeshift_schedules=["daily"], timeshift_snapshots=[], timeshift_btrfs=True,
                            timeshift_dir="/dev/vda4: timeshift-btrfs/snapshots")
    r = b.check_backup(snap, t=lambda k, **v: f"{k} {v}")
    f = next(f for f in r.findings if f.key == "backup.timeshift_none")
    assert "'mode': 'BTRFS'" in f.message


def test_the_mode_is_named_when_read():
    snap = b.BackupSnapshot(active_tools=["timeshift"], timeshift_schedules=["daily"], timeshift_snapshots=["2026-11-14_11-25-10"],
                            timeshift_btrfs=True, timeshift_dir="/dev/vda4: timeshift-btrfs/snapshots")
    r = b.check_backup(snap, t=lambda k, **v: f"{k} {v}")
    f = next(f for f in r.findings if f.key == "backup.timeshift_snapshots")
    assert "'mode': 'BTRFS'" in f.message


def test_from_system_reads_them_and_counts_none_as_not_active(vm):
    _dev, _calls, mp, R = vm
    mp.setattr(b, "_command_exists", lambda name: name in ("timeshift", "btrfs"))
    # v0.38.0 — "now" pinned an hour after the newest measured snapshot. The
    # test read the real clock: from 17 November 2026 the snapshot was over
    # 48 h old and Timeshift was (rightly) no longer counted active — a test
    # that could pass for two days only.
    from datetime import datetime
    _stale = b._timeshift_stale
    mp.setattr(b, "_timeshift_stale", lambda sched, snaps, now: _stale(sched, snaps, datetime(2026, 11, 15, 12, 0)))
    snap = b.BackupSnapshot.from_system()
    assert snap.timeshift_btrfs is True and snap.timeshift_snapshots == ["2026-11-14_11-25-10", "2026-11-15_11-00-01"]
    assert "timeshift" in snap.active_tools
    mp.setattr(b, "run_result", lambda *a, timeout=None: R(True, "ID 256 gen 29 top level 5 path <FS_TREE>/@\n"))
    snap = b.BackupSnapshot.from_system()
    assert snap.timeshift_snapshots == [] and "timeshift" not in snap.active_tools
