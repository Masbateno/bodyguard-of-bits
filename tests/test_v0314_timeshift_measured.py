"""v0.31.4 — Timeshift is "active" on what its own files say, not on their existence.

`backup.active` named Timeshift as soon as the binary and
/etc/timeshift/timeshift.json were both there. That file holds the schedules
and the backup device; it exists with every schedule off, and with a device
that holds no snapshot. Measured on Linux Mint 22.3 (timeshift 25.12.4, read
without root, 9 November 2026): schedule_weekly true, backup_device_uuid = the
partition mounted at /home, /home/timeshift/snapshots holding
2026-11-01_19-00-01 and 2026-11-08_19-00-02, /etc/cron.d/timeshift-hourly
running `timeshift --check --scripted`.

Now: active takes a schedule that is on, and no readable snapshot directory
that is empty. The snapshots are read in rsync mode when the backup device is
already mounted; BOB runs nothing and mounts nothing, and says why when it did
not read them. No score moves: "active" is OK and "installed only" is INFO,
both 0 points.
"""

from __future__ import annotations

import json
import os

import pytest

from bob import i18n
from bob.checks import backup as b
from tests.helpers import _t

_UUID = "0a1b2c3d-0000-4000-8000-000000000001"


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A device, its by-uuid link, a mount of it, and a timeshift.json."""
    dev = tmp_path / "dev" / "sdz1"
    dev.parent.mkdir()
    dev.write_text("")
    byuuid = tmp_path / "by-uuid"
    byuuid.mkdir()
    (byuuid / _UUID).symlink_to(dev)
    mnt = tmp_path / "mnt point"
    snaps = mnt / "timeshift" / "snapshots"
    snaps.mkdir(parents=True)
    mountinfo = tmp_path / "mountinfo"
    cfg = tmp_path / "timeshift.json"
    monkeypatch.setattr(b, "_DISK_BY_UUID", byuuid)
    monkeypatch.setattr(b, "_MOUNTINFO", mountinfo)
    monkeypatch.setattr(b, "_TIMESHIFT_CONFIG", cfg)

    class Host:
        pass
    h = Host()
    h.dev, h.mnt, h.snaps, h.cfg, h.mountinfo = dev, mnt, snaps, cfg, mountinfo

    def mount(root="/", where=None):
        where = str(where or mnt).replace(" ", "\\040")
        mountinfo.write_text(f"30 1 259:2 / / rw - ext4 /dev/nvme1n1p2 rw\n"
                             f"36 25 259:1 {root} {where} rw,relatime shared:1 - ext4 {dev} rw\n")

    def config(**values):
        base = {"backup_device_uuid": _UUID, "btrfs_mode": "false",
                **{f"schedule_{n}": "false" for n in b._TIMESHIFT_SCHEDULES}}
        cfg.write_text(json.dumps({**base, **values}))

    h.mount, h.config = mount, config
    return h


class TestWhatItReads:
    def test_the_mint_as_measured(self, host):
        host.config(schedule_weekly="true")
        host.mount()
        for name in ("2026-11-08_19-00-02", "2026-11-01_19-00-01", "not-a-snapshot"):
            (host.snaps / name).mkdir()
        (host.snaps / "2026-11-09_00-00-00").symlink_to(host.snaps / "2026-11-01_19-00-01")
        assert b._read_timeshift() == (["weekly"], ["2026-11-01_19-00-01", "2026-11-08_19-00-02"],
                                       "", os.path.join(str(host.mnt), "timeshift", "snapshots"))

    def test_every_schedule_off(self, host):
        host.config()
        host.mount()
        assert b._read_timeshift()[0] == []

    def test_an_empty_snapshot_directory_is_read_as_empty(self, host):
        host.config(schedule_daily="true", schedule_boot="true")
        host.mount()
        assert b._read_timeshift()[:3] == (["daily", "boot"], [], "")

    def test_a_device_timeshift_never_wrote_to_holds_no_snapshot(self, host):
        """Measured on Ubuntu: the directory appears with the first snapshot."""
        host.config(schedule_daily="true")
        host.snaps.rmdir()
        host.mount()
        assert b._read_timeshift()[1:3] == ([], "")

    def test_a_directory_that_cannot_be_listed_is_unread(self, host, monkeypatch):
        host.config(schedule_daily="true")
        host.mount()

        def denied(path):
            raise PermissionError(13, "Permission denied", path)
        monkeypatch.setattr(b.os, "scandir", denied)
        assert b._read_timeshift()[1:3] == (None, "unreadable")

    def test_btrfs_mode(self, host):
        host.config(schedule_daily="true", btrfs_mode="true")
        host.mount()
        assert b._read_timeshift()[1:3] == (None, "btrfs")

    def test_no_device_set(self, host):
        host.config(schedule_daily="true", backup_device_uuid="")
        assert b._read_timeshift()[1:3] == (None, "no_device")

    def test_a_device_that_is_not_there(self, host):
        host.config(schedule_daily="true", backup_device_uuid="ffffffff-0000-4000-8000-000000000009")
        assert b._read_timeshift()[1:] == (None, "device_absent", "ffffffff-0000-4000-8000-000000000009")

    def test_a_device_that_is_not_mounted(self, host):
        host.config(schedule_daily="true")
        host.mountinfo.write_text("30 1 259:2 / / rw - ext4 /dev/nvme1n1p2 rw\n")
        assert b._read_timeshift()[1:] == (None, "not_mounted", str(host.dev))

    def test_a_bind_mount_of_a_subdirectory_is_not_the_device_root(self, host):
        host.config(schedule_daily="true")
        host.mount(root="/srv")
        assert b._read_timeshift()[2] == "not_mounted"

    def test_a_config_that_is_not_json(self, host):
        host.cfg.write_text("{ not json")
        assert b._read_timeshift() == (None, None, "config", "")


class TestTheVerdict:
    @pytest.fixture
    def only_timeshift(self, monkeypatch, host):
        monkeypatch.setattr(b, "_command_exists", lambda name: name == "timeshift")
        host.cfg.write_text("{}")

    @pytest.mark.parametrize("read, active", [
        ((["weekly"], ["2026-11-08_19-00-02"], "", "/x"), True),
        ((["weekly"], None, "not_mounted", "/dev/sdz1"), True),
        ((["weekly"], [], "", "/x"), False),
        (([], ["2026-11-08_19-00-02"], "", "/x"), False),
        ((None, None, "config", ""), False),
    ], ids=["snapshots", "unread", "scheduled-none-there", "no-schedule", "config-unread"])
    def test_active_or_installed(self, monkeypatch, only_timeshift, read, active):
        monkeypatch.setattr(b, "_read_timeshift", lambda: read)
        snap = b.BackupSnapshot.from_system()
        assert ("timeshift" in snap.active_tools) is active
        assert ("timeshift" in snap.installed_tools) is not active

    def test_no_config_reads_nothing(self, monkeypatch, host):
        monkeypatch.setattr(b, "_command_exists", lambda name: name == "timeshift")
        monkeypatch.setattr(b, "_read_timeshift", lambda: pytest.fail("read without a config"))
        assert b.BackupSnapshot.from_system().installed_tools == ["timeshift"]


def _keys(snap):
    return {f.key: f for f in b.check_backup(snap, t=_t).findings}


class TestWhatItSays:
    def test_snapshots_counted(self):
        snap = b.BackupSnapshot(active_tools=["timeshift"], timeshift_schedules=["weekly"],
                                timeshift_snapshots=["a", "b"], timeshift_dir="/home/timeshift/snapshots")
        assert "backup.timeshift_snapshots" in _keys(snap)

    def test_none_there(self):
        snap = b.BackupSnapshot(installed_tools=["timeshift"], timeshift_schedules=["weekly"],
                                timeshift_snapshots=[], timeshift_dir="/x")
        keys = _keys(snap)
        assert "backup.timeshift_none" in keys and "backup.installed_only" in keys

    def test_unread_says_why(self):
        snap = b.BackupSnapshot(active_tools=["timeshift"], timeshift_schedules=["weekly"],
                                timeshift_unread="not_mounted", timeshift_dir="/dev/sdz1")
        assert "backup.timeshift_unread" in _keys(snap)

    def test_config_unread_says_nothing_of_timeshift(self):
        snap = b.BackupSnapshot(installed_tools=["timeshift"])
        assert not [k for k in _keys(snap) if k.startswith("backup.timeshift")]


@pytest.mark.parametrize("lang, snapshot_line, unread_line, none_line", [
    ("en", "Timeshift (rsync): 2 snapshot(s) in /home/timeshift/snapshots, the newest 2026-11-08_19-00-02 — schedule: weekly",
     "the backup device /dev/sdz1 is not mounted, and BOB mounts nothing",
     "Timeshift (rsync): no snapshot in /x — schedule: none (snapshots only by hand)"),
    ("fr", "Timeshift (rsync) : 2 instantané(s) dans /home/timeshift/snapshots, le plus récent 2026-11-08_19-00-02 — planification : hebdomadaire",
     "le périphérique de sauvegarde /dev/sdz1 n'est pas monté, et BOB ne monte rien",
     "Timeshift (rsync) : aucun instantané dans /x — planification : aucune (instantanés seulement à la main)"),
], ids=["en", "fr"])
def test_the_rendered_lines(lang, snapshot_line, unread_line, none_line):
    i18n.init(lang)
    try:
        def msgs(**kw):
            return [f.message for f in b.check_backup(b.BackupSnapshot(**kw), t=i18n.t).findings]
        seen = msgs(active_tools=["timeshift"], timeshift_schedules=["weekly"],
                    timeshift_snapshots=["2026-11-01_19-00-01", "2026-11-08_19-00-02"],
                    timeshift_dir="/home/timeshift/snapshots")
        unread = msgs(active_tools=["timeshift"], timeshift_schedules=["weekly"],
                      timeshift_unread="not_mounted", timeshift_dir="/dev/sdz1")
        none = msgs(installed_tools=["timeshift"], timeshift_schedules=[],
                    timeshift_snapshots=[], timeshift_dir="/x")
    finally:
        i18n.init(lang="en")
    assert snapshot_line in seen
    assert any(unread_line in m for m in unread)
    assert none_line in none
