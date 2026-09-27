"""v0.22.0 — privileged /dev device-node permissions, INFO-only.

A narrow look at world access on the nodes that bypass filesystem permissions
(/dev/mem, /dev/kmem, /dev/port, raw block devices). Reported, never penalised:
the defaults are tight, so world access is almost always a mistake worth naming,
but occasionally deliberate. Only ever stats a node, never opens it, so a
hostile node cannot block the audit. One aggregated INFO, not one per node.
"""

from __future__ import annotations

import stat as _stat
from types import SimpleNamespace

import bob.checks.dev_privileged as dp
from bob.checks.dev_privileged import (
    DevPrivilegedSnapshot,
    check_dev_privileged,
)
from tests.helpers import _keys


def _key_levels(result):
    return {f.key: f.level.value for f in result.findings}


class TestDisposition:
    def test_world_accessible_nodes_are_listed(self):
        snap = DevPrivilegedSnapshot(
            too_open=[("/dev/mem", "readable"), ("/dev/sda", "writable")])
        r = check_dev_privileged(snap)
        assert _key_levels(r).get("dev_privileged.world_accessible") == "info"
        msg = next(f.message for f in r.findings
                   if f.key == "dev_privileged.world_accessible")
        assert "/dev/mem" in msg and "/dev/sda" in msg

    def test_no_world_access_is_ok(self):
        snap = DevPrivilegedSnapshot(too_open=[])
        r = check_dev_privileged(snap)
        assert _key_levels(r).get("dev_privileged.locked_down") == "ok"
        assert "dev_privileged.world_accessible" not in _keys(r)

    def test_unreadable_dev_is_info(self):
        snap = DevPrivilegedSnapshot(dev_read=False)
        r = check_dev_privileged(snap)
        assert "dev_privileged.unreadable" in _keys(r)

    def test_is_never_more_than_info(self):
        """INFO-only invariant: no WARN/ALERT, no deduction, ever."""
        for snap in (
            DevPrivilegedSnapshot(too_open=[("/dev/mem", "writable")]),
            DevPrivilegedSnapshot(too_open=[]),
            DevPrivilegedSnapshot(dev_read=False),
        ):
            r = check_dev_privileged(snap)
            assert not r.deductions
            assert all(f.level.value in ("ok", "info") for f in r.findings)


def _fake_stat(mode: int):
    return SimpleNamespace(st_mode=mode)


class TestFromSystem:
    def test_world_writable_block_device_flagged(self, monkeypatch):
        """The mutation guard: a world-writable raw disk must be flagged."""
        modes = {
            "/dev/sda": _stat.S_IFBLK | 0o622,   # world-writable, no world-read
            "/dev/mem": _stat.S_IFCHR | 0o640,   # root:kmem default, fine
        }

        def fake_stat(path):
            if path in modes:
                return _fake_stat(modes[path])
            raise FileNotFoundError(2, "no such node", path)

        monkeypatch.setattr(dp.os, "stat", fake_stat)
        monkeypatch.setattr(dp.os, "listdir", lambda p: ["sda", "loop0"])
        snap = DevPrivilegedSnapshot.from_system()
        assert ("/dev/sda", "writable") in snap.too_open
        assert ("/dev/mem", "readable") not in snap.too_open  # 0o640 = no world

    def test_world_readable_memory_device_flagged(self, monkeypatch):
        def fake_stat(path):
            if path == "/dev/mem":
                return _fake_stat(_stat.S_IFCHR | 0o644)   # world-readable
            raise FileNotFoundError(2, "no such node", path)

        monkeypatch.setattr(dp.os, "stat", fake_stat)
        monkeypatch.setattr(dp.os, "listdir", lambda p: [])
        snap = DevPrivilegedSnapshot.from_system()
        assert ("/dev/mem", "readable") in snap.too_open

    def test_regular_file_named_like_a_disk_is_ignored(self, monkeypatch):
        """A world-writable *regular* file called /dev/sdaX is not a device."""
        def fake_stat(path):
            if path == "/dev/sda_note":
                return _fake_stat(_stat.S_IFREG | 0o666)
            raise FileNotFoundError(2, "no such node", path)

        monkeypatch.setattr(dp.os, "stat", fake_stat)
        monkeypatch.setattr(dp.os, "listdir", lambda p: ["sda_note"])
        snap = DevPrivilegedSnapshot.from_system()
        assert snap.too_open == []

    def test_unlistable_dev_marks_unknown(self, monkeypatch):
        def boom(p):
            raise PermissionError(13, "denied")
        monkeypatch.setattr(dp.os, "stat",
                            lambda p: (_ for _ in ()).throw(FileNotFoundError()))
        monkeypatch.setattr(dp.os, "listdir", boom)
        snap = DevPrivilegedSnapshot.from_system()
        assert snap.dev_read is False

    def test_from_system_never_raises(self):
        DevPrivilegedSnapshot.from_system()
