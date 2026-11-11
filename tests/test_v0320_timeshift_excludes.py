"""v0.32.0 — Timeshift's exclude patterns are said with its snapshots.

"Backup solution active: timeshift" read as "my files are backed up" while
timeshift.json excluded the home: measured on Linux Mint 22.3 (review of a
real 0.31.3 audit), `exclude` held the home, /var/lib/libvirt/** and
/root/** — no snapshot holds what these match. The Timeshift line now carries
them in its detail, in all three branches (snapshots counted, none, unread).
"""

from __future__ import annotations

import json

import pytest

from bob import i18n
from bob.checks import backup as b
from tests.helpers import _t

_EXCL = ["/home/alice/**", "/root/**"]


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "timeshift.json"
    monkeypatch.setattr(b, "_TIMESHIFT_CONFIG", path)

    def write(payload):
        path.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)
        return b._timeshift_excludes()
    return write


class TestWhatItReads:
    def test_the_mint_as_measured(self, cfg):
        assert cfg({"exclude": _EXCL}) == _EXCL

    @pytest.mark.parametrize("payload", [{}, {"exclude": "no"}, {"exclude": [1, ""]}, "{bad", {"exclude": None}],
                             ids=["absent", "not-a-list", "not-strings", "not-json", "null"])
    def test_anything_else_is_empty(self, cfg, payload):
        assert cfg(payload) == []


def _keys_details(**kw):
    snap = b.BackupSnapshot(active_tools=["timeshift"], **kw)
    return {f.key: f.detail for f in b.check_backup(snap, t=_t).findings}


class TestItIsSaid:
    @pytest.mark.parametrize("kw, key", [
        (dict(timeshift_schedules=["weekly"], timeshift_snapshots=["2026-11-08_19-00-02"], timeshift_dir="/d"),
         "backup.timeshift_snapshots"),
        (dict(timeshift_schedules=["weekly"], timeshift_snapshots=[], timeshift_dir="/d"),
         "backup.timeshift_none"),
        (dict(timeshift_schedules=["weekly"], timeshift_unread="not_mounted", timeshift_dir="/dev/sdz1"),
         "backup.timeshift_unread"),
    ], ids=["counted", "none", "unread"])
    def test_each_branch_carries_them(self, kw, key):
        details = _keys_details(timeshift_excludes=_EXCL, **kw)
        assert "backup.timeshift_excludes" in details[key]

    def test_without_excludes_the_detail_is_empty(self):
        details = _keys_details(timeshift_schedules=["weekly"],
                                timeshift_snapshots=["2026-11-08_19-00-02"], timeshift_dir="/d")
        assert details["backup.timeshift_snapshots"] == ""


def test_from_system_reads_them(monkeypatch, tmp_path):
    path = tmp_path / "timeshift.json"
    path.write_text(json.dumps({"exclude": _EXCL}))
    monkeypatch.setattr(b, "_TIMESHIFT_CONFIG", path)
    monkeypatch.setattr(b, "_command_exists", lambda name: name == "timeshift")
    monkeypatch.setattr(b, "_read_timeshift", lambda: (["weekly"], ["s1"], "", "/d"))
    snap = b.BackupSnapshot.from_system()
    assert snap.timeshift_excludes == _EXCL and "timeshift" in snap.active_tools


@pytest.mark.parametrize("lang, words", [
    ("en", "Excluded from every snapshot (timeshift.json): /home/alice/**, /root/**."),
    ("fr", "Exclu de chaque instantané (timeshift.json) : /home/alice/**, /root/**."),
], ids=["en", "fr"])
def test_the_rendered_line(lang, words):
    i18n.init(lang)
    try:
        snap = b.BackupSnapshot(active_tools=["timeshift"], timeshift_schedules=["weekly"],
                                timeshift_snapshots=["2026-11-08_19-00-02"], timeshift_dir="/d",
                                timeshift_excludes=_EXCL)
        details = [f.detail for f in b.check_backup(snap, t=i18n.t).findings if f.detail]
    finally:
        i18n.init(lang="en")
    assert any(words in d for d in details)
