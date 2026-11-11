"""v0.33.0 — a Timeshift schedule whose newest snapshot is old is not active.

0.31.4 made "active" need an enabled schedule and at least one snapshot when
the directory can be read; the age of that snapshot was shown, not weighed. A
weekly schedule whose newest snapshot is two months old was "Backup solution
active: timeshift". Timeshift's hourly cron job takes a snapshot when one is
due, so a newest snapshot older than twice the longest enabled period means no
schedule produced one for that long. Then Timeshift counts as installed, not
active, and the line says how old the newest snapshot is. "boot" has no
period: no age is judged. No score moves (active and installed both cost 0).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from bob.checks import backup as b
from tests.helpers import _t

NOW = datetime(2026, 11, 11, 20, 0, 0)


@pytest.mark.parametrize("schedules, newest, stale", [
    (["weekly"], "2026-11-08_19-00-02", False),         # the operator's desktop, 3 days
    (["weekly"], "2026-10-27_19-00-00", True),          # 15 days > 2 × 7
    (["daily"], "2026-11-08_20-00-00", True),           # 3 days > 2 × 1
    (["daily", "weekly"], "2026-11-01_20-00-00", False),  # 10 days < 2 × 7: the longest decides
    (["monthly"], "2026-09-20_12-00-00", False),        # 52 days < 2 × 31
    (["boot"], "2025-01-01_00-00-00", False),           # no period
    (["weekly"], "2026-12-01_00-00-00", False),         # a clock ahead: not stale
], ids=["fresh", "weekly-stale", "daily-stale", "longest-decides", "monthly-fresh", "boot-only", "future"])
def test_the_age_rule(schedules, newest, stale):
    got = b._timeshift_stale(schedules, ["2026-01-01_00-00-00", newest], NOW)
    assert (got is not None) == stale


def test_nothing_read_or_nothing_there_is_not_judged():
    assert b._timeshift_stale(["weekly"], None, NOW) is None
    assert b._timeshift_stale(["weekly"], [], NOW) is None


def test_from_system_counts_a_stale_schedule_as_installed(monkeypatch, tmp_path):
    cfg = tmp_path / "timeshift.json"
    cfg.write_text("{}")
    monkeypatch.setattr(b, "_TIMESHIFT_CONFIG", cfg)
    monkeypatch.setattr(b, "_command_exists", lambda name: name == "timeshift")
    monkeypatch.setattr(b, "_read_timeshift", lambda: (["weekly"], ["2026-01-05_10-00-00"], "", "/d"))
    snap = b.BackupSnapshot.from_system()
    assert "timeshift" in snap.installed_tools and "timeshift" not in snap.active_tools
    assert snap.timeshift_stale_h is not None


def test_what_it_says():
    snap = b.BackupSnapshot(installed_tools=["timeshift"], timeshift_schedules=["weekly"],
                            timeshift_snapshots=["2026-09-01_10-00-00"], timeshift_dir="/d",
                            timeshift_stale_h=24 * 71.4)
    f = {x.key: x for x in b.check_backup(snap, t=_t).findings}
    assert "backup.timeshift_stale" in f and "backup.timeshift_snapshots" not in f
    assert "backup.installed_only" in f
