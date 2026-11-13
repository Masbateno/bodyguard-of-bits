"""v0.35.0 — Timeshift's mode is named in each of its lines.

A field audit (Mint desktop, 12 November 2026) asked which mode Timeshift
ran in: the snapshot lines named a directory (rsync mode) without saying so,
and the BTRFS mode was named only inside the reason its snapshots were not
read.
"""

from __future__ import annotations

from bob import i18n
from bob.checks import backup as b


def _messages(**kw):
    i18n.init("en")
    return [f.message for f in b.check_backup(b.BackupSnapshot(**kw), t=i18n.t).findings
            if f.key.startswith("backup.timeshift")]


def test_btrfs_mode_is_named():
    got = _messages(active_tools=["timeshift"], timeshift_schedules=["daily"], timeshift_unread="btrfs")
    assert got and got[0].startswith("Timeshift (BTRFS): ")


def test_rsync_mode_is_named_when_unread_too():
    got = _messages(active_tools=["timeshift"], timeshift_schedules=["daily"],
                    timeshift_unread="not_mounted", timeshift_dir="/dev/sdz1")
    assert got and got[0].startswith("Timeshift (rsync): ")
