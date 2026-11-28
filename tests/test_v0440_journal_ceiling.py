"""v0.44.0 (B-050) — the journals' ceiling: archived past it, never cut.

Asked by the user (23 November 2026): a ceiling they choose, with a warning.
Decided with the user (27 November 2026): 8 MiB by default, settable up to
16 MiB (the size BOB reads a file to); the same for the journal of --fix
--apply. Past the ceiling the journal is archived — ``<name>.0001``, never
renamed again — and the next one's first line chains onto the archive's last:
read end to end they are one chain, so a deleted or edited archive shows. BOB
deletes no archive (their deletion, by the master or whoever they delegate it
to, comes later).

The journals live in a directory of the test's own (tests/conftest.py), owned
by the account running the suite, with no system log.
"""

from __future__ import annotations

import json
import os

import pytest

from bob import fix_journal as FJ
from bob import i18n
from bob import journals as J


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


@pytest.fixture
def small(monkeypatch):
    """A ceiling of 1500 bytes: a few events per file."""
    monkeypatch.setattr(FJ, "ceiling", lambda: 1500)


def _fill(n=20):
    for i in range(n):
        J.append("cron", "address_added", category="carnet", address=f"ops{i}@example.com")


def _lines(file):
    return [json.loads(ln) for ln in file.read_text().splitlines() if ln.strip()]


# --- the ceiling --------------------------------------------------------------------------

def test_the_ceiling_is_8_mib_by_default_and_16_at_most():
    assert FJ.ceiling() == 8 << 20 == FJ.CEILING_DEFAULT
    assert FJ.CEILING_MAX == 16 << 20 == FJ.MAX_FILE


def test_past_the_ceiling_the_journal_is_archived_and_chained(small):
    _fill()
    archives = FJ.archive_names("cron.journal")
    assert archives and archives[0] == "cron.journal.0001"
    last = _lines(FJ.DIR / archives[0])[-1]
    assert last["kind"] == "rotate" and last["archive"] == "cron.journal.0001"
    first = _lines(FJ.DIR / archives[1] if len(archives) > 1 else FJ.DIR / "cron.journal")[0]
    assert first["prev"] == FJ._digest(FJ._canonical(last))
    journal = J.load("cron")
    assert journal.intact and not journal.foreign_owner
    assert sum(e.kind == "address_added" for e in journal.events) == 20       # nothing cut
    assert all(os.path.getsize(FJ.DIR / a) <= 1500 for a in archives)      # never past the ceiling


def test_archives_are_never_renamed(small):
    _fill(8)
    inode = os.stat(FJ.DIR / "cron.journal.0001").st_ino
    _fill(20)
    assert os.stat(FJ.DIR / "cron.journal.0001").st_ino == inode
    names = FJ.archive_names("cron.journal")
    assert names == [f"cron.journal.{n:04d}" for n in range(1, len(names) + 1)] and len(names) >= 3


def test_the_journal_of_fixes_rotates_and_keeps_an_entry_across_the_archive(monkeypatch):
    entry = FJ.start(finding="ssh.root_login", message="m", command="true", how="shell")
    monkeypatch.setattr(FJ, "ceiling", lambda: 10)          # the outcome line rotates first
    FJ.finish(entry, status="ok", rc=0, error=b"", seconds=0.1)
    assert FJ.archive_names() == ["fixes.journal.0001"]
    journal = FJ.load()
    assert journal.intact and [e.status for e in journal.entries] == ["ok"]


def test_a_deleted_archive_shows_as_a_break(small):
    _fill(30)
    assert len(FJ.archive_names("cron.journal")) >= 2
    os.unlink(FJ.DIR / "cron.journal.0001")
    journal = J.load("cron")
    assert not journal.intact
    assert "cron.journal.0002" in J.broken_where(journal, i18n.t)


def test_an_archive_changed_breaks_the_chain_at_its_line(small):
    """In the second archive: there, the chain's line number and the file's differ."""
    _fill(40)
    first = len((FJ.DIR / "cron.journal.0001").read_text().splitlines())
    archive = FJ.DIR / "cron.journal.0002"
    rows = archive.read_text().splitlines()
    rows[1] = rows[1].replace("@example.com", "@evil.example")
    archive.write_text("\n".join(rows) + "\n")
    journal = J.load("cron")
    assert not journal.intact
    assert J.broken_where(journal, i18n.t) == f"{first + 3} (cron.journal.0002, line 3)"


def test_an_empty_journal_after_its_archive_goes_on_the_chain(small):
    _fill(10)
    os.unlink(FJ.DIR / "cron.journal")              # BOB stopped between archive and new line
    J.append("cron", "address_added", category="carnet", address="after@example.com")
    assert J.load("cron").intact


def test_an_archive_that_cannot_be_made_drops_no_trace(small, monkeypatch):
    def refuse(*_a, **_k):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(FJ.os, "link", refuse)
    _fill(10)
    assert FJ.archive_names("cron.journal") == []
    journal = J.load("cron")
    assert journal.intact and len(journal.events) == 10


# --- reading back --------------------------------------------------------------------------

def test_archives_beyond_the_read_budget_are_counted_not_alarmed(small, monkeypatch):
    _fill(40)
    monkeypatch.setattr(FJ, "CHAIN_BUDGET", 2500)
    journal = J.load("cron")
    assert journal.skipped >= 1 and journal.intact
    lines, _code = J.journal_lines("cron", i18n.t)
    assert any("older archive(s) not read here" in ln for ln in lines)


def test_lines_of_unread_archives_are_not_said_removed(monkeypatch):
    from datetime import datetime, timedelta
    from bob import fix_witness as W
    for _ in range(6):
        FJ.record(finding="ssh.root_login", message="m", command="true", how="shell",
                  status="ok", rc=0, error=b"", seconds=0.1)
    journal = FJ.load()
    journal.skipped = 1                              # as when the oldest archives were not read
    first = W._at(journal.seen[0].at)
    old = W.Witness(kind="run", id="gone-with-an-archive", digest="x", body="y",
                    at=first - timedelta(days=3), message="")
    later = W.Witness(kind="run", id="really-removed", digest="x", body="y",
                      at=first + timedelta(seconds=1), message="")
    read = W.WitnessRead(state="ok", items=[old, later], oldest=datetime(2000, 1, 1).astimezone())
    verdict = W.verify(journal, read, append_only=None)
    assert [w.id for w in verdict.removed] == ["really-removed"]


def test_the_size_says_the_ceiling_and_the_archives(small):
    _fill(20)
    text = J.size_text("cron", i18n.t)
    assert "past it, archived — nothing is cut" in text and "archive(s)" in text


# --- setting it ------------------------------------------------------------------------------

def test_max_size_is_set_warned_and_written(capsys):
    asked = []
    tone, lines = J.set_max_size("1M", i18n.t, ask=lambda q: asked.append(q) or True, say=print)
    assert tone == "done" and J.load_settings().max_size == 1 << 20 == FJ.ceiling()
    assert "Nothing is cut" in asked[0] and "BOB deletes no archive" in asked[0]
    assert any(e.kind == "journals_ceiling" for e in J.load("admin").events)
    J._settings_checked(print)
    assert "changed outside bob" not in capsys.readouterr().out.lower()


@pytest.mark.parametrize("value", ["10K", "32M", "lots"])
def test_a_ceiling_out_of_bounds_is_refused(value):
    from bob import team
    with pytest.raises(team.TeamError) as err:
        J.set_max_size(value, i18n.t, ask=lambda q: True)
    assert err.value.key == "journals_max_size"


def test_default_goes_back_to_8_mib():
    J.set_max_size("2M", i18n.t, ask=lambda q: True)
    J.set_max_size("default", i18n.t, ask=lambda q: True)
    assert J.load_settings().max_size == 0 and FJ.ceiling() == 8 << 20


def test_a_refusal_changes_nothing():
    tone, _lines = J.set_max_size("2M", i18n.t, ask=lambda q: False)
    assert tone == "info" and J.load_settings().max_size == 0


def test_the_categories_keep_the_ceiling():
    J.set_max_size("2M", i18n.t, ask=lambda q: True)
    J.set_categories(["cron"], False, i18n.t)
    assert J.load_settings().max_size == 2 << 20


def test_the_command_line_reads_max_size(monkeypatch, capsys):
    import bob._tty
    monkeypatch.setattr(bob._tty, "safe_input", lambda *a, **k: "y")
    assert J.run(["max-size", "4M"], i18n.t) == 0
    assert J.load_settings().max_size == 4 << 20
    assert "Journals' ceiling: 4.0 MB" in capsys.readouterr().out


def test_the_journals_screen_announces_p_and_the_ceiling():
    from bob.tui import _keys
    from bob.tui import journals as TJ
    assert _keys.CEILING in TJ._LIST_KEYS
    assert "8.0 MB" in TJ.ceiling_text(i18n.t) and "deletes no archive" in TJ.ceiling_text(i18n.t)


def test_a_writer_that_waited_through_an_archive_writes_to_the_new_journal(monkeypatch):
    """Two BOBs: the second waits for the lock while the first archives the
    journal. What it then holds is the archive — it must reopen the journal."""
    J.append("cron", "address_added", category="carnet", address="first@example.com")
    real, done = FJ.fcntl.flock, []

    def flock(fd, op):
        if not done:                               # the other BOB archives meanwhile
            done.append(True)
            os.rename(FJ.DIR / "cron.journal", FJ.DIR / "cron.journal.0001")
        return real(fd, op)

    monkeypatch.setattr(FJ.fcntl, "flock", flock)
    J.append("cron", "address_added", category="carnet", address="second@example.com")
    assert "second@" not in (FJ.DIR / "cron.journal.0001").read_text()
    assert "second@" in (FJ.DIR / "cron.journal").read_text()


def test_the_journal_of_fixes_says_the_file_its_chain_breaks_in(monkeypatch):
    from bob import fix_witness as W
    from bob import fixlog
    monkeypatch.setattr(FJ, "ceiling", lambda: 1200)
    for _ in range(6):
        FJ.record(finding="ssh.root_login", message="m", command="true", how="shell",
                  status="ok", rc=0, error=b"", seconds=0.1)
    archive = FJ.DIR / "fixes.journal.0001"
    rows = archive.read_text().splitlines()
    rows[0] = rows[0].replace('"m"', '"changed"')
    archive.write_text("\n".join(rows) + "\n")
    journal = FJ.load()
    verdict = W.verify(journal, W.WitnessRead(state="no_journald"), append_only=None)
    text = " ".join(t for t, _k in fixlog.verdict_lines(verdict, journal, i18n.t))
    assert "fixes.journal.0001, line 2" in text


def test_the_line_that_says_archived_is_read_back_from_the_system_log():
    """Measured as root on the test Mint (27 November 2026): the witness
    reader knew run, result and note only — the rotation's line was the one
    of 241 not shown, so every rotation would leave the verdict unproven."""
    from bob import fix_witness as W
    rotated = {"kind": "rotate", "id": "a1b2c3d4e5f6", "archive": "fixes.journal.0001",
               "ceiling": 8 << 20, "by": {}, "prev": "0" * 64}
    match = W._HEAD.match(FJ.witness_message(rotated, "f" * 64))
    assert match and match.group(1) == "rotate"


def test_a_journal_whose_archives_are_all_gone_says_its_first_line_follows_nothing(small):
    """Measured as root on the test Mint: the archive deleted read "line 1" only."""
    _fill(10)
    for name in FJ.archive_names("cron.journal"):
        os.unlink(FJ.DIR / name)
    text = J.broken_where(J.load("cron"), i18n.t)
    assert text.startswith("1 (cron.journal, line 1: it does not follow the line before it")


def test_at_the_highest_ceiling_every_file_stays_readable(monkeypatch):
    """Found after the external review: the archive took the rotation line on
    top of a full journal and passed the ceiling — at 16 MiB, past the size BOB
    reads a file to, an archive BOB could not read back. Here the read bound
    and the highest ceiling are made small, the relation between them kept."""
    monkeypatch.setattr(FJ, "MAX_FILE", 6000)
    monkeypatch.setattr(FJ, "CEILING_MAX", 6000)
    monkeypatch.setattr(FJ, "ceiling", lambda: FJ.CEILING_MAX)
    _fill(120)
    files = FJ.archive_names("cron.journal") + ["cron.journal"]
    assert len(files) >= 3 and all(os.path.getsize(FJ.DIR / f) <= 6000 for f in files)
    journal = J.load("cron")
    assert not journal.unreadable and journal.intact and len(journal.events) >= 120
