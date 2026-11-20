"""v0.39.0 — notes on an audit report, beside it and never inside it.

Decided with the user (16-17 November 2026): notes on a report shown by
``--manage-logs`` in a block of their own above it; dated automatically; as
many as wanted; edits marked and their history kept; on a server several
operators share, every action must say who did it, a deletion included —
"perfect transparency". A note is withdrawn (its text stays in the journal) or,
for a secret pasted by mistake, purged (its text removed; who, when and why
kept).

Who: measured on the test Linux Mint 22.3 (a10390, 17 November 2026), the
kernel's login uid named the operator through sudo, sudo -i, sudo su -, sudo
env -i and a nested sudo, where SUDO_USER was absent, "root" or forged
(sudo SUDO_USER=alice). Root can still rewrite its login uid (measured): the
journal makes a change outside BOB visible, it cannot forbid one.
"""

from __future__ import annotations

import errno
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from bob import annotations as A


@pytest.fixture(autouse=True)
def _journal_owner(monkeypatch):
    """The journal belongs to root; the tests do not run as root, so the
    expected owner is the account running them (A._JOURNAL_UID is the seam)."""
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())


@pytest.fixture
def report(tmp_path, monkeypatch):
    r = tmp_path / "bob_20261117_150000.log"
    r.write_text("audit\n", encoding="utf-8")
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("DOAS_USER", raising=False)
    return r


class TestWho:
    def _loginuid(self, monkeypatch, tmp_path, value):
        f = tmp_path / "loginuid"
        f.write_text(value)
        monkeypatch.setattr(A, "_LOGINUID", f)

    def test_the_login_uid_names_the_operator(self, monkeypatch, tmp_path):
        self._loginuid(monkeypatch, tmp_path, str(os.getuid()))
        monkeypatch.delenv("SUDO_USER", raising=False)
        who = A.operator()
        assert who["login"] and "sudo" not in who and who["uid"] == os.geteuid()

    def test_a_sudo_claim_that_differs_is_shown_beside_it(self, monkeypatch, tmp_path):
        self._loginuid(monkeypatch, tmp_path, str(os.getuid()))
        monkeypatch.setenv("SUDO_USER", "alice")
        who = A.operator()
        assert who["sudo"] == "alice"
        assert A.who_label(who) == f"{who['login']} (sudo: alice)"

    def test_outside_a_login_session_the_claim_then_the_account(self, monkeypatch, tmp_path):
        self._loginuid(monkeypatch, tmp_path, "4294967295")
        monkeypatch.setenv("SUDO_USER", "bob")
        who = A.operator()
        assert "login" not in who and A.who_label(who) == "bob"
        monkeypatch.delenv("SUDO_USER")
        assert A.who_label(A.operator())       # the effective account, never empty

    def test_every_action_carries_its_author(self, report):
        A.add(report, "one")
        A.withdraw(report, 1)
        for ev in A.load(report).events:
            assert isinstance(ev["by"], dict) and "uid" in ev["by"] and ev["at"]


class TestTheActions:
    def test_notes_are_numbered_and_dated(self, report):
        A.add(report, "first")
        j = A.add(report, "second")
        assert [(n.number, n.text) for n in j.active] == [(1, "first"), (2, "second")]
        assert all(n.created.at for n in j.notes)

    def test_an_edit_is_marked_and_its_versions_kept(self, report):
        A.add(report, "draft")
        j = A.edit(report, 1, "final")
        note = j.notes[0]
        assert note.text == "final" and note.edited is not None
        assert [v.text for v in note.versions] == ["draft", "final"]

    def test_a_withdrawn_note_leaves_the_block_and_stays_in_the_journal(self, report):
        A.add(report, "kept in the journal")
        j = A.withdraw(report, 1)
        assert j.active == [] and j.notes[0].withdrawn is not None
        assert "kept in the journal" in A.note_path(report).read_text()

    def test_a_withdrawn_note_cannot_be_edited_or_withdrawn_again(self, report):
        A.add(report, "x")
        A.withdraw(report, 1)
        for act in (lambda: A.edit(report, 1, "y"), lambda: A.withdraw(report, 1)):
            with pytest.raises(A.NoteError) as e:
                act()
            assert e.value.key == "no_note"

    def test_an_empty_note_is_not_written(self, report):
        with pytest.raises(A.NoteError) as e:
            A.add(report, "  \x1b\x07\r  ")
        assert e.value.key == "empty"
        assert A.load(report).events == []

    def test_control_characters_never_reach_the_journal(self, report):
        j = A.add(report, "line\x1b[31mred\rback\x07")
        assert j.notes[0].text == "line [31mred back"


class TestThePurge:
    def test_the_text_leaves_every_line_and_the_trace_stays(self, report):
        A.add(report, "secret hunter2")
        A.edit(report, 1, "still hunter2")
        j = A.purge(report, 1, "password pasted by mistake")
        raw = A.note_path(report).read_text()
        assert "hunter2" not in raw
        note = j.notes[0]
        assert note.purged is not None and note.purged[2] == "password pasted by mistake"
        assert j.intact and all(v.text is None for v in note.versions)

    def test_a_withdrawn_note_can_be_purged(self, report):
        A.add(report, "secret")
        A.withdraw(report, 1)
        assert A.purge(report, 1, "secret").notes[0].purged is not None

    def test_a_reason_is_required(self, report):
        A.add(report, "x")
        with pytest.raises(A.NoteError) as e:
            A.purge(report, 1, "   ")
        assert e.value.key == "no_reason"

    def test_the_digest_left_cannot_be_matched_without_the_salt(self, report):
        A.add(report, "1234")
        A.purge(report, 1, "pin")
        ev = json.loads(A.note_path(report).read_text().splitlines()[0])
        assert "salt" not in ev and "text" not in ev and ev["th"]
        assert ev["th"] != A._digest(b"1234")


class TestAChangeOutsideBobShows:
    def _lines(self, report):
        return A.note_path(report).read_text().splitlines()

    def _write(self, report, lines):
        A.note_path(report).write_text("\n".join(lines) + "\n")

    def _three(self, report):
        for text in ("one", "two", "three"):
            A.add(report, text)

    def test_untouched_is_intact(self, report):
        self._three(report)
        assert A.load(report).intact

    def test_a_text_changed(self, report):
        self._three(report)
        lines = self._lines(report)
        ev = json.loads(lines[1])
        ev["text"] = "rewritten"
        lines[1] = json.dumps(ev)
        self._write(report, lines)
        j = A.load(report)
        assert not j.intact and j.broken_at == 2

    def test_an_author_changed(self, report):
        self._three(report)
        lines = self._lines(report)
        ev = json.loads(lines[0])
        ev["by"] = {"login": "someone-else", "uid": 0}
        lines[0] = json.dumps(ev)
        self._write(report, lines)
        j = A.load(report)
        assert not j.intact and j.broken_at == 2      # the next line no longer chains

    def test_a_line_removed_from_the_middle(self, report):
        self._three(report)
        lines = self._lines(report)
        del lines[1]
        self._write(report, lines)
        assert not A.load(report).intact

    def test_lines_reordered(self, report):
        self._three(report)
        lines = self._lines(report)
        lines[0], lines[1] = lines[1], lines[0]
        self._write(report, lines)
        assert not A.load(report).intact

    def test_a_journal_moved_to_another_report(self, report, tmp_path):
        self._three(report)
        other = tmp_path / "bob_20261118_150000.log"
        other.write_text("other\n")
        A.note_path(other).write_text(A.note_path(report).read_text())
        assert not A.load(other).intact

    def test_nothing_is_written_over_a_changed_journal(self, report):
        self._three(report)
        lines = self._lines(report)
        del lines[1]
        self._write(report, lines)
        with pytest.raises(A.NoteError) as e:
            A.add(report, "four")
        assert e.value.key == "tampered"


class TestTheFile:
    def test_root_owned_in_the_report_s_group(self, report):
        """0640, owner = root (the seam's uid here), group = the report's: the
        report's owner reads it, only root writes it."""
        A.add(report, "x")
        st, rst = os.stat(A.note_path(report)), os.stat(report)
        assert st.st_mode & 0o777 == 0o640
        assert (st.st_uid, st.st_gid) == (A._JOURNAL_UID, rst.st_gid)

    def test_written_only_by_bob_run_as_root(self, report, monkeypatch):
        monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid() + 1)
        with pytest.raises(A.NoteError) as e:
            A.add(report, "x")
        assert e.value.key == "needs_root" and not A.note_path(report).exists()

    def test_a_journal_owned_by_someone_else_is_not_bob_s(self, report, monkeypatch):
        """Measured on the test Mint: owned by the report's owner, the journal
        was rewritten without root, its chain recomputed, and read as intact.
        Not owned by root, it is said not to be BOB's, whatever its chain."""
        A.add(report, "x")
        monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid() + 1)
        j = A.load(report)
        assert not j.intact and j.foreign_owner

    def test_nothing_is_written_to_a_journal_someone_else_owns(self, report, monkeypatch):
        A.add(report, "x")
        monkeypatch.setattr(A, "_JOURNAL_UID", 12345)
        monkeypatch.setattr(A.os, "geteuid", lambda: 12345)
        with pytest.raises(A.NoteError) as e:
            A.add(report, "y")
        assert e.value.key == "foreign_owner"

    def test_a_name_that_never_settles_is_refused_not_retried_for_ever(self, report, monkeypatch):
        """Measured in the 0.39.0 mutation run: unbounded, the reopen loop spun
        for ever on a link at the name. Bounded, it refuses."""
        real = os.stat

        def moving(name, *a, **k):
            r = real(name, *a, **k)
            if k.get("dir_fd") is None:
                return r
            return os.stat_result((r.st_mode, r.st_ino + 1, r.st_dev, r.st_nlink, r.st_uid, r.st_gid,
                                   r.st_size, int(r.st_atime), int(r.st_mtime), int(r.st_ctime)))
        monkeypatch.setattr(A.os, "stat", moving)
        with pytest.raises(A.NoteError) as e:
            A.add(report, "x")
        assert e.value.key == "busy"

    def test_a_non_regular_file_is_not_read(self, report):
        os.mkfifo(A.note_path(report))
        j = A.load(report)
        assert j.unreadable == "not_regular" and not j.events

    def test_a_link_at_its_name_is_refused(self, report, tmp_path):
        """Measured on the test Mint (a10390/root-owned-2.txt): the report's
        owner put a link where the journal was. Neither read nor written
        through — but it came back as the system's English "Too many levels of
        symbolic links", inside a French screen. Read: the key "link";
        written: NoteError("link"); the link's target untouched."""
        target = tmp_path / "elsewhere"
        target.write_text("")
        A.note_path(report).symlink_to(target)
        assert A.load(report).unreadable == "link"
        with pytest.raises(A.NoteError) as e:
            A.add(report, "x")
        assert e.value.key == "link"
        assert target.read_text() == ""

    def test_a_journal_this_account_cannot_read_is_said_so(self, report, monkeypatch):
        """An operator outside the report's group, without root: denied, said
        as such rather than in the system's words."""
        A.add(report, "x")
        real = A.os.open

        def deny(path, *a, **k):
            if str(path).endswith(A.SUFFIX):
                raise PermissionError(errno.EACCES, "Permission denied")
            return real(path, *a, **k)
        monkeypatch.setattr(A.os, "open", deny)
        assert A.load(report).unreadable == "denied"

    def test_the_report_itself_is_never_touched(self, report):
        before = report.read_bytes()
        A.add(report, "x")
        A.purge(report, 1, "y")
        assert report.read_bytes() == before


def _slow_adder(path: str, n: int) -> None:
    """Adds *n* notes, pausing between reading the journal and writing to it,
    so that two of these overlap for certain: without the lock both read the
    same state and the chain breaks; with it they take turns."""
    import time
    real = A._read_fd

    def slow(fd):
        out = real(fd)
        time.sleep(0.3)
        return out
    A._read_fd = slow
    for i in range(n):
        A.add(Path(path), f"from {os.getpid()} #{i}")


def test_two_operators_writing_at_once_lose_nothing(report):
    """Two writers at once, overlapping for certain: the lock keeps every line
    and the chain intact. (A first version let the processes run as they
    came, and its mutation — the lock removed — survived when they happened
    not to overlap.)"""
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_slow_adder, args=(str(report), 3)) for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    j = A.load(report)
    assert j.intact and len(j.events) == 6 and len(j.active) == 6
