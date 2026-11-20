"""v0.40.0 — the journal of ``--fix --apply`` (B-031), the module alone.

Decided with the user (19 and 20 November 2026): every command ``--fix
--apply`` runs leaves a dated entry — who, which finding, the exact command,
what came of it — in one journal for the host; an entry is never changed, a
note can be added to it, never edited or withdrawn; each entry is also sent to
the system log with its digest, and an entry written where there is no system
log says so.

Writing needs root: the tests make the account running them the journal's
expected owner (FJ._JOURNAL_UID is the seam, as for the notes) and give the
journal the account's own group (FJ._group_id).
"""

from __future__ import annotations

import json
import os
import socket
import stat
import syslog

import pytest

from bob import annotations as A
from bob import fix_journal as FJ


@pytest.fixture(autouse=True)
def _journal(tmp_path, monkeypatch):
    monkeypatch.setattr(FJ, "DIR", tmp_path / "bob")
    monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid())
    monkeypatch.setattr(FJ, "_group_id", lambda: os.getegid())
    monkeypatch.setattr(FJ, "_SYSLOG_SOCKET", tmp_path / "no-log")
    monkeypatch.setattr(FJ, "_operator", lambda: {"uid": 0, "login": "alice", "sudo": "alice"})
    yield


def _run(**over):
    args = dict(finding="ssh.root_login", message="Root login allowed",
                command="sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                how="shell", status="ok", rc=0, error=b"", seconds=0.4)
    args.update(over)
    return FJ.record(**args)


def _lines():
    return FJ.path().read_text().splitlines()


class TestOneEntryPerCommand:
    def test_what_an_entry_keeps(self):
        _run()
        (entry,) = FJ.load().entries
        assert (entry.finding, entry.message, entry.status, entry.rc, entry.seconds) == (
            "ssh.root_login", "Root login allowed", "ok", 0, 0.4)
        assert entry.command.startswith("sed -i 's/^PermitRootLogin")
        assert entry.who == {"uid": 0, "login": "alice", "sudo": "alice"}
        assert entry.at and entry.how == "shell"

    @pytest.mark.parametrize("status", ["ok", "failed", "timeout", "unconfirmed"])
    def test_every_outcome_is_kept(self, status):
        _run(status=status, rc=None if status == "timeout" else 1)
        assert FJ.load().entries[0].status == status

    def test_an_unknown_outcome_is_not_called_success(self):
        _run(status="weird")
        assert FJ.load().entries[0].status == "failed"

    def test_bounded(self):
        _run(command="x" * (FJ.MAX_COMMAND + 50), error=("é" * (FJ.MAX_ERROR + 50)).encode())
        entry = FJ.load().entries[0]
        assert len(entry.command) == FJ.MAX_COMMAND and len(entry.error) == FJ.MAX_ERROR

    def test_one_entry_per_command_in_order(self):
        for n in range(3):
            _run(finding=f"f{n}")
        assert [e.finding for e in FJ.load().entries] == ["f0", "f1", "f2"]
        assert [json.loads(ln)["kind"] for ln in _lines()] == ["run", "result"] * 3

    def test_written_before_the_command_runs(self):
        """BOB dies during the command (the firewall fix that cuts its SSH
        session): the entry is there, started, outcome unknown."""
        entry_id = FJ.start(finding="ufw.inactive", message="m", command="ufw --force enable", how="shell")
        (entry,) = FJ.load().entries
        assert (entry.id, entry.status, entry.rc, entry.ended) == (entry_id, FJ.STARTED, None, "")
        FJ.finish(entry_id, status="ok", rc=0, error=b"", seconds=1.5)
        (entry,) = FJ.load().entries
        assert (entry.status, entry.seconds) == ("ok", 1.5) and entry.ended
        assert len(entry.lines) == 2

    def test_writable_is_asked_first(self, monkeypatch):
        FJ.check_writable()
        assert FJ.path().exists() and FJ.load().entries == []
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        with pytest.raises(FJ.FixJournalError):
            FJ.check_writable()


class TestNeverChanged:
    def test_the_chain_holds(self):
        _run(); _run(status="failed", rc=2)
        FJ.add_note(FJ.load().entries[0].id, "checked by hand")
        journal = FJ.load()
        assert journal.intact and journal.broken_at is None and journal.lines == 5

    def test_a_changed_line_breaks_the_chain_at_the_next(self):
        _run(); _run(); _run()
        lines = _lines()
        event = json.loads(lines[1]); event["status"] = "failed"
        lines[1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        FJ.path().write_text("\n".join(lines) + "\n")
        journal = FJ.load()
        assert not journal.intact and journal.broken_at == 3

    def test_a_removed_line_breaks_the_chain(self):
        _run(); _run(); _run()
        lines = _lines()
        FJ.path().write_text(lines[0] + "\n" + lines[2] + "\n")
        journal = FJ.load()
        assert not journal.intact and journal.broken_at == 2

    def test_a_reordered_journal_breaks_at_once(self):
        _run(); _run()
        lines = _lines()
        FJ.path().write_text(lines[1] + "\n" + lines[0] + "\n")
        assert FJ.load().broken_at == 1

    def test_a_changed_journal_still_receives_the_next_command(self):
        """A command that changed the system must leave a trace; the break
        stays visible at its line."""
        _run(); _run()
        lines = _lines()
        FJ.path().write_text(lines[0] + "\ngarbage\n" + lines[1] + "\n")
        _run(finding="after")
        journal = FJ.load()
        assert journal.entries[-1].finding == "after" and journal.broken_at == 2

    def test_a_note_is_added_not_edited(self):
        _run()
        entry_id = FJ.load().entries[0].id
        FJ.add_note(entry_id, "first")
        FJ.add_note(entry_id, "second")
        (entry,) = FJ.load().entries
        assert [n.text for n in entry.notes] == ["first", "second"]
        assert entry.status == "ok" and len(_lines()) == 4
        assert entry.notes[0].who == {"uid": 0, "login": "alice", "sudo": "alice"}

    def test_a_note_needs_text_and_an_entry(self):
        _run()
        with pytest.raises(FJ.FixJournalError) as err:
            FJ.add_note(FJ.load().entries[0].id, "  \x1b \n\t \x07 ")
        assert err.value.key == "empty"
        with pytest.raises(FJ.FixJournalError) as err:
            FJ.add_note("nope", "text")
        assert err.value.key == "no_entry"

    def test_the_genesis_is_this_journals_own(self):
        """A notes journal's first line does not chain into this one."""
        _run()
        assert json.loads(_lines()[0])["prev"] == FJ._digest(b"bob-fixes\0")


class TestWhoCanWrite:
    def test_root_only(self, monkeypatch):
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        with pytest.raises(FJ.FixJournalError) as err:
            _run()
        assert err.value.key == "needs_root" and not FJ.DIR.exists()

    def test_modes(self):
        _run()
        dst, fst = os.stat(FJ.DIR), os.stat(FJ.path())
        assert stat.S_IMODE(dst.st_mode) == 0o750 and stat.S_IMODE(fst.st_mode) == 0o640
        assert (fst.st_uid, fst.st_gid) == (os.geteuid(), os.getegid())

    def test_a_link_at_the_journal_is_refused(self, tmp_path):
        FJ.DIR.mkdir()
        target = tmp_path / "elsewhere"
        target.write_text("")
        FJ.path().symlink_to(target)
        with pytest.raises(FJ.FixJournalError) as err:
            _run()
        assert err.value.key == "link" and target.read_text() == ""
        assert FJ.load().unreadable == "link"

    def test_a_link_at_the_directory_is_refused(self, tmp_path):
        (tmp_path / "real").mkdir()
        FJ.DIR.symlink_to(tmp_path / "real")
        with pytest.raises(FJ.FixJournalError) as err:
            _run()
        assert err.value.key == "link" and not list((tmp_path / "real").iterdir())

    def test_a_hard_link_is_refused(self, tmp_path):
        FJ.DIR.mkdir()
        FJ.path().write_text("")
        os.link(FJ.path(), tmp_path / "twin")
        with pytest.raises(FJ.FixJournalError) as err:
            _run()
        assert err.value.key == "not_regular"

    def test_a_journal_root_does_not_own_is_not_bobs(self, monkeypatch):
        """The file's own owner, the directory accepted: without that, the
        directory's check answered first and the file's was never reached (a
        mutation of it survived)."""
        _run()
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        monkeypatch.setattr(FJ.os, "geteuid", lambda: os.getuid() + 1)
        monkeypatch.setattr(FJ, "_open_dir", lambda: os.open(str(FJ.DIR), os.O_RDONLY | os.O_DIRECTORY))
        with pytest.raises(FJ.FixJournalError) as err:
            _run()
        assert err.value.key == "foreign_owner"
        journal = FJ.load()
        assert journal.foreign_owner and not journal.intact and len(_lines()) == 2

    def test_a_directory_root_does_not_own_is_refused(self, monkeypatch):
        FJ.DIR.mkdir()
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        monkeypatch.setattr(FJ.os, "geteuid", lambda: os.getuid() + 1)
        with pytest.raises(FJ.FixJournalError) as err:
            _run()
        assert err.value.key == "foreign_owner" and not FJ.path().exists()


class TestReading:
    def test_absent_is_empty(self):
        journal = FJ.load()
        assert journal.entries == [] and journal.intact and journal.unreadable is None

    def test_denied_is_said(self):
        _run()
        os.chmod(FJ.path(), 0)
        try:
            if os.access(FJ.path(), os.R_OK):
                pytest.skip("running as root")
            assert FJ.load().unreadable == "denied"
        finally:
            os.chmod(FJ.path(), 0o640)

    def test_it_reads_past_the_notes_bound(self):
        """Never purged, the journal reads further than a notes journal."""
        for _ in range(A.MAX_FILE // 3000 + 2):
            _run(command="y" * 3000)
        assert FJ.path().stat().st_size > A.MAX_FILE
        journal = FJ.load()
        assert journal.unreadable is None and journal.intact
        assert A._read_raw(FJ.path())[1] == "too_large"        # the notes keep theirs

    def test_by_day_most_recent_first(self):
        _run(finding="a"); _run(finding="b"); _run(finding="c")
        lines = [json.loads(ln) for ln in _lines()]
        lines[0]["at"] = "2026-11-18T10:00:00+01:00"
        lines[1]["at"] = "2026-11-20T09:00:00+01:00"
        lines[2]["at"] = "2026-11-20T11:00:00+01:00"
        prev = FJ._GENESIS
        for event in lines:
            event["prev"] = prev
            prev = FJ._digest(FJ._canonical(event))
        FJ.path().write_text("".join(json.dumps(e) + "\n" for e in lines))
        days = FJ.days(FJ.load())
        assert [d for d, _ in days] == ["2026-11-20", "2026-11-18"]
        assert [e.finding for e in days[0][1]] == ["b", "c"]


class TestTheWitness:
    def test_no_system_log_is_said(self, monkeypatch):
        sent = []
        monkeypatch.setattr(syslog, "syslog", lambda *a: sent.append(a))
        _run()
        assert FJ.load().entries[0].witness == "none" and sent == []

    def test_a_plain_file_is_no_system_log(self, tmp_path, monkeypatch):
        (tmp_path / "no-log").write_text("")
        sent = []
        monkeypatch.setattr(syslog, "syslog", lambda *a: sent.append(a))
        _run()
        assert FJ.load().entries[0].witness == "none" and sent == []

    def test_each_entry_is_sent_with_its_digest(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind("log")
        monkeypatch.setattr(FJ, "_SYSLOG_SOCKET", FJ.Path("log"))
        sent = []
        monkeypatch.setattr(syslog, "syslog", lambda prio, msg: sent.append((prio, msg)))
        try:
            _run()
            FJ.add_note(FJ.load().entries[0].id, "seen")
        finally:
            sock.close()
        lines = [json.loads(ln) for ln in _lines()]
        assert [e["witness"] for e in lines] == ["syslog"] * 3
        assert len(sent) == 3
        for (prio, msg), event in zip(sent, lines, strict=True):
            assert prio == syslog.LOG_NOTICE
            assert msg.startswith(f"{event['kind']} id={event['id']} sha256={FJ._digest(FJ._canonical(event))} "
                                  f"body={FJ.body_digest(event)}")
        assert "PermitRootLogin" in sent[0][1]
        assert f"of={lines[0]['id']} status=ok rc=0" in sent[1][1] and f"of={lines[0]['id']}" in sent[2][1]

    def test_a_witness_that_fails_does_not_stop_the_entry(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind("log")
        monkeypatch.setattr(FJ, "_SYSLOG_SOCKET", FJ.Path("log"))

        def boom(*_a):
            raise OSError("no")
        monkeypatch.setattr(syslog, "syslog", boom)
        try:
            _run()
        finally:
            sock.close()
        assert len(FJ.load().entries) == 1
