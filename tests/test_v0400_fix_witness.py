"""v0.40.0 — a falsified journal of ``--fix --apply`` is shown (B-031).

The user (20 November 2026): "the moment the log has been falsified, it must
be shown explicitly, or at least be easy to demonstrate". One test for each
way of falsifying it — the same list the documentation demonstrates — and one
for each case that must *not* be called a falsification.

The system log is played by a list: what ``_send_witness`` would have sent,
read back as journald would hand it (``_UID=0``).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from bob import fix_journal as FJ
from bob import fix_witness as W


@pytest.fixture
def journald(tmp_path, monkeypatch):
    monkeypatch.setattr(FJ, "DIR", tmp_path / "bob")
    monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid())
    monkeypatch.setattr(FJ, "_group_id", lambda: os.getegid())
    monkeypatch.setattr(FJ, "_operator", lambda: {"uid": 0, "login": "alice"})
    monkeypatch.setattr(FJ, "_has_witness", lambda: True)
    sent = []
    monkeypatch.setattr(FJ, "_send_witness",
                        lambda event, digest: sent.append(W.Witness(
                            kind=event["kind"], id=event["id"], digest=digest,
                            body=FJ.body_digest(event), at=datetime.now(timezone.utc), message=FJ.witness_message(event, digest))))
    return sent


def _run(finding="ssh.root_login", status="ok"):
    return FJ.record(finding=finding, message="m", command="cmd", how="shell",
                     status=status, rc=0, error="", seconds=0.1)


def _read(sent, oldest=None):
    return W.WitnessRead("ok", items=list(sent), oldest=oldest or datetime(2000, 1, 1, tzinfo=timezone.utc))


def _events():
    """The journal's lines; each command is two — its start, its outcome."""
    return [json.loads(ln) for ln in FJ.path().read_text().splitlines()]


def _rewrite(events, rechain=True):
    """Write *events* back as a falsifier would; *rechain* recomputes every
    digest, so the chain alone no longer shows anything."""
    prev = FJ._GENESIS
    out = []
    for event in events:
        if rechain:
            event["prev"] = prev
        prev = FJ._digest(FJ._canonical(event))
        out.append(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    FJ.path().write_text("\n".join(out) + "\n")


def _verify(sent, **kw):
    return W.verify(witness=_read(sent, kw.pop("oldest", None)), append_only=kw.pop("append_only", None))


def _ids(events):
    return [e["id"] for e in events]


class TestNothingDone:
    def test_intact(self, journald):
        _run(); _run(status="failed")
        FJ.add_note(FJ.load().entries[0].id, "seen")
        verdict = _verify(journald)
        assert verdict.overall == "intact"
        assert len(verdict.confirmed) == 5 and not verdict.removed
        assert {verdict.of_entry(e) for e in FJ.load().entries} == {"confirmed"}


class TestFalsifications:
    def test_an_outcome_changed_and_the_chain_recomputed(self, journald):
        """The chain alone sees nothing; the witness does — and names the line
        changed apart from the lines merely re-chained after it."""
        _run(); _run(status="failed"); _run()
        events = _events()
        events[3]["status"] = "ok"                                   # the second command's outcome
        _rewrite(events)
        assert FJ.load().intact                                      # the chain is fooled
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and verdict.differs == [events[3]["id"]]
        assert verdict.rechained == _ids(events[4:])                 # said the same, re-chained
        entries = FJ.load().entries
        assert [verdict.of_entry(e) for e in entries] == ["confirmed", "differs", "rechained"]

    def test_a_line_changed_without_recomputing(self, journald):
        _run(); _run()
        events = _events()
        events[0]["command"] = "true"
        _rewrite(events, rechain=False)
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and verdict.chain_broken_at == 2
        assert verdict.differs == [events[0]["id"]]

    def test_the_last_entries_cut(self, journald):
        _run(); _run(finding="b"); _run(finding="c")
        events = _events()
        _rewrite(events[:2])
        verdict = _verify(journald)
        assert verdict.overall == "tampered"
        assert [w.id for w in verdict.removed] == _ids(events[2:])
        assert "finding=c" in verdict.removed[2].message             # what was cut can be read

    def test_an_outcome_cut_to_look_interrupted(self, journald):
        """Removing an outcome line makes a failed command read as started
        with no known outcome; the witness still has the outcome."""
        _run(status="failed")
        events = _events()
        _rewrite(events[:1])
        assert FJ.load().entries[0].status == FJ.STARTED
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and [w.id for w in verdict.removed] == [events[1]["id"]]
        assert "status=failed" in verdict.removed[0].message

    def test_the_journal_deleted(self, journald):
        _run(); _run()
        FJ.path().unlink()
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and len(verdict.removed) == 4

    def test_an_entry_removed_from_the_middle_and_rechained(self, journald):
        _run(); _run(); _run()
        events = _events()
        _rewrite(events[:2] + events[4:])
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and [w.id for w in verdict.removed] == _ids(events[2:4])

    def test_a_witness_forged_as_root_beside_the_real_one(self, journald):
        _run()
        events = _events()
        events[1]["status"] = "failed"
        _rewrite(events)
        forged = W.Witness(kind="result", id=events[1]["id"], digest=FJ._digest(FJ._canonical(events[1])),
                           body=FJ.body_digest(events[1]), at=None, message="forged")
        verdict = _verify(journald + [forged])
        assert verdict.overall == "tampered" and verdict.conflicting == [events[1]["id"]]

    def test_the_witness_field_flipped_to_none(self, journald):
        """Claiming an entry was written without a system log changes its line."""
        _run()
        events = _events()
        events[0]["witness"] = "none"
        _rewrite(events)
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and verdict.differs == [events[0]["id"]]
        assert not verdict.no_witness

    def test_a_journal_root_does_not_own(self, journald, monkeypatch):
        _run()
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        verdict = _verify(journald)
        assert verdict.overall == "tampered" and verdict.foreign_owner


class TestNotAFalsification:
    def test_rotation_took_the_witness(self, journald):
        _run()
        verdict = _verify([], oldest=datetime.now(timezone.utc) + timedelta(days=1))
        assert verdict.overall == "intact" and verdict.witness_gone == _ids(_events())

    def test_written_without_a_system_log(self, journald, monkeypatch):
        monkeypatch.setattr(FJ, "_has_witness", lambda: False)
        _run()
        verdict = _verify([])
        assert verdict.overall == "intact" and verdict.no_witness == _ids(_events())

    def test_a_missing_witness_is_not_proof(self, journald):
        _run()
        verdict = _verify([])
        assert verdict.overall == "unproven" and verdict.not_shown == _ids(_events())

    def test_the_witness_unreadable(self, journald):
        _run()
        verdict = W.verify(witness=W.WitnessRead("unreadable"), append_only=None)
        assert verdict.overall == "unproven" and verdict.of_entry(FJ.load().entries[0]) == "unchecked"

    def test_an_interrupted_command_is_not_a_falsification(self, journald):
        """BOB killed mid-command: a start with no outcome, its witness only."""
        FJ.start(finding="f", message="m", command="ufw enable", how="shell")
        verdict = _verify(journald)
        assert verdict.overall == "intact" and FJ.load().entries[0].status == FJ.STARTED

    def test_append_only_taken_off(self, journald, monkeypatch):
        monkeypatch.setattr(FJ, "_set_append_only", lambda fd: True)
        _run()
        verdict = _verify(journald, append_only=False)
        assert verdict.overall == "unproven" and verdict.append_only_removed
        assert _verify(journald, append_only=True).overall == "intact"

    def test_append_only_never_possible_is_no_removal(self, journald, monkeypatch):
        monkeypatch.setattr(FJ, "_set_append_only", lambda fd: False)
        _run()
        assert not _verify(journald, append_only=False).append_only_removed


class TestReadingJournald:
    @pytest.fixture
    def store(self, tmp_path, monkeypatch):
        (tmp_path / "var" / "mid").mkdir(parents=True)
        (tmp_path / "var" / "mid" / "system.journal").write_text("")
        (tmp_path / "machine-id").write_text("mid\n")
        monkeypatch.setattr(W, "_MACHINE_ID", tmp_path / "machine-id")
        monkeypatch.setattr(W, "_JOURNAL_ROOTS", (tmp_path / "var", tmp_path / "run"))
        monkeypatch.setattr(W, "_oldest", lambda: None)
        return tmp_path

    def _answer(self, monkeypatch, records, rc=0):
        class P:
            returncode, stderr = rc, "boom"
            stdout = "\n".join(json.dumps(r) for r in records)
        monkeypatch.setattr(W, "_journalctl", lambda *a: P)

    def test_only_what_root_sent(self, store, monkeypatch):
        head = "run id=abcdef012345 sha256=" + "a" * 64 + " body=" + "d" * 64
        self._answer(monkeypatch, [
            {"_UID": "0", "MESSAGE": head + " status=ok", "__REALTIME_TIMESTAMP": "1795195240987013"},
            {"_UID": "1000", "MESSAGE": "run id=999999999999 sha256=" + "b" * 64 + " body=" + "d" * 64},
            {"_UID": "0", "MESSAGE": [ord(c) for c in "note id=111111111111 sha256=" + "c" * 64
                                      + " body=" + "d" * 64]},
            {"_UID": "0", "MESSAGE": "unrelated"},
        ])
        read = W.read_witness()
        assert read.state == "ok" and read.persistent and read.sealed is False
        assert [(w.kind, w.id) for w in read.items] == [("run", "abcdef012345"), ("note", "111111111111")]
        assert read.items[0].at.year == 2026

    def test_sealing_is_said(self, store, monkeypatch):
        (store / "var" / "mid" / "fss").write_text("")
        self._answer(monkeypatch, [])
        assert W.read_witness().sealed is True

    def test_volatile_is_said(self, store, monkeypatch):
        (store / "var" / "mid" / "system.journal").unlink()
        (store / "run" / "mid").mkdir(parents=True)
        (store / "run" / "mid" / "system.journal").write_text("")
        self._answer(monkeypatch, [])
        assert W.read_witness().persistent is False

    def test_no_journalctl(self, store, monkeypatch):
        def missing(*_a):
            raise FileNotFoundError
        monkeypatch.setattr(W, "_journalctl", missing)
        assert W.read_witness().state == "no_journald"

    def test_journalctl_failing(self, store, monkeypatch):
        self._answer(monkeypatch, [], rc=1)
        read = W.read_witness()
        assert read.state == "failed" and read.detail == "boom"

    def test_no_store(self, store, monkeypatch):
        (store / "var" / "mid" / "system.journal").unlink()
        self._answer(monkeypatch, [])
        assert W.read_witness().state == "no_store"

    def test_unreadable_is_not_a_failure(self, store, monkeypatch):
        """journalctl without the right exits 1: the reader lacks the right,
        journalctl did not fail."""
        self._answer(monkeypatch, [], rc=1)
        monkeypatch.setattr(W.os, "access", lambda *_a: False)
        assert W.read_witness().state == "unreadable"
