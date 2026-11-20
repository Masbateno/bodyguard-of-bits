"""v0.39.0 — the --manage-logs preview: blocks detached from the report.

Decided with the user (16-17 November 2026):

- above the report, in this order: notes, comparison with the previous
  report, history — each a block of its own, never part of the report;
- the notes open when the preview opens (if there are any), closable; closed,
  they come back only on the next opening of the preview;
- comparison and history closed at opening, each opened by its key; once
  open they stay open and follow ←/→, closed only on request;
- line numbers off at every opening, kept while ←/→, on the report's lines
  only (the whole log: the summary's lines are not consecutive);
- the companion files (notes, state) never listed, moved and deleted with
  their report.

--diff compares with one baseline rewritten by every audit; nothing kept the
state of the audit before an old report. Each -d report now gets
``<report>.state`` (its baseline and its history line): the comparison is with
the previous report of the same host in the directory, said as --diff says it;
a report without a state says so.
"""

from __future__ import annotations

import inspect
import json
import os

import pytest

from bob import annotations as A
from bob import compare as C
from bob import i18n
from bob.history import history_entry
from bob.tui import _keys
from bob.tui._chrome import done, info, refused
from tests.test_v0320_manage_logs_peer import ESC, R, L, _Screen, fake_curses  # noqa: F401


def _t(key, **kw):
    return i18n.t(key, **kw)


def _baseline(score, ports, keys, host="host-a", ts="2026-11-16T08:00:00+00:00"):
    return C.AuditBaseline(timestamp=ts, score=score, alert_count=0, warn_count=len(keys), info_count=0,
                           open_ports=ports, active_services=[], finding_keys=keys, deduction_total=10 - score,
                           hostname=host, sections=["firewall"])


def _report(d, stamp, host="host-a", score=7, ports=("22/tcp",), keys=(), state=True):
    r = d / f"bob_{stamp}.log"
    r.write_text(f"report {stamp}\nScore   : {score}/10\nline 3\n", encoding="utf-8")
    if state:
        C.save_report_state(r, _baseline(score, list(ports), list(keys), host), history_entry(score, "medium"))
    return r


@pytest.fixture(autouse=True)
def _journal_owner(monkeypatch):
    """The journal belongs to root; these tests run as their own account."""
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())


@pytest.fixture(autouse=True)
def _en():
    i18n.init("en")
    yield
    i18n.init("en")


class TestTheState:
    def test_it_holds_the_baseline_and_the_history_line(self, tmp_path):
        r = _report(tmp_path, "20261117_150000", score=6)
        raw = json.loads(C.state_path(r).read_text())
        assert raw["score"] == 6 and raw["history"]["score"] == 6 and raw["hostname"] == "host-a"
        base, line = C.load_report_state(r)
        assert base.score == 6 and line["score"] == 6
        assert os.stat(C.state_path(r)).st_mode & 0o777 == 0o600

    def test_the_audit_writes_it_beside_a_d_report(self):
        import bob.__main__ as main
        src = inspect.getsource(main)
        # v0.40.0 (B-032) — with the computation of the score beside them.
        assert ("save_report_state(report.path, curr_baseline, history_entry(**_history_args),\n"
                "                                  breakdown_state(engine))") in src
        assert "save_score(**_history_args)" in src

    def test_no_state_no_comparison_no_history(self, tmp_path):
        r = _report(tmp_path, "20261117_150000", state=False)
        assert C.comparison_lines(r, _t) == [_t("manage_logs.compare_no_state")]
        assert C.history_lines(r, _t) == [_t("manage_logs.history_no_state")]


class TestTheComparison:
    def test_it_is_with_the_previous_report_of_the_same_host(self, tmp_path):
        _report(tmp_path, "20261115_090000", score=5, ports=("22/tcp", "23/tcp"))
        _report(tmp_path, "20261116_090000", host="host-b", score=9)
        _report(tmp_path, "20261116_100000", state=False)
        r = _report(tmp_path, "20261117_150000", score=7)
        prev, base = C.previous_report(r, "host-a")
        assert prev.name == "bob_20261115_090000.log" and base.score == 5
        lines = C.comparison_lines(r, _t)
        assert lines[0] == _t("manage_logs.compare_with", name="bob_20261115_090000.log")
        assert any(_t("compare.port_closed", port="23/tcp") in x for x in lines)

    def test_it_says_what_diff_says(self, tmp_path):
        """The block is display_delta's own output, not a second wording."""
        _report(tmp_path, "20261115_090000", score=5, keys=["ssh.password_auth"])
        r = _report(tmp_path, "20261117_150000", score=7)
        sink = C._Lines()
        prev, _ = C.load_report_state(tmp_path / "bob_20261115_090000.log")
        curr, _ = C.load_report_state(r)
        C.display_delta(C.compute_delta(prev, curr), _t, sink)
        assert C.comparison_lines(r, _t)[1:] == sink.lines[1:]

    def test_the_first_report_has_none_before_it(self, tmp_path):
        r = _report(tmp_path, "20261117_150000")
        assert C.comparison_lines(r, _t) == [_t("manage_logs.compare_no_previous")]


class TestTheHistory:
    def test_it_holds_this_host_up_to_this_report(self, tmp_path):
        _report(tmp_path, "20261114_090000", score=4)
        _report(tmp_path, "20261115_090000", host="host-b", score=9)
        r = _report(tmp_path, "20261116_090000", score=6)
        _report(tmp_path, "20261117_090000", score=8)              # later: not in this report's history
        text = "\n".join(C.history_lines(r, _t))
        assert "4/10" in text and "6/10" in text and "9/10" not in text and "8/10" not in text


class TestTheCompanions:
    def _pair(self, tmp_path):
        r = _report(tmp_path, "20261117_150000")
        A.add(r, "note")
        return r

    def test_they_move_with_their_report(self, tmp_path):
        import bob.manage_logs as ml
        r = self._pair(tmp_path)
        dest = tmp_path / "archive"
        dest.mkdir()
        ml._move_report(r, dest)
        assert sorted(p.name for p in dest.iterdir()) == [r.name, r.name + ".note", r.name + ".state"]
        assert list(tmp_path.glob("bob_*")) == []
        assert A.load(dest / r.name).intact

    def test_they_are_deleted_with_their_report(self, tmp_path):
        import bob.manage_logs as ml
        r = self._pair(tmp_path)
        ml._unlink_report(r)
        assert list(tmp_path.glob("bob_*")) == []

    def test_they_are_never_listed(self, tmp_path):
        """Every list keeps bob_*.log: a companion is neither listed, counted
        as a report, nor opened as one."""
        import bob.manage_logs as ml
        self._pair(tmp_path)
        assert [p.name for p in tmp_path.glob("bob_*.log")] == ["bob_20261117_150000.log"]
        assert [p.name for p in C._reports_of(tmp_path)] == ["bob_20261117_150000.log"]
        src = inspect.getsource(ml)
        assert src.count('glob("bob_*.log")') >= 4 and 'e.name.endswith(".log")' in src


class TestTheView:
    def test_an_opened_preview_starts_notes_open_the_rest_closed(self):
        import bob.manage_logs as ml
        # v0.40.0 (B-032) — the breakdown closed too (decided with the user).
        assert ml._new_view() == {"mode": "full", "notes": True, "compare": False, "history": False,
                                  "breakdown": False, "numbers": False, "journal": False}

    def test_the_blocks_come_in_order_above_the_report(self, tmp_path):
        import bob.manage_logs as ml
        _report(tmp_path, "20261116_090000", score=5)
        r = _report(tmp_path, "20261117_150000")
        A.add(r, "a note")
        view = ml._new_view()
        view.update(compare=True, history=True)
        texts = [x for x, _ in ml._preview_content(r, _t, view, ["report line"], 80)]
        heads = [i for i, x in enumerate(texts) if x.startswith("┌─ ")]
        titles = [texts[i] for i in heads]
        assert [_t("manage_logs.block_notes", count=1) in titles[0],
                _t("manage_logs.block_compare") in titles[1],
                _t("manage_logs.block_history") in titles[2]] == [True, True, True]
        assert texts[-1] == "report line" and texts.index("report line") > heads[-1]

    def test_no_notes_no_notes_block(self, tmp_path):
        import bob.manage_logs as ml
        r = _report(tmp_path, "20261117_150000")
        assert ml._preview_content(r, _t, ml._new_view(), ["x"], 80) == [("x", "report")]

    def test_a_journal_not_owned_by_root_is_said(self, tmp_path, monkeypatch):
        import bob.manage_logs as ml
        r = _report(tmp_path, "20261117_150000")
        A.add(r, "x")
        monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid() + 1)
        texts = [x for x, _ in ml._preview_content(r, _t, ml._new_view(), [], 80)]
        assert any("not to root" in x for x in texts)
        assert not any(_t("manage_logs.note_intact", count=1) in x for x in texts)

    def test_unreadable_notes_are_said(self, tmp_path):
        import bob.manage_logs as ml
        r = _report(tmp_path, "20261117_150000")
        os.mkfifo(A.note_path(r))
        texts = [x for x, _ in ml._preview_content(r, _t, ml._new_view(), [], 80)]
        assert any("could not be read" in x for x in texts)

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_why_notes_are_unreadable_is_said_in_the_screen_s_language(self, tmp_path, lang):
        """Measured on the test Mint: a link at the journal's name showed as
        "les notes n'ont pas pu être lues : Too many levels of symbolic links"."""
        import bob.manage_logs as ml
        r = _report(tmp_path, "20261117_150000")
        A.note_path(r).symlink_to(tmp_path / "elsewhere")
        before = i18n.current_lang()
        i18n.init(lang)
        try:
            texts = [x for x, _ in ml._preview_content(r, _t, ml._new_view(), [], 200)]
            expected = _t("manage_logs.note_err.link")
        finally:
            i18n.init(before)
        assert any(expected in x for x in texts), texts
        assert not any("symbolic" in x for x in texts), texts

    def test_numbers_on_the_whole_log_only(self, tmp_path):
        import bob.manage_logs as ml
        r = _report(tmp_path, "20261117_150000")
        view = ml._new_view()
        view["numbers"] = True
        assert ml._preview_content(r, _t, view, ["a", "b"], 80) == [("1 │ a", "report"), ("2 │ b", "report")]
        view["mode"] = "summary"
        assert ml._preview_content(r, _t, view, ["a", "b"], 80) == [("a", "report"), ("b", "report")]

    def test_a_note_cannot_inject_terminal_escapes(self, tmp_path):
        import bob.manage_logs as ml
        r = _report(tmp_path, "20261117_150000")
        A.add(r, "x")
        raw = A.note_path(r).read_text().replace('"text":"x"', '"text":"\\u001b[2Jx"')
        A.note_path(r).write_text(raw)
        texts = [x for x, _ in ml._preview_content(r, _t, ml._new_view(), [], 80)]
        assert not any("\x1b" in x for x in texts)


class TestTheKeys:
    def test_numbers_are_offered_on_the_whole_log_only(self):
        import bob.manage_logs as ml
        assert _keys.NUMBERS in ml._preview_keys("full") and _keys.NUMBERS not in ml._preview_keys("summary")

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_notes_footer_fits(self, lang):
        import bob.manage_logs as ml
        i18n.init(lang)
        lines = _keys.footer_lines(i18n.t, ml._NOTES_KEYS, 78)
        assert len(lines) <= 2 and all(len(x) <= 78 for x in lines)
        assert not _keys.conflicts(ml._NOTES_KEYS)


class TestTheBlocksFollowTheArrows:
    """Run the preview itself on a fake screen: open the comparison, move to
    the older report — still open; close it — closed; Esc."""

    def _logs(self, tmp_path):
        a = _report(tmp_path, "20261115_090000", score=5)
        b = _report(tmp_path, "20261116_090000", score=6)
        c = _report(tmp_path, "20261117_090000", score=7)
        return [c, b, a]

    def _has(self, frame, text):
        return any(text in row for row in frame.values())

    def test_compare_stays_open_across_peers_and_closes_on_request(self, tmp_path, fake_curses):
        import bob.manage_logs as ml
        logs = self._logs(tmp_path)
        title = _t("manage_logs.block_compare")
        scr = _Screen([ord("c"), L, ord("c"), ESC], h=40, w=110)
        ml._curses_preview_log(scr, logs[0], i18n.t, logs)
        f0, f1, f2, f3 = scr.frames[:4]
        assert not self._has(f0, title)                    # closed at opening
        assert self._has(f1, title)                        # c opens it
        assert self._has(f2, title) and self._has(f2, logs[1].name)   # ← : still open, updated
        assert not self._has(f3, title)                    # c again closes it

    def test_closed_notes_stay_closed_across_peers(self, tmp_path, fake_curses):
        import bob.manage_logs as ml
        logs = self._logs(tmp_path)
        for r in logs:
            A.add(r, f"note on {r.name}")
        title = _t("manage_logs.block_notes", count=1)
        scr = _Screen([ord("n"), L, ESC], h=40, w=110)
        ml._curses_preview_log(scr, logs[0], i18n.t, logs)
        f0, f1, f2 = scr.frames[:3]
        assert self._has(f0, title) and not self._has(f1, title) and not self._has(f2, title)

    def test_the_next_opening_starts_over(self, tmp_path, fake_curses):
        import bob.manage_logs as ml
        logs = self._logs(tmp_path)
        A.add(logs[0], "a note")
        ml._curses_preview_log(_Screen([ord("n"), ord("c"), ESC], h=40, w=110), logs[0], i18n.t, logs)
        again = _Screen([ESC], h=40, w=110)
        ml._curses_preview_log(again, logs[0], i18n.t, logs)
        f = again.frames[0]
        assert self._has(f, _t("manage_logs.block_notes", count=1))
        assert not self._has(f, _t("manage_logs.block_compare"))


class TestTheNotesActions:
    """The notes' actions as the preview runs them, prompts answered."""

    def _run(self, monkeypatch, path, action, inputs, confirm=True):
        import bob.manage_logs as ml
        answers = list(inputs)
        monkeypatch.setattr(ml, "_context_input", lambda *a, **k: answers.pop(0))
        monkeypatch.setattr(ml, "_context_confirm", lambda *a, **k: confirm)
        return ml._notes_action(None, path, _t, action)

    def test_add_edit_withdraw_purge(self, tmp_path, monkeypatch):
        r = _report(tmp_path, "20261117_150000")
        assert self._run(monkeypatch, r, _keys.NOTE_ADD, ["first"]) == done(_t("manage_logs.note_added", number=1))
        assert self._run(monkeypatch, r, _keys.NOTE_EDIT, ["1", "second"]) == done(_t("manage_logs.note_edited_ok", number=1))
        assert self._run(monkeypatch, r, _keys.NOTE_WITHDRAW, ["1"]) == done(_t("manage_logs.note_withdrawn_ok", number=1))
        assert self._run(monkeypatch, r, _keys.NOTE_PURGE, ["1", "mistake"]) == done(_t("manage_logs.note_purged_ok", number=1))
        assert [e["op"] for e in A.load(r).events] == ["add", "edit", "withdraw", "purge"]

    def test_cancelled_or_refused_writes_nothing(self, tmp_path, monkeypatch):
        r = _report(tmp_path, "20261117_150000")
        A.add(r, "x")
        assert self._run(monkeypatch, r, _keys.NOTE_ADD, [None]) == info(_t("manage_logs.note_cancelled"))
        assert self._run(monkeypatch, r, _keys.NOTE_WITHDRAW, ["1"], confirm=False) == info(_t("manage_logs.note_cancelled"))
        out = self._run(monkeypatch, r, _keys.NOTE_PURGE, ["1", "  "])
        assert out == refused(_t("manage_logs.note_err.no_reason"))
        out = self._run(monkeypatch, r, _keys.NOTE_EDIT, ["9"])
        assert out == refused(_t("manage_logs.note_err.no_note", number=9))
        assert len(A.load(r).events) == 1
