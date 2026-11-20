"""v0.39.0 — what the user found in --manage-logs and --manage-cron (19 November 2026).

* A purge asked for its reason, then its confirmation, and only then said the
  note did not exist; a withdrawal said it only after the confirmation. The
  selection is now read first, strictly: a missing number, or anything that is
  not a selection, is refused before anything else is asked.
* Several notes, or all of them, can be withdrawn or purged at once
  ("1,3", "2-5", "all" — the syntax the plain-text report list already used):
  one chained write, or one rewrite, for all of them, and nothing written when
  one number is wrong.
* A block's bar took the colour of each line's text; it keeps the frame's.
* Every deletion is confirmed, in one wording, on the context line:
  "<question>  Press y to confirm, any other key to cancel." --manage-cron's
  address book deleted without asking; its job list asked without saying how
  to answer; the plain-text report list deleted by number without asking.
"""

from __future__ import annotations

import json
import os
import re
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from bob import annotations as A
from bob import i18n
from bob.tui import _chrome, _keys
from tests.test_v0320_manage_logs_peer import _FakeCurses


class _EditCurses(_FakeCurses):
    """What a text field needs on top: Backspace."""
    KEY_BACKSPACE = 1008

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _journal_owner(monkeypatch):
    """The journal belongs to root; the suite does not run as root."""
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


@pytest.fixture
def report(tmp_path):
    r = tmp_path / "bob_20261119_100000.log"
    r.write_text("report\n", encoding="utf-8")
    return r


def _t(key, **kw):
    return i18n.t(key, **kw)


def _ml():
    import bob.manage_logs as ml
    return ml


# ---------------------------------------------------------------------------
# The selection
# ---------------------------------------------------------------------------

class TestTheSelectionIsStrict:
    @pytest.mark.parametrize("raw, expected", [
        ("3", [3]), ("1,3", [1, 3]), ("2-3", [2, 3]), (" ALL ", [1, 2, 3]),
        ("1, 2-3", [1, 2, 3]), ("3,1,3", [1, 3]),
    ])
    def test_the_forms_it_takes(self, raw, expected):
        assert _ml()._note_selection(raw, [1, 2, 3]) == expected

    @pytest.mark.parametrize("raw, missing", [("4", 4), ("1,7", 7), ("2-3,9", 9)])
    def test_a_number_with_no_note_is_refused(self, raw, missing):
        with pytest.raises(A.NoteError) as e:
            _ml()._note_selection(raw, [1, 2, 3])
        assert e.value.key == "no_note" and e.value.vars == {"number": missing}

    @pytest.mark.parametrize("raw", ["x", "1;2", "5-2", "", "-", "1-", "tout"])
    def test_what_is_not_a_selection_is_said_so(self, raw):
        with pytest.raises(A.NoteError) as e:
            _ml()._note_selection(raw, [1, 2, 3, 4, 5])
        assert e.value.key == "bad_selection"

    def test_nothing_left_to_act_on(self):
        with pytest.raises(A.NoteError) as e:
            _ml()._note_selection("all", [])
        assert e.value.key == "none_left"

    @pytest.mark.parametrize("raw, expected", [
        ("2-4", [2, 4]), ("1-20", [1, 2, 4, 9]), ("3-10", [4, 9]), ("1-999999999", [1, 2, 4, 9]),
    ])
    def test_a_range_takes_the_notes_there_are(self, raw, expected):
        """The user's report (19 November 2026): "2-4" over notes 1, 2 and 4
        said "no note 3"; a run of notes with holes had to go piece by piece."""
        assert _ml()._note_selection(raw, [1, 2, 4, 9]) == expected

    def test_a_range_with_no_note_in_it_is_refused(self):
        with pytest.raises(A.NoteError) as e:
            _ml()._note_selection("5-8", [1, 2, 4, 9])
        assert e.value.key == "empty_range" and e.value.vars == {"low": 5, "high": 8}


# ---------------------------------------------------------------------------
# The journal: several notes at once
# ---------------------------------------------------------------------------

class TestSeveralNotesAtOnce:
    def test_withdrawn_together_and_chained(self, report):
        for text in ("one", "two", "three"):
            A.add(report, text)
        j = A.withdraw_many(report, [1, 3])
        assert [n.number for n in j.active] == [2]
        assert j.intact and [e["op"] for e in j.events] == ["add"] * 3 + ["withdraw"] * 2

    def test_one_wrong_number_withdraws_nothing(self, report):
        A.add(report, "one")
        before = A.note_path(report).read_bytes()
        with pytest.raises(A.NoteError) as e:
            A.withdraw_many(report, [1, 9])
        assert e.value.key == "no_note"
        assert A.note_path(report).read_bytes() == before

    def test_purged_together_text_and_salt_gone(self, report):
        for text in ("secret one", "secret two", "kept three"):
            A.add(report, text)
        A.withdraw(report, 2)                       # a withdrawn note can be purged
        j = A.purge_many(report, [1, 2], "pasted by mistake")
        raw = A.note_path(report).read_text(encoding="utf-8")
        assert "secret one" not in raw and "secret two" not in raw and "kept three" in raw
        assert j.intact
        assert [e["op"] for e in j.events].count("purge") == 2
        assert [n.number for n in j.notes if n.purged is not None] == [1, 2]
        for e in j.events:
            if e.get("id") in {j.notes[0].id, j.notes[1].id}:
                assert "salt" not in e

    def test_one_wrong_number_purges_nothing(self, report):
        A.add(report, "secret")
        before = A.note_path(report).read_bytes()
        with pytest.raises(A.NoteError):
            A.purge_many(report, [1, 9], "reason")
        assert A.note_path(report).read_bytes() == before


# ---------------------------------------------------------------------------
# The viewer's actions: what is asked, and when
# ---------------------------------------------------------------------------

class _Asked:
    """Stands in for the context line: answers in turn, remembers the prompts."""

    def __init__(self, monkeypatch, answers, confirm=True):
        self.prompts: "list[str]" = []
        self.questions: "list[str]" = []
        self._answers = list(answers)
        self._confirm = confirm
        ml = _ml()
        monkeypatch.setattr(ml, "_context_input", self._input)
        monkeypatch.setattr(ml, "_context_confirm", self._question)

    def _input(self, stdscr, t, actions, prompt, default=""):
        self.prompts.append(prompt)
        return self._answers.pop(0)

    def _question(self, stdscr, t, actions, question):
        self.questions.append(question)
        return self._confirm


class TestTheActionsAskInOrder:
    @pytest.mark.parametrize("action", [_keys.NOTE_PURGE, _keys.NOTE_WITHDRAW])
    def test_a_missing_note_is_refused_before_anything_else(self, monkeypatch, report, action):
        A.add(report, "one")
        asked = _Asked(monkeypatch, ["7"])
        status = _ml()._notes_action(None, report, _t, action)
        assert status.startswith("✖") and _t("manage_logs.note_err.no_note", number=7) in status
        assert len(asked.prompts) == 1 and asked.questions == []     # no reason, no confirmation

    def test_withdraw_all(self, monkeypatch, report):
        for text in ("one", "two", "three"):
            A.add(report, text)
        asked = _Asked(monkeypatch, ["all"])
        status = _ml()._notes_action(None, report, _t, _keys.NOTE_WITHDRAW)
        assert status.startswith("✔") and A.load(report).active == []
        assert asked.questions == [_t("manage_logs.note_confirm_withdraw_many", count=3, numbers="1, 2, 3")]

    def test_purge_several(self, monkeypatch, report):
        for text in ("secret one", "two", "secret three"):
            A.add(report, text)
        _Asked(monkeypatch, ["1,3", "pasted by mistake"])
        status = _ml()._notes_action(None, report, _t, _keys.NOTE_PURGE)
        assert status == _chrome.done(_t("manage_logs.note_purged_many", count=2, numbers="1, 3"))
        raw = A.note_path(report).read_text(encoding="utf-8")
        assert "secret" not in raw and '"two"' in raw

    def test_a_refused_confirmation_writes_nothing(self, monkeypatch, report):
        A.add(report, "one")
        before = A.note_path(report).read_bytes()
        _Asked(monkeypatch, ["1"], confirm=False)
        assert _ml()._notes_action(None, report, _t, _keys.NOTE_WITHDRAW).startswith("ℹ")
        assert A.note_path(report).read_bytes() == before


# ---------------------------------------------------------------------------
# A block's bar
# ---------------------------------------------------------------------------

class _Recorder:
    def __init__(self, h=30, w=90):
        self._h, self._w = h, w
        self.calls: "list[tuple[int, int, str, int]]" = []

    def getmaxyx(self):
        return self._h, self._w

    def erase(self):
        pass

    def refresh(self):
        pass

    def addstr(self, row, col, text, attr=0):
        self.calls.append((row, col, text, attr))

    def move(self, *_a):
        pass


class TestTheBarKeepsTheFramesColour:
    def test_body_and_warning_lines(self, monkeypatch):
        from bob.tui._palette import ACCENT
        monkeypatch.setitem(sys.modules, "curses", _FakeCurses)
        ml = _ml()
        content = ml._frame("Notes", [("a note", "body"), ("a warning", "warn")], 60)
        scr = _Recorder()
        ml._draw_preview(scr, Path("x"), _t, ml._new_view(), content, 0, 10,
                         ml._NOTES_KEYS, "  title", "", True)
        frame = _FakeCurses.color_pair(ACCENT) | _FakeCurses.A_BOLD
        bars = [c for c in scr.calls if c[1] == 0 and c[2] == ml._BAR]
        assert [c[3] for c in bars] == [frame, frame]          # both bars in the frame's colour
        texts = {c[2]: c[3] for c in scr.calls if c[1] == len(ml._BAR)}
        assert texts["a note"] == _FakeCurses.A_NORMAL
        assert texts["a warning"] != frame


# ---------------------------------------------------------------------------
# One way to confirm
# ---------------------------------------------------------------------------

class _KeyScreen(_Recorder):
    def __init__(self, keys):
        super().__init__()
        self._keys = list(keys)

    def getch(self):
        return self._keys.pop(0) if self._keys else 27

    def get_wch(self):
        return self.getch()


class TestOneWayToConfirm:
    @pytest.mark.parametrize("lang, expected", [
        ("en", "Delete x?  Press y to confirm, any other key to cancel."),
        ("fr", "Delete x?  Appuyez sur y pour confirmer, sur toute autre touche pour annuler."),
    ])
    def test_the_wording(self, lang, expected):
        i18n.init(lang)
        assert _chrome.confirm_text(_t, "Delete x?") == expected

    @pytest.mark.parametrize("key, answer", [(ord("y"), True), (ord("Y"), True),
                                             (ord("n"), False), (27, False), (10, False)])
    def test_y_confirms_any_other_key_cancels(self, monkeypatch, key, answer):
        class _Coloured(_FakeCurses):
            @staticmethod
            def has_colors():
                return True
        scr = _KeyScreen([key])
        assert _chrome.ask_confirm(scr, _Coloured, _t, "Delete x?") is answer
        h, w = scr.getmaxyx()
        rows = {row: (text, attr) for row, col, text, attr in scr.calls if col == 0}   # rows, not key caps
        text, attr = rows[_chrome.context_row(_t, _chrome.CONFIRM_ACTIONS, h, w)]
        assert text.strip() == _chrome.confirm_text(_t, "Delete x?")
        assert attr == _chrome.context_attr(_Coloured, True, _chrome.PROMPT)
        # Its banner announces y and nothing else: any other key only cancels.
        assert rows[h - 1][0].strip() == _keys.footer(_t, (_keys.CONFIRM,), w).strip()

    def test_no_confirmation_carries_its_own_instructions(self):
        """The instruction lives in one key; a question that spelled its own
        drifted ("y to confirm, any other key to cancel", "autre touche…")."""
        pattern = re.compile(r"y to confirm|y pour confirmer|any other key|autre touche", re.I)
        for lang in ("en", "fr"):
            data = json.loads((ROOT / f"bob/locales/{lang}.json").read_text(encoding="utf-8"))

            def walk(d, path=""):
                for k, v in d.items():
                    if isinstance(v, dict):
                        yield from walk(v, f"{path}{k}.")
                    elif isinstance(v, str) and pattern.search(v):
                        yield f"{path}{k}"
            assert list(walk(data)) == ["tui.confirm_suffix"], lang

    def test_every_wizard_asks_in_the_shared_wording(self):
        ml = (ROOT / "bob/manage_logs.py").read_text(encoding="utf-8")
        cron = (ROOT / "bob/tui/cron.py").read_text(encoding="utf-8")
        assert "_ch.confirm_text(t, t('manage_logs.confirm_prompt'" in ml        # report list
        assert ml.count("_chrome.ask_confirm(stdscr, curses, t, ") == 2           # notes, folders
        assert "_chrome.confirm_text(t, t('tui.confirm_delete'" in cron          # job list
        assert cron.count("_chrome.ask_confirm(stdscr, _curses, t,") == 2        # address book, overwrite
        assert not re.search(r"getch\(\) in \(ord\(\"y\"\)", ml + cron)

    def test_the_plain_report_list_says_which_number_is_missing(self, tmp_path, capsys):
        """v0.39.0 (bob/selection.py) — "1,7" over one report chose the first
        and dropped the seventh without a word."""
        from unittest.mock import patch
        from tests.test_manage_logs import _make_config, _make_log, _make_user_config
        log = _make_log(tmp_path, "bob_2026-01-01.log")
        uc, _ = _make_user_config(str(tmp_path))
        with patch("builtins.input", side_effect=iter(["1,7", "q"])):
            _ml().run_manage_logs(uc, _make_config(), _t)
        assert log.exists()
        assert _t("selection.missing", number=7) in capsys.readouterr().out

    @pytest.mark.parametrize("answer, kept", [("n", True), ("", True), ("y", False)])
    def test_the_plain_report_list_confirms_a_deletion_by_number(self, tmp_path, answer, kept):
        from unittest.mock import patch
        from tests.test_manage_logs import _make_config, _make_log, _make_user_config
        log = _make_log(tmp_path, "bob_2026-01-01.log")
        uc, _ = _make_user_config(str(tmp_path))
        with patch("builtins.input", side_effect=iter(["1", answer, "q"])):
            _ml().run_manage_logs(uc, _make_config(), _t)
        assert log.exists() is kept


# ---------------------------------------------------------------------------
# --manage-cron's address book
# ---------------------------------------------------------------------------

class _Store:
    def __init__(self, emails):
        self.emails = list(emails)
        self.removed: "list[str]" = []

    def all(self):
        return list(self.emails)

    def remove(self, email):
        self.removed.append(email)
        self.emails.remove(email)


class TestTheAddressBookAsks:
    def _run(self, monkeypatch, keys, emails=("a@example.org", "b@example.org", "c@example.org")):
        import bob.config
        from bob.tui import cron
        store = _Store(list(emails))
        monkeypatch.setattr(bob.config.EmailStore, "load", classmethod(lambda cls: store))
        monkeypatch.setitem(sys.modules, "curses", _EditCurses)
        self.screen = _KeyScreen(keys)
        cron._curses_email_store_sub(self.screen, _t)
        return store

    def test_a_refusal_deletes_nothing(self, monkeypatch):
        # d, Enter keeps the number under the cursor, n refuses
        store = self._run(monkeypatch, [ord("d"), 10, ord("n"), 27])
        assert store.removed == []

    def test_y_deletes(self, monkeypatch):
        store = self._run(monkeypatch, [ord("d"), 10, ord("y"), 27])
        assert store.removed == ["a@example.org"]

    def test_the_addresses_are_numbered(self, monkeypatch):
        """v0.39.0 (user, 19 November 2026) — numbered, as the notes are."""
        self._run(monkeypatch, [27])
        drawn = [c[2] for c in self.screen.calls]
        assert any("1. a@example.org" in x for x in drawn) and any("3. c@example.org" in x for x in drawn)

    def test_deleted_by_their_numbers(self, monkeypatch):
        """d, the cursor's number erased, "2-3" typed, Enter, y."""
        store = self._run(monkeypatch, [ord("d"), 127, *map(ord, "2-3"), 10, ord("y"), 27])
        assert store.removed == ["c@example.org", "b@example.org"]

    def test_a_number_with_no_address_is_refused(self, monkeypatch):
        store = self._run(monkeypatch, [ord("d"), 127, ord("9"), 10, 27])
        assert store.removed == []
        drawn = [c[2] for c in self.screen.calls]
        assert any(_t("selection.missing", number=9) in x for x in drawn)


# ---------------------------------------------------------------------------
# --manage-cron's job list
# ---------------------------------------------------------------------------

class TestTheJobListByNumbers:
    """v0.39.0 (user, 19 November 2026) — numbered, and d takes numbers, as the
    notes and the address book do."""

    def _run(self, monkeypatch, keys):
        from bob.cron._parse import CronEntry
        from bob.tui import cron
        jobs = [CronEntry(name=n, schedule_expr="0 3 * * *", hour=3, minute=0,
                          script_path=Path(f"/nonexistent/bob-{n}"), cron_path=Path(f"/nonexistent/{n}"))
                for n in ("alpha", "beta", "gamma")]
        removed = []
        monkeypatch.setattr(cron, "list_installed_crons", lambda: [j for j in jobs if j.name not in removed])
        monkeypatch.setattr(cron, "remove_cron_job", lambda e: removed.append(e.name))
        monkeypatch.setitem(sys.modules, "curses", _EditCurses)
        self.screen = _KeyScreen(keys)
        cron._run_manage_cron_curses(self.screen, SimpleNamespace(lang="en"), _t)
        return removed

    def test_the_jobs_are_numbered(self, monkeypatch):
        self._run(monkeypatch, [ord("q")])
        drawn = " ".join(c[2] for c in self.screen.calls)
        assert "1. alpha" in drawn and "3. gamma" in drawn

    def test_deleted_by_their_numbers(self, monkeypatch):
        removed = self._run(monkeypatch, [ord("d"), 127, *map(ord, "2-3"), 10, ord("y"), ord("q")])
        assert removed == ["beta", "gamma"]

    def test_d_then_enter_deletes_the_job_under_the_cursor(self, monkeypatch):
        removed = self._run(monkeypatch, [ord("d"), 10, ord("y"), ord("q")])
        assert removed == ["alpha"]

    def test_a_number_with_no_job_is_refused(self, monkeypatch):
        removed = self._run(monkeypatch, [ord("d"), 127, ord("9"), 10, ord("q")])
        assert removed == []
        drawn = " ".join(c[2] for c in self.screen.calls)
        assert _t("selection.missing", number=9) in drawn
