"""v0.39.0 — a screen accepts exactly the keys it announces (user, 19 November 2026).

0.16.3 made every announced key work. The other half was missing: keys that
worked without being announced. Measured in the code before this release —
the schedule confirmation took Enter as yes and any other key as no, its banner
saying y and Esc; the job editor announced Enter and Esc and took the arrows,
jk, PgUp/PgDn, g/G and two digits (a digit acted only when the cursor already
stood on its entry); every numbered menu took its digits unannounced; the
address book took u without announcing it; the job list announced Enter and m
while entries were marked, when neither does anything; the report preview
announced n for a report with no notes; a text field in --manage-logs kept the
screen's banner (a e r p v, c d…), none of whose keys did anything while typing.

The guard is black-box: on each screen, every key it does not announce is
pressed alone, and the screen must stay exactly as it was — no move, no mark,
no redraw, no exit. What a screen announces is read from the same tuple of
actions its banner is drawn from (bob/tui/_keys.py: accepted()).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bob import i18n
from bob.tui import _keys
from tests.test_v0320_manage_logs_peer import _FakeCurses


class _Curses(_FakeCurses):
    KEY_BACKSPACE, KEY_HOME, KEY_END = 1008, 1009, 1010
    COLORS = 8

    @staticmethod
    def start_color():
        pass

    @staticmethod
    def use_default_colors():
        pass

    @staticmethod
    def init_pair(*_a):
        pass


#: Every key an operator could press by mistake: printable ASCII, the editing
#: and submit keys, and the special keys curses reports.
_PROBE = (list(range(32, 127)) + [8, 9, 10, 13, 127]
          + [_Curses.KEY_UP, _Curses.KEY_DOWN, _Curses.KEY_PPAGE, _Curses.KEY_NPAGE,
             _Curses.KEY_LEFT, _Curses.KEY_RIGHT, _Curses.KEY_ENTER, _Curses.KEY_BACKSPACE,
             _Curses.KEY_HOME, _Curses.KEY_END])
ESC = 27


class _OutOfKeys(Exception):
    """The screen kept reading after the last key the test gave it."""


class _Screen:
    """Records the whole screen each time a key is read."""

    def __init__(self, keys, h=24, w=110):
        self._h, self._w = h, w
        self._keys = list(keys)
        self.cells: "dict[tuple[int, int], str]" = {}
        self.frames: "list[dict]" = []

    def getmaxyx(self):
        return self._h, self._w

    def erase(self):
        self.cells.clear()

    def clrtoeol(self):
        pass

    def move(self, *_a):
        pass

    def refresh(self):
        pass

    def addstr(self, row, col, text, attr=0):
        if row < 0 or row >= self._h:
            raise _Curses.error("out of bounds")
        self.cells[(row, col)] = text

    def getch(self):
        self.frames.append(dict(self.cells))
        if self._keys:
            return self._keys.pop(0)
        # A screen still asking once its keys are spent is a screen that did not
        # let the test out: stop it rather than feed it Esc for ever (the first
        # version did, and the job list — which q leaves, not Esc — filled the
        # memory until the kernel killed the run).
        raise _OutOfKeys

    def get_wch(self):
        return self.getch()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", _Curses)
    yield
    i18n.init(before)


def _banner(frame, h=24, w=110) -> "list[str]":
    """The banner rows as drawn at the bottom of *frame*, top first."""
    rows = []
    for row in range(h - 1, h - 4, -1):
        text = frame.get((row, 0), "")
        if not text.strip():
            break
        rows.insert(0, text.strip())
    return rows


def _silent(run, actions, prefix=(), tail=(ESC, ESC, ESC)):
    """The screen draws the banner of *actions*, and each key *actions* does
    not announce leaves the screen as it was."""
    scr = _Screen(list(prefix) + list(tail))
    try:
        run(scr)
    except _OutOfKeys:
        pass
    drawn = _banner(scr.frames[len(prefix)])
    expected = [line.strip() for line in _keys.footer_lines(_t, actions, 110 - 2)]
    assert drawn[-len(expected):] == expected, (drawn, expected)
    accepted = _keys.accepted(_Curses, actions) | {ESC}
    loud = []
    for key in _PROBE:
        if key in accepted:
            continue
        scr = _Screen(list(prefix) + [key] + list(tail))
        try:
            run(scr)
        except _OutOfKeys:
            pass                      # judged on the frames below
        at = len(prefix)
        if len(scr.frames) < at + 2 or scr.frames[at] != scr.frames[at + 1]:
            loud.append(chr(key) if 32 <= key < 127 else key)
    assert loud == [], f"keys that act without being announced: {loud}"


def _t(key, **kw):
    return i18n.t(key, **kw)


def _entry(name="nightly"):
    from bob.cron._parse import CronEntry
    return CronEntry(name=name, schedule_expr="0 3 * * *", hour=3, minute=0,
                     script_path=Path(f"/nonexistent/bob-{name}"), cron_path=Path(f"/nonexistent/{name}"),
                     email="ops@example.org")


_CONFIG = SimpleNamespace(lang="en")


# ---------------------------------------------------------------------------
# --install-cron / --manage-cron
# ---------------------------------------------------------------------------

class TestTheCronScreens:
    def test_the_schedule_menu(self):
        from bob.tui import cron
        _silent(lambda s: cron._curses_schedule_wizard(s, _entry(), _CONFIG, _t), cron._SCHEDULE_KEYS)

    def test_the_schedule_confirmation_takes_y_and_esc_only(self):
        """Enter applied the schedule and any other key abandoned it."""
        from bob.tui import cron
        _silent(lambda s: cron._curses_schedule_wizard(s, _entry(), _CONFIG, _t),
                cron._CONFIRM_KEYS, prefix=(10, 10))        # daily, then the default time

    def test_the_job_editor(self):
        from bob.tui import cron
        _silent(lambda s: cron._curses_edit_sub(s, _entry(), _CONFIG, _t), cron._menu_keys(2))

    def test_a_numbered_menu_takes_its_own_digits_only(self):
        from bob.tui import cron
        _silent(lambda s: cron._curses_choice_screen(s, _t, "title", "prompt", ["a", "b", "c"], 0),
                cron._menu_keys(3))

    def test_the_address_book(self, monkeypatch):
        import bob.config
        from bob.tui import cron
        store = SimpleNamespace(all=lambda: ["a@example.org", "b@example.org"], remove=lambda e: None)
        monkeypatch.setattr(bob.config.EmailStore, "load", classmethod(lambda cls: store))
        _silent(lambda s: cron._curses_email_store_sub(s, _t), cron._STORE_KEYS)

    def test_the_address_book_with_addresses_marked(self, monkeypatch):
        """u acts once something is marked, and is announced then."""
        import bob.config
        from bob.tui import cron
        store = SimpleNamespace(all=lambda: ["a@example.org", "b@example.org"], remove=lambda e: None)
        monkeypatch.setattr(bob.config.EmailStore, "load", classmethod(lambda cls: store))
        _silent(lambda s: cron._curses_email_store_sub(s, _t), cron._with_unmark(cron._STORE_KEYS, 1),
                prefix=(ord(" "),))

    def test_the_job_list(self, monkeypatch):
        from bob.tui import cron
        monkeypatch.setattr(cron, "list_installed_crons", lambda: [_entry("a"), _entry("b")])
        _silent(lambda s: cron._run_manage_cron_curses(s, _CONFIG, _t), cron._manage_actions(0),
                tail=(ord("q"),))

    def test_the_job_list_with_entries_marked(self, monkeypatch):
        """Enter (edit one job) and m (address book) do nothing then: not announced."""
        from bob.tui import cron
        monkeypatch.setattr(cron, "list_installed_crons", lambda: [_entry("a"), _entry("b")])
        actions = cron._manage_actions(1)
        assert _keys.SELECT not in actions and _keys.BOOK not in actions and _keys.UNMARK in actions
        _silent(lambda s: cron._run_manage_cron_curses(s, _CONFIG, _t), actions,
                prefix=(ord(" "),), tail=(ord("q"),))


# ---------------------------------------------------------------------------
# --manage-logs
# ---------------------------------------------------------------------------

class TestTheReportPreview:
    @pytest.fixture
    def report(self, tmp_path):
        r = tmp_path / "bob_20261119_100000.log"
        r.write_text("line one\nscore 7/10\n", encoding="utf-8")
        return r

    def test_a_report_without_notes_does_not_announce_n(self, report):
        import bob.manage_logs as ml
        actions = ml._preview_keys("full", has_notes=False)
        assert _keys.NOTES not in actions
        _silent(lambda s: ml._curses_preview_log(s, report, _t, [report]), actions)

    def test_the_notes_actions(self, report):
        import bob.manage_logs as ml
        _silent(lambda s: ml._curses_preview_log(s, report, _t, [report]), ml._NOTES_KEYS,
                prefix=(ord("a"),))

    @pytest.mark.parametrize("name, keys", [("_INPUT_KEYS", (_keys.SUBMIT, _keys.BACK)),
                                            ("_PATH_INPUT_KEYS", (_keys.SUBMIT, _keys.COMPLETE, _keys.BACK))])
    def test_a_text_field_announces_its_own_keys(self, name, keys):
        """Enter, Esc — and Tab where it completes a path — over the field."""
        import bob.manage_logs as ml
        assert getattr(ml, name) == keys
        scr = _Screen(["\x1b"])               # a text field reads characters: Esc as one
        ml._context_input(scr, _t, ml._NOTES_KEYS, "prompt")
        h, w = scr.getmaxyx()
        assert scr.frames[0][(h - 1, 0)].strip() == _keys.footer(_t, ml._INPUT_KEYS, w).strip()
