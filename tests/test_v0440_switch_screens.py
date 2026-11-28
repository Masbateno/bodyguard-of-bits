"""v0.44.0 — B-051: from any wizard to any other, without leaving BOB.

Asked by the user (23 November 2026); decided with the user (27 November
2026): F2 --manage-logs, F3 --manage-cron, F4 --manage-team, F5 --explain,
Ctrl+G a selector; switching replaces the wizard. Measured by the user: the
five keys reach curses locally, over ``ssh -t``, in tmux, and in tmux over ssh.

Screens are driven on a fake screen that RAISES when its keys run out — a fake
screen answering a default key looped forever on 20 November and took the
workstation down.
"""

from __future__ import annotations

import sys

import pytest

from bob import i18n
from bob.tui import _keys
from bob.tui import switch


class _Curses:
    A_BOLD, A_REVERSE, A_NORMAL, A_DIM, A_UNDERLINE = 1, 2, 0, 4, 8
    KEY_UP, KEY_DOWN, KEY_PPAGE, KEY_NPAGE, KEY_ENTER = 1001, 1002, 1003, 1004, 1005
    KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END, KEY_BACKSPACE, KEY_DC = 1006, 1007, 1008, 1009, 1010, 1011
    KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5 = 265, 266, 267, 268, 269
    COLOR_BLACK, COLOR_RED, COLOR_GREEN, COLOR_YELLOW = 0, 1, 2, 3
    COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE = 4, 5, 6, 7

    class error(Exception):
        pass

    @staticmethod
    def curs_set(_n):
        return 0

    @staticmethod
    def color_pair(n):
        return n << 8

    @staticmethod
    def has_colors():
        return False


class _KeysRanOut(BaseException):
    """BaseException, not Exception: the code under test catches Exception
    (bob/tui/cron.py's _read_key returns -1 on it), and a swallowed "keys ran
    out" let a field loop forever — measured on 27 November 2026, when a
    mutation's loop took the test run to its 8 GB memory cap."""


class _Screen:
    def __init__(self, keys):
        self._keys = list(keys)
        self.rows: "dict[int, str]" = {}

    def getmaxyx(self):
        return 30, 120

    def erase(self):
        self.rows.clear()

    clear = erase

    def addstr(self, row, col, text, attr=0):
        line = self.rows.get(row, "")
        self.rows[row] = line[:col].ljust(col) + text + line[col + len(text):]

    def addnstr(self, row, col, text, n, attr=0):
        self.addstr(row, col, text[:n], attr)

    def move(self, *_a):
        pass

    def clrtoeol(self):
        pass

    def keypad(self, *_a):
        pass

    def refresh(self):
        pass

    def getch(self):
        if not self._keys:
            raise _KeysRanOut("the screen asked for one key more than the test gave")
        return self._keys.pop(0)

    def get_wch(self):
        k = self.getch()
        return chr(k) if isinstance(k, int) and k < 256 else k

    def frame(self) -> str:
        return "\n".join(self.rows[k] for k in sorted(self.rows))


@pytest.fixture(autouse=True)
def _english(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", _Curses)
    yield
    i18n.init(before)


# --- the keys ------------------------------------------------------------------------

@pytest.mark.parametrize("ch, target", [(266, "logs"), (267, "cron"), (268, "team"),
                                        (269, "explain"), (7, None), ("\x07", None)])
def test_each_switch_key_names_its_screen(ch, target):
    assert _keys.switch_request(_Curses, ch) == (True, target)


@pytest.mark.parametrize("ch", [265, ord("g"), 27, 10])
def test_other_keys_switch_nothing(ch):
    assert _keys.switch_request(_Curses, ch) == (False, None)


def test_a_landing_screen_switches():
    with pytest.raises(_keys.SwitchScreen) as asked:
        _keys.resolve(_Curses, 268, _keys.NAVIGATION + _keys.LANDING_EXIT)
    assert asked.value.target == "team"


@pytest.mark.parametrize("ch", [266, 269, 7])
def test_a_screen_below_a_landing_one_ignores_them(ch):
    """The user, 27 November 2026: the switch keys on landing screens only."""
    assert _keys.resolve(_Curses, ch, _keys.NAVIGATION + _keys.NESTED_EXIT) is None


def test_a_screen_that_does_not_announce_them_ignores_them():
    """Only the keys a banner announces act (CONVENTIONS.md)."""
    assert _keys.resolve(_Curses, 266, _keys.NAVIGATION + (_keys.SELECT,)) is None
    assert _keys.resolve(_Curses, 7, (_keys.CONFIRM,)) is None


def test_only_landing_screens_announce_them():
    assert _keys.SCREENS in _keys.LANDING_EXIT and _keys.SCREENS not in _keys.NESTED_EXIT
    landing = " ".join(_keys.footer_lines(i18n.t, _keys.NAVIGATION + _keys.LANDING_EXIT, width=200))
    nested = " ".join(_keys.footer_lines(i18n.t, _keys.NAVIGATION + _keys.NESTED_EXIT, width=200))
    assert "F2-F5 ^G screens" in landing and "F2-F5" not in nested


# --- the switcher --------------------------------------------------------------------

def _run(monkeypatch, plan, first="logs", euid=0, logs=True):
    """switch.run with *plan*: per launch, what the wizard does (an int it ends
    with, or a target it switches to). Returns the screens launched."""
    launched = []
    plan = list(plan)

    def launch(target, *_a):
        launched.append(target)
        step = plan.pop(0)
        if isinstance(step, int):
            return step
        raise _keys.SwitchScreen(step)

    monkeypatch.setattr(switch.os, "geteuid", lambda: euid)
    monkeypatch.setattr(switch, "_logs_to_show", lambda uc: logs)
    said = []
    monkeypatch.setattr(switch, "said", lambda scr, t, target, why: said.append((target, why)))
    rc = switch.run(object(), first, {}, None, i18n.t, launch=launch)
    return rc, launched, said


def test_a_switch_key_opens_the_wizard_it_names(monkeypatch):
    rc, launched, said = _run(monkeypatch, ["team", "explain", 3])
    assert (rc, launched, said) == (3, ["logs", "team", "explain"], [])


def test_ctrl_g_opens_the_menu(monkeypatch):
    seen = []
    monkeypatch.setattr(switch, "hub", lambda scr, t, came_from, config=None: seen.append(came_from) or "cron")
    rc, launched, _said = _run(monkeypatch, [None, 0])
    assert launched == ["logs", "cron"] and seen == ["logs"]


def test_esc_on_a_landing_screen_opens_the_menu(monkeypatch):
    """The user, 27 November 2026: Esc on any wizard's first page — however it
    was opened — comes back to the menu of every wizard."""
    seen = []
    monkeypatch.setattr(switch, "hub", lambda scr, t, came_from, config=None: seen.append(came_from) or "explain")
    rc, launched, _said = _run(monkeypatch, ["hub", 0], first="team")
    assert launched == ["team", "explain"] and seen == ["team"]


def test_leaving_the_menu_leaves_bob(monkeypatch):
    monkeypatch.setattr(switch, "hub", lambda scr, t, came_from, config=None: None)
    rc, launched, _said = _run(monkeypatch, ["hub"], first="cron")
    assert (rc, launched) == (0, ["cron"])


def test_bob_tui_starts_on_the_menu(monkeypatch):
    monkeypatch.setattr(switch, "hub", lambda scr, t, came_from, config=None: "team" if came_from is None else None)
    rc, launched, _said = _run(monkeypatch, [0], first="hub")
    assert launched == ["team"]


def test_a_root_screen_is_refused_without_root_and_said(monkeypatch):
    rc, launched, said = _run(monkeypatch, ["logs", 0], first="explain", euid=1000)
    assert launched == ["explain", "explain"]
    assert said and said[0][0] == "logs" and "sudo bob --manage-logs" in said[0][1]


def test_team_and_explain_open_without_root(monkeypatch):
    rc, launched, said = _run(monkeypatch, ["team", "explain", 0], first="explain", euid=1000)
    assert (launched, said) == (["explain", "team", "explain"], [])


def test_the_reports_before_any_audit_are_said(monkeypatch):
    rc, launched, said = _run(monkeypatch, ["logs", 0], first="team", logs=False)
    assert launched == ["team", "team"] and said[0][0] == "logs"


# --- the menu (bob --bob-tui), key by key -------------------------------------------------

def test_the_menu_marks_the_wizard_just_left_and_picks_by_number():
    scr = _Screen([ord("3")])
    assert switch.hub(scr, i18n.t, "logs") == "team"
    frame = scr.frame()
    assert "bob --bob-tui" in frame and "F2  Reports and journals" in frame and "last opened" in frame


def test_the_menu_moves_from_the_wizard_just_left_and_selects():
    scr = _Screen([_Curses.KEY_DOWN, 10])
    assert switch.hub(scr, i18n.t, "cron") == "team"


def test_q_leaves_the_menu():
    assert switch.hub(_Screen([ord("q")]), i18n.t, "team") is None


def test_esc_in_the_menu_does_nothing_and_is_not_announced():
    """The user, 27 November 2026: Esc quitting the menu only repeated q."""
    scr = _Screen([27, ord("3")])
    assert switch.hub(scr, i18n.t, None) == "team"
    assert "Esc" not in scr.frame() and "q quit" in scr.frame()


def test_a_function_key_in_the_menu_opens_its_wizard():
    with pytest.raises(_keys.SwitchScreen) as asked:
        switch.hub(_Screen([_Curses.KEY_F5]), i18n.t, None)
    assert asked.value.target == "explain"


# --- Esc: the menu from a landing screen, back from any other -----------------------------

def test_landing_screens_announce_esc_as_the_menu():
    assert _keys.HOME in _keys.LANDING_EXIT and _keys.BACK not in _keys.LANDING_EXIT
    assert _keys.BACK in _keys.NESTED_EXIT and _keys.HOME not in _keys.NESTED_EXIT
    assert "Esc BOB menu" in " ".join(_keys.footer_lines(i18n.t, _keys.LANDING_EXIT, width=200))


def test_esc_on_a_landing_screen_raises_the_menu():
    with pytest.raises(_keys.SwitchScreen) as asked:
        _keys.resolve(_Curses, 27, _keys.NAVIGATION + _keys.LANDING_EXIT)
    assert asked.value.target == "hub"


def test_esc_below_a_landing_screen_still_goes_back():
    assert _keys.resolve(_Curses, 27, _keys.NAVIGATION + _keys.NESTED_EXIT) == _keys.BACK


# --- the option --------------------------------------------------------------------------

def test_the_option_is_read():
    from bob.cli import parse_args
    assert parse_args(["--bob-tui"]).bob_tui is True


def test_without_a_terminal_the_wizards_and_their_commands_are_listed(capsys, monkeypatch):
    from bob import __main__ as M
    monkeypatch.setattr(M.sys.stdin, "isatty", lambda: False, raising=False)

    def no_audit(*_a, **_k):                 # were --bob-tui ever lost, no audit runs
        raise AssertionError("an audit started")

    monkeypatch.setattr(M, "run_checks", no_audit)
    assert M.main(["--bob-tui", "--lang=en"]) == M.EXIT_OK
    out = capsys.readouterr().out
    assert "need a terminal" in out and "F4  The team (--manage-team)" in out


# --- a field being typed keeps them out (landing screens only) --------------------------

def test_a_switch_key_does_nothing_in_a_text_field():
    from bob import manage_logs as ml
    scr = _Screen([ord("a"), _Curses.KEY_F4, 7, ord("b"), 10])
    assert ml._curses_input(scr, 5, 80, "prompt", "", complete_paths=False) == "ab"


def test_the_cron_wizard_reads_a_switch_key_as_a_key():
    from bob.tui import cron
    assert cron._read_key(_Screen(["\x07"])) == 7


# --- colours and a clean screen, whichever screen comes first -----------------------------
#
# Found by the user (27 November 2026): `bob --bob-tui` came up in two greys —
# no wizard had set the colours yet (measured in a pty: no cyan background
# for the banner) — and switching left glitches behind.

class _ColourCurses(_Curses):
    """A terminal with colour, recording the pairs defined."""
    COLORS = 256
    pairs: "dict[int, tuple]" = {}

    @staticmethod
    def has_colors():
        return True

    @staticmethod
    def start_color():
        pass

    @staticmethod
    def use_default_colors():
        pass

    @classmethod
    def init_pair(cls, n, fg, bg):
        cls.pairs[n] = (fg, bg)


class _AttrScreen(_Screen):
    def __init__(self, keys):
        super().__init__(keys)
        self.pairs_drawn: "set[int]" = set()

    def addstr(self, row, col, text, attr=0):
        self.pairs_drawn.add(attr >> 8)
        super().addstr(row, col, text, attr)


@pytest.fixture
def colour(monkeypatch):
    from bob.tui import _palette
    _ColourCurses.pairs = {}
    monkeypatch.setitem(sys.modules, "curses", _ColourCurses)
    return _palette


@pytest.mark.parametrize("screen", ["hub", "said"])
def test_the_menu_and_a_refusal_draw_in_the_shared_colours(colour, screen):
    scr = _AttrScreen([ord("q")] if screen == "hub" else [27])  # q leaves the menu, Esc a refusal
    if screen == "hub":
        switch.hub(scr, i18n.t, None)
    else:
        switch.said(scr, i18n.t, "logs", "why")
    assert _ColourCurses.pairs.get(colour.BANNER) == (_Curses.COLOR_WHITE, _Curses.COLOR_CYAN)
    assert colour.BANNER in scr.pairs_drawn


def test_every_screen_opens_on_the_colours_and_a_cleared_screen(colour, monkeypatch):
    """Each screen the switcher opens — menu or wizard — starts from the shared
    chart (reset: --explain redefines one pair) and a full repaint."""
    events = []

    class Scr:
        def clear(self):
            events.append("clear")

    def pair(cls, n, fg, bg):
        if n == colour.BANNER:
            events.append("palette")

    monkeypatch.setattr(_ColourCurses, "init_pair", classmethod(pair))
    plan = ["team", 0]

    def launch(target, *_a):
        events.append(target)
        step = plan.pop(0)
        if isinstance(step, int):
            return step
        raise _keys.SwitchScreen(step)

    monkeypatch.setattr(switch.os, "geteuid", lambda: 0)
    assert switch.run(Scr(), "explain", {}, None, i18n.t, launch=launch) == 0
    assert events == ["clear", "palette", "explain", "clear", "palette", "team"]
