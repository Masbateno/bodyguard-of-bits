"""v0.43.0 — ``--manage-team`` on a full screen (B-045).

Asked by the user (22 November 2026): "a real wizard, like --manage-logs, not
a list of choices in the terminal the audit writes to". Driven key by key on
a fake screen that RAISES when its keys run out — a fake screen answering a
default key looped forever on 20 November and took the workstation down.
"""

from __future__ import annotations

import os
import pwd
import sys

import pytest

from bob import i18n, journals as J, team
from bob.tui import team as screen

ME = pwd.getpwuid(os.geteuid()).pw_name
ENTER, ESC, DOWN = 10, 27, 1002


class _Curses:
    A_BOLD, A_REVERSE, A_NORMAL, A_DIM, A_UNDERLINE = 1, 2, 0, 4, 8
    KEY_UP, KEY_DOWN, KEY_PPAGE, KEY_NPAGE, KEY_ENTER = 1001, 1002, 1003, 1004, 1005
    KEY_LEFT, KEY_RIGHT, KEY_HOME, KEY_END, KEY_BACKSPACE, KEY_DC = 1006, 1007, 1008, 1009, 1010, 1011
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


class _KeysRanOut(Exception):
    pass


class _Screen:
    def __init__(self, keys):
        self._keys = list(keys)
        self.rows: "dict[int, str]" = {}
        self.attrs: "dict[int, list]" = {}
        self.drawn: "list[tuple[str, int]]" = []
        self.frames: "list[str]" = []

    def getmaxyx(self):
        return 30, 120

    def erase(self):
        self.rows.clear()
        self.attrs.clear()

    clear = erase

    def addstr(self, row, col, text, attr=0):
        """Composed by column, as a terminal does: a line may be drawn in
        pieces (an account name in its own colour, v0.43.0)."""
        if 0 <= row < 30:
            line = self.rows.get(row, "")
            self.rows[row] = line[:col].ljust(col) + text + line[col + len(text):]
            self.attrs.setdefault(row, []).append((col, text, attr))
            self.drawn.append((text, attr))          # every piece ever drawn

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
        self.frames.append("\n".join(self.rows[k] for k in sorted(self.rows)))
        if not self._keys:
            raise _KeysRanOut("the screen asked for one key more than the test gave")
        return self._keys.pop(0)

    def get_wch(self):
        """As curses does: an ordinary key comes back as a character."""
        k = self.getch()
        return chr(k) if k < 256 else k


@pytest.fixture(autouse=True)
def _english(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", _Curses)
    yield
    i18n.init(before)


def keys(*items):
    out = []
    for item in items:
        out += [ord(c) for c in item] if isinstance(item, str) else [item]
    return out


def run(monkeypatch, *items, actor="alice"):
    monkeypatch.setattr(team, "_actor", lambda: actor)
    scr = _Screen(keys(*items))
    assert screen.run(scr, None, i18n.t) == 0
    return scr


def declare(**members):
    decl = team.Declaration(master="alice", members={k: list(v) for k, v in members.items()})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))


def test_create_the_team_on_the_screen(monkeypatch):
    scr = run(monkeypatch, ENTER, ENTER, "y", ESC, "q")
    assert team.load().master == "alice"
    assert any("No team declared" in f for f in scr.frames)


def test_add_a_member_with_its_attributes(monkeypatch):
    declare()
    run(monkeypatch, ENTER, "n", ME, ENTER, DOWN, " ", ENTER, ESC, ESC, "q")
    assert team.load().members[ME] == ["audit"]
    assert [e.data["op"] for e in J.load("team").events] == ["init", "grant"]


def test_outside_the_perimeter_the_question_is_asked_on_the_screen(monkeypatch, capsys):
    declare(dave=["audit"])
    scr = run(monkeypatch, ENTER, "n", ME, ENTER, DOWN, " ", ENTER, "n", ESC, ESC, "q", actor="dave")
    assert ME not in team.load().members
    assert [e.data["outcome"] for e in J.load("team").events if e.kind == "attempt"] == ["abandoned"]
    assert capsys.readouterr().err == ""                 # nothing written over the screen
    assert any("outside the perimeter declared for dave" in f for f in scr.frames)


def test_remove_a_member_after_confirmation(monkeypatch):
    declare(**{ME: ["audit"]})
    run(monkeypatch, ENTER, "d", "1", ENTER, "y", ESC, "q")
    assert ME not in team.load().members


def test_what_is_recorded_set_on_the_screen(monkeypatch):
    cats = list(J.CATEGORIES)
    moves = [DOWN] * (cats.index("config") + 1)          # the first row is "all categories"
    scr = run(monkeypatch, "2", *moves, " ", ENTER, ESC, "q")
    assert J.load_settings().off == {"config"}
    # Enter applied and the screen stayed: the frame after it is still this
    # screen, the box now read back unticked, the outcome said (asked by the
    # user: nothing leaves a screen but Esc).
    after = scr.frames[-2]
    assert "What is recorded" in after and "[ ] config" in after and "config: NOT recorded" in after
    assert [e.kind for e in J.load("admin").events] == ["journals"]


def test_without_a_terminal_the_menu_is_used(monkeypatch):
    import bob.__main__ as M
    from bob import team_wizard
    called = []
    monkeypatch.setattr(team_wizard, "run", lambda t: called.append(1) or 0)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert M._manage_team(None) == 0 and called == [1]


def test_a_refused_creation_creates_nothing(monkeypatch):
    run(monkeypatch, ENTER, ENTER, "x", ESC, "q")
    assert team.load() is None


def test_a_refused_removal_keeps_the_member(monkeypatch):
    declare(**{ME: ["audit"]})
    run(monkeypatch, ENTER, "d", "1", ENTER, "x", ESC, "q")
    assert team.load().members[ME] == ["audit"]


@pytest.mark.parametrize("answer, left", [("1,3", ["m2"]), ("1-2", ["m3"]), ("all", [])])
def test_members_are_numbered_and_removed_by_selection(monkeypatch, answer, left):
    monkeypatch.setattr(team, "_account_exists", lambda n: True)
    declare(m1=["audit"], m2=["audit"], m3=["audit"])
    scr = run(monkeypatch, ENTER, "d", answer, ENTER, "y", ESC, "q")
    assert sorted(team.load().members) == left
    assert any("   1  m1" in f and "   3  m3" in f for f in scr.frames)


def test_a_wrong_selection_is_said_and_removes_nothing(monkeypatch):
    declare(m1=["audit"])
    scr = run(monkeypatch, ENTER, "d", "7", ENTER, ESC, "q")
    assert team.load().members == {"m1": ["audit"]}
    assert any("✖" in f and "7" in f for f in scr.frames)   # said on the team's screen


def test_marked_members_are_removed_together(monkeypatch):
    monkeypatch.setattr(team, "_account_exists", lambda n: True)
    declare(m1=["audit"], m2=["audit"], m3=["audit"])
    scr = run(monkeypatch, ENTER, " ", DOWN, DOWN, " ", "d", "y", ESC, "q")
    assert sorted(team.load().members) == ["m2"]
    assert any(" ✓ 1  m1" in f for f in scr.frames)


def test_a_marks_all_and_u_unmarks(monkeypatch):
    monkeypatch.setattr(team, "_account_exists", lambda n: True)
    declare(m1=["audit"], m2=["audit"])
    run(monkeypatch, ENTER, "a", "u", " ", "d", "y", ESC, "q")
    assert sorted(team.load().members) == ["m2"]          # only the one marked after u
    declare(m1=["audit"], m2=["audit"])
    run(monkeypatch, ENTER, "a", "d", "y", ESC, "q")
    assert team.load().members == {}


def test_without_marks_d_asks_which_and_an_empty_answer_removes_nothing(monkeypatch):
    monkeypatch.setattr(team, "_account_exists", lambda n: True)
    declare(m1=["audit"], m2=["audit"])
    run(monkeypatch, ENTER, "d", ENTER, "d", "2", ENTER, "y", ESC, "q")
    assert sorted(team.load().members) == ["m1"]


def test_the_all_row_ticks_every_attribute_then_none(monkeypatch):
    """Asked by the user (23 November 2026): an "all" option at the top of a
    member's attributes."""
    monkeypatch.setattr(team, "_account_exists", lambda n: True)
    declare(m1=["audit"])
    scr = run(monkeypatch, ENTER, ENTER, " ", ENTER, ESC, ESC, "q")
    assert team.load().members["m1"] == list(team.ATTRIBUTES)
    assert any("[x] all attributes" in f for f in scr.frames)
    run(monkeypatch, ENTER, ENTER, " ", ENTER, ESC, ESC, "q")
    assert team.load().members["m1"] == []


def test_what_is_recorded_has_an_all_row_too(monkeypatch):
    """Asked by the user (23 November 2026)."""
    from bob import journals as J
    run(monkeypatch, "2", " ", ENTER, ESC, "q")              # every box ticked already: all off
    assert J.load_settings().off == set(J.CATEGORIES)
    scr = run(monkeypatch, "2", " ", ENTER, ESC, "q")        # and back on
    assert J.load_settings().off == set()
    assert any("[x] all categories" in f for f in scr.frames)
