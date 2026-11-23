"""v0.43.0 — coming back to a screen, the selection stays on the entry just left.

Asked by the user (23 November 2026): --manage-team went back to its first
entry; the rule holds everywhere. Driven on the real screens (a fake curses
that records what each row was drawn with: the row under the cursor is the
reversed one, colours being off).
"""

from __future__ import annotations

import sys

import pytest

from bob import i18n, journals as J, team
from tests import test_v0430_team_screen as S


@pytest.fixture(autouse=True)
def _fake(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", S._Curses)
    yield
    i18n.init(before)


class _Rec(S._Screen):
    """Remembers, for each key read, the text of the row drawn reversed."""

    def __init__(self, keys):
        super().__init__(keys)
        self.selected: "list[str]" = []
        self._now = ""

    def erase(self):
        super().erase()
        self._now = ""

    def addstr(self, row, col, text, attr=0):
        # the body only: the key banner at the bottom is reversed too
        if attr == S._Curses.A_REVERSE and row < 24 and text.strip():
            self._now = text.strip()
        super().addstr(row, col, text, attr)

    def getch(self):
        self.selected.append(self._now)
        return super().getch()


def run(monkeypatch, *items):
    from bob.tui import team as screen
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    scr = _Rec(S.keys(*items))
    assert screen.run(scr, None, i18n.t) == 0
    return scr


def test_back_on_the_landing_screen_the_choice_left_stays_selected(monkeypatch):
    scr = run(monkeypatch, "2", S.ESC, "q")
    assert "What is recorded" in scr.selected[-1]


def test_back_in_the_team_the_member_left_stays_selected(monkeypatch):
    monkeypatch.setattr(team, "_account_exists", lambda n: True)
    decl = team.Declaration(master="alice", members={"m1": [], "m2": [], "m3": []})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    # The list changes while away: on m3, add a0 (it sorts first) — coming
    # back, the selection is on a0, the entry just left, not on m3's old rank.
    monkeypatch.setattr(team, "candidate_accounts", lambda decl: ["a0"])
    scr = run(monkeypatch, S.ENTER, S.DOWN, S.DOWN, "n", S.ENTER, S.DOWN, " ", S.ENTER, S.ESC, S.ESC, "q")
    team_frames = [x for x in scr.selected if x.split()[1:2] in (["a0"], ["m1"], ["m2"], ["m3"])]
    assert team_frames[-1].split()[1] == "a0", team_frames


def test_manage_logs_landing_screen_too(monkeypatch):
    import bob.manage_logs as ml
    from bob.tui import fixlog as fl
    asked = []
    answers = iter(["fixes", "quit"])
    monkeypatch.setattr(ml, "_home", lambda stdscr, uc, config, t, cursor=0: asked.append(cursor) or next(answers))
    monkeypatch.setattr(fl, "run", lambda *a, **k: None)
    monkeypatch.setattr(ml, "_init_colors_ml", lambda: False)
    assert ml._run_manage_logs_curses(None, None, None, i18n.t) == 0
    assert asked == [0, 1]


def test_manage_logs_folder_list_too(monkeypatch, tmp_path):
    import bob.manage_logs as ml
    anchors = []
    homes = iter(["reports", "quit"])
    picks = iter([("select", tmp_path), ("quit", None)])
    monkeypatch.setattr(ml, "_home", lambda stdscr, uc, config, t, cursor=0: next(homes))
    monkeypatch.setattr(ml, "_dir_picker", lambda stdscr, uc, config, t, anchor=None: anchors.append(anchor) or next(picks))
    monkeypatch.setattr(ml, "_browse_dir", lambda *a, **k: None)
    assert ml._run_manage_logs_curses(None, None, None, i18n.t) == 0
    assert anchors == [None, tmp_path]
