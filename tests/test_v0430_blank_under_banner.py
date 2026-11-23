"""v0.43.0 — an empty row under the header banner, on every screen.

Asked by the user (23 November 2026): "establish the convention that an empty
line is left under the header banner everywhere". Every screen draws its body
from BODY_TOP (bob/tui/_chrome.py), scrolled or not. Each kind of drawer is
run on a fake screen that records its writes; nothing may land on row 1.
"""

from __future__ import annotations

import sys

import pytest

from bob import i18n
from bob.tui._chrome import BODY_TOP
from tests import test_v0430_team_screen as S


@pytest.fixture(autouse=True)
def _fake(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", S._Curses)
    yield
    i18n.init(before)


def rows_written(scr):
    return {row for row in scr.attrs}


def test_body_top_leaves_row_one_empty():
    assert BODY_TOP == 2


def test_the_shared_drawer():
    from bob.tui import fixlog as _fl
    scr = S._Screen([])
    _fl._draw(scr, S._Curses, i18n.t, "title", [("first line", "body"), ("second", "body")],
              (), False, 0, None, "")
    assert 1 not in rows_written(scr) and scr.rows[BODY_TOP].startswith("first line")


def test_the_shared_drawer_scrolled():
    from bob.tui import fixlog as _fl
    scr = S._Screen([])
    _fl._draw(scr, S._Curses, i18n.t, "title", [(f"line {i}", "body") for i in range(80)],
              (), False, 30, None, "")
    assert 1 not in rows_written(scr) and scr.rows[BODY_TOP].startswith("line 30")


def test_the_report_preview(tmp_path):
    from bob import manage_logs as ml
    scr = S._Screen([])
    ml._draw_preview(scr, tmp_path / "r.log", i18n.t, {}, [("report line", "report")], 0, 20, (), "banner", "", False)
    assert 1 not in rows_written(scr) and scr.rows[BODY_TOP].startswith("report line")


def test_the_explain_lists():
    from bob import explain
    scr = S._Screen([])
    explain._draw_rows(scr, S._Curses, [("a key", "key")], 0, 0, 10, 100, False)
    assert 1 not in rows_written(scr) and BODY_TOP in rows_written(scr)


def test_the_team_screen(monkeypatch):
    from bob import team, journals as J
    decl = team.Declaration(master="alice", members={"m1": ["audit"]})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    seen = set()

    class Rec(S._Screen):
        def addstr(self, row, col, text, attr=0):
            if text.strip():
                seen.add(row)
            super().addstr(row, col, text, attr)

    from bob.tui import team as screen
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    assert screen.run(Rec(S.keys(S.ENTER, S.ESC, "q")), None, i18n.t) == 0
    assert 1 not in seen and BODY_TOP in seen
