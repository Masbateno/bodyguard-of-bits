"""v0.43.0 — account names in colour in every wizard (asked by the user, 22 November 2026).

A name is marked in the text (bob/_names.py); the shared drawer draws it in
the accounts' colour; every text output strips the marks.
"""

from __future__ import annotations

import io
import sys

import pytest

from bob import _names, i18n, journals as J, team
from tests import test_v0430_team_screen as S


@pytest.fixture(autouse=True)
def _fake(monkeypatch):
    before = i18n.current_lang()
    i18n.init("en")
    monkeypatch.setitem(sys.modules, "curses", S._Curses)
    yield
    i18n.init(before)


def test_marks_are_cut_and_stripped():
    text = "by " + _names.mark("alice") + " and " + _names.cell("bob", 6) + "|"
    assert _names.plain(text) == "by alice and bob   |"
    assert _names.segments(text) == [("by ", None), ("alice", "name"), (" and ", None), ("bob", "name"), ("   |", None)]
    assert _names.plain("".join(p for p, _ in _names.segments("ice" + _names.CLOSE + " rest"))) == "ice rest"


def test_the_drawer_draws_a_name_in_its_own_colour():
    from bob.tui import fixlog as _fl
    scr = S._Screen([])
    body = [("", "body"), ("  done by " + _names.mark("alice"), "body"), ("  plain line", "body")]
    _fl._draw(scr, S._Curses, i18n.t, "title", body, (), False, 0, None, "")
    pieces = {text: attr for text, attr in scr.drawn}
    assert pieces["alice"] == S._Curses.A_BOLD and pieces["  done by "] == S._Curses.A_NORMAL
    assert all(_names.OPEN not in r and _names.CLOSE not in r for r in scr.rows.values())


def test_the_team_screen_colours_the_members(monkeypatch):
    decl = team.Declaration(master="alice", members={"m1": ["audit"], "m2": ["audit"]})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    scr = S.run(monkeypatch, S.ENTER, S.ESC, "q")
    bold = {text for text, attr in scr.drawn if attr == S._Curses.A_BOLD}
    # m1 sits under the cursor, drawn in the selection's colour like the rest
    # of its row; m2 and the master in the accounts' colour.
    assert "alice" in bold and "m2" in bold


def test_no_text_output_carries_a_mark(monkeypatch, capsys):
    J.append("team", "team", op="init", account="alice", attributes=[], digest="x")
    assert J.run(["show", "team"], i18n.t) == 0
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    monkeypatch.setattr("sys.stdin", io.StringIO("1\nq\n"))         # the declaration, then quit
    from bob import team_wizard
    team_wizard.run(i18n.t)
    out = capsys.readouterr().out
    assert "alice" in out and _names.OPEN not in out and _names.CLOSE not in out


def test_the_report_preview_colours_a_notes_author_and_never_shows_a_mark(monkeypatch, tmp_path):
    """Found by the user on the real screen (22 November 2026): the preview
    of --manage-logs has its own drawer, which printed ^Nalice^O."""
    import os
    from bob import annotations as A
    from bob import manage_logs as ml
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())
    monkeypatch.setattr(A, "operator", lambda: {"uid": 0, "login": "alice"})
    report = tmp_path / "bob_20261121_085012.log"
    report.write_text("report\n")
    A.add(report, "test de note")
    content = ml._frame("Notes (1)", ml._notes_body(report, i18n.t, True), 100)
    scr = S._Screen([])
    ml._draw_preview(scr, report, i18n.t, {}, content, 0, 20, (), "banner", "", False)
    assert not any(_names.OPEN in r or _names.CLOSE in r for r in scr.rows.values())
    assert any("alice: test de note" in r for r in scr.rows.values())
    assert ("alice", S._Curses.A_BOLD) in scr.drawn
