"""v0.43.0 — ``bob --manage-team``: the team, step by step (B-045).

Asked by the user (22 November 2026): a wizard offering everything the
commands do, what is recorded included. It is driven here through its menu,
and each step must leave exactly what the command leaves: same checks, same
traces.
"""

from __future__ import annotations

import io
import os
import pwd

import pytest

from bob import i18n, journals as J, team, team_wizard

ME = pwd.getpwuid(os.geteuid()).pw_name


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def drive(monkeypatch, *answers, actor="alice"):
    monkeypatch.setattr(team, "_actor", lambda: actor)
    monkeypatch.setattr(team, "_interactive", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO("".join(a + "\n" for a in answers)))
    assert team_wizard.run(i18n.t) == 0


def test_create_the_team_then_grant(monkeypatch, capsys):
    attrs = list(team.ATTRIBUTES)
    pick = f"{attrs.index('audit') + 1},{attrs.index('note') + 1}"
    # menu without a team: 1 show, 2 init, 3 journals, 4 read; with one: 1 show,
    # 2 grant, 3 revoke, 4 remove, 5 journals, 6 read
    drive(monkeypatch, "2", "2", ME, pick, "q")
    decl = team.load()
    assert decl.master == "alice" and decl.members[ME] == ["audit", "note"]
    assert [e.data["op"] for e in J.load("team").events] == ["init", "grant"]
    assert "Create the team" in capsys.readouterr().out


def test_remove_asks_first(monkeypatch):
    drive(monkeypatch, "2", "2", ME, "1", "4", "1", "n", "q")
    assert ME in team.load().members                     # refused: kept
    drive(monkeypatch, "4", "1", "y", "q")
    assert ME not in team.load().members


def test_what_is_recorded_is_set_from_the_wizard(monkeypatch):
    cats = list(J.CATEGORIES)
    drive(monkeypatch, "3", str(cats.index("config") + 1), "off", "q")
    assert J.load_settings().off == {"config"}
    [ev] = J.load("admin").events
    assert ev.kind == "journals" and ev.data["state"] == "off"


def test_a_member_using_the_wizard_meets_the_same_question(monkeypatch):
    decl = team.Declaration(master="alice", members={"dave": ["audit"]})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))
    drive(monkeypatch, "2", ME, "1", "n", "q", actor="dave")
    assert ME not in team.load().members
    assert [e.data["outcome"] for e in J.load("team").events if e.kind == "attempt"] == ["abandoned"]


def test_a_wrong_choice_is_said(monkeypatch, capsys):
    drive(monkeypatch, "9", "q")
    assert "Not a choice of this menu." in capsys.readouterr().out
