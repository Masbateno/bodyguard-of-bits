"""v0.43.0 — adding an account to the team: the host's login accounts listed (B-045).

Asked by the user (22 November 2026): BOB lists the existing accounts rather
than making one type a name it may then refuse. Listed: a UID in the
``UID_MIN``–``UID_MAX`` range of /etc/login.defs and a login shell; the
master and the members left out. Another name can still be typed; an
account absent from the host is refused with the command that creates it.
"""

from __future__ import annotations

import io
import os
import pwd
import sys
from types import SimpleNamespace

import pytest

from bob import i18n, journals as J, team, team_wizard
from tests import test_v0430_team_screen as S

ME = pwd.getpwuid(os.geteuid()).pw_name


def acct(name, uid, shell="/bin/bash"):
    return SimpleNamespace(pw_name=name, pw_uid=uid, pw_shell=shell)


@pytest.fixture(autouse=True)
def _host(monkeypatch, tmp_path):
    before = i18n.current_lang()
    i18n.init("en")
    defs = tmp_path / "login.defs"
    defs.write_text("UID_MIN 1000\nUID_MAX 60000\n")
    monkeypatch.setattr(team, "_LOGIN_DEFS", defs)
    monkeypatch.setattr(team, "_accounts", lambda: [
        acct("root", 0), acct("daemon", 1, "/usr/sbin/nologin"), acct("avahi", 110, "/bin/false"),
        acct(ME, 1000), acct("carol", 1001), acct("svc", 1002, "/usr/sbin/nologin"),
        acct("alice", 1003), acct("nobody", 65534, "/usr/sbin/nologin")])
    monkeypatch.setattr(team, "_account_exists", lambda n: n in {a.pw_name for a in team._accounts()})
    monkeypatch.setitem(sys.modules, "curses", S._Curses)
    yield
    i18n.init(before)


def test_the_range_is_read_from_login_defs(tmp_path):
    team._LOGIN_DEFS.write_text("# x\nUID_MIN\t500\nUID_MAX   2000\n")
    assert team.uid_range() == (500, 2000)


def test_without_login_defs_the_usual_range(tmp_path, monkeypatch):
    monkeypatch.setattr(team, "_LOGIN_DEFS", tmp_path / "absent")
    assert team.uid_range() == (1000, 60000)


def test_only_login_accounts_not_yet_declared_are_listed():
    decl = team.Declaration(master="alice", members={"carol": ["audit"]})
    assert team.candidate_accounts(decl) == [ME]
    assert team.candidate_accounts(None) == sorted([ME, "carol", "alice"])


def test_a_system_account_is_not_listed_even_with_a_shell():
    assert "root" not in team.candidate_accounts(None)


def _declare(**members):
    decl = team.Declaration(master="alice", members={k: list(v) for k, v in members.items()})
    J.append("team", "team", op="init", account="alice", attributes=[], digest=team.write(decl))


def test_the_screen_lists_them_and_adds_the_one_picked(monkeypatch):
    _declare()
    scr = S.run(monkeypatch, S.ENTER, "n", S.ENTER, S.DOWN, " ", S.ENTER, S.ESC, S.ESC, "q")
    first = sorted([ME, "carol"])[0]
    assert team.load().members[first] == ["audit"]
    assert any("Login accounts of this host not yet declared" in f for f in scr.frames)


def test_another_name_can_still_be_typed(monkeypatch):
    _declare()
    n = len(team.candidate_accounts(team.load()))
    S.run(monkeypatch, S.ENTER, "n", *([S.DOWN] * n), S.ENTER, "ghost", S.ENTER, S.ESC, S.ESC, "q")
    assert "ghost" not in team.load().members            # refused: no such account


def test_no_account_left_is_said_with_the_command(monkeypatch):
    _declare(**{ME: ["audit"], "carol": []})
    scr = S.run(monkeypatch, S.ENTER, "n", S.ESC, S.ESC, "q")
    assert any("sudo useradd -m NAME" in f for f in scr.frames)


def test_the_menu_takes_a_number(monkeypatch):
    _declare()
    names = team.candidate_accounts(team.load())
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    monkeypatch.setattr(team, "_interactive", lambda: True)
    attrs = list(team.ATTRIBUTES)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"2\n{names.index(ME) + 1}\n{attrs.index('audit') + 1}\nq\n"))
    assert team_wizard.run(i18n.t) == 0
    assert team.load().members[ME] == ["audit"]


def test_an_absent_account_is_refused_with_the_command_that_creates_it():
    _declare()
    with pytest.raises(team.TeamError) as err:
        team.command(["grant", "ghost", "audit"], i18n.t)
    assert "sudo useradd -m ghost" in i18n.t(f"team.err.{err.value.key}", **err.value.vars)


def test_several_accounts_marked_are_added_together(monkeypatch):
    _declare()
    names = team.candidate_accounts(team.load())           # [carol, ME] sorted
    scr = S.run(monkeypatch, S.ENTER, "n", " ", S.DOWN, " ", S.ENTER, S.DOWN, " ", S.ENTER, S.ESC, S.ESC, "q")
    decl = team.load()
    assert all(decl.members[n] == ["audit"] for n in names)
    assert any(" ✓ 1" in f for f in scr.frames)


def test_a_marks_every_account_and_u_unmarks(monkeypatch):
    _declare()
    names = team.candidate_accounts(team.load())
    S.run(monkeypatch, S.ENTER, "n", "a", "u", " ", S.ENTER, S.DOWN, " ", S.ENTER, S.ESC, S.ESC, "q")
    assert list(team.load().members) == [names[0]]          # only the one marked after u
    _declare()                                              # every account offered again
    S.run(monkeypatch, S.ENTER, "n", "a", S.ENTER, S.DOWN, " ", S.ENTER, S.ESC, S.ESC, "q")
    assert sorted(team.load().members) == sorted(names)


def test_for_several_an_attribute_held_by_one_only_is_not_taken(monkeypatch):
    _declare(carol=["audit", "note"])
    monkeypatch.setattr(team, "_actor", lambda: "alice")
    from bob.tui import team as T
    # ME (none) and carol (audit, note) together: the common set is empty;
    # ticking nothing and applying must leave carol's attributes alone.
    shown = []
    monkeypatch.setattr(T, "_checks", lambda stdscr, curses, t, hc, title, items, load, apply, *a, **k:
                        shown.append((load(), apply(set()))))
    T._member(None, S._Curses, i18n.t, False, ["carol", ME])
    assert shown[0][0] == set()
    assert team.load().members["carol"] == ["audit", "note"]
