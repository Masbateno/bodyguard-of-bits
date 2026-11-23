"""v0.43.0 — where the team perimeter is asked: the audit, --fix --apply, --manage-logs (B-045).

Each gate is driven through the code that carries the action out, not
through bob/team.py alone: a gate that is not on the path of the action
protects nothing (lesson of 0.42.0: measure the path too). The conftest sends
the declaration and the journals to directories of the test's own.
"""

from __future__ import annotations

import io
import os

import pytest

from bob import annotations as A
from bob import fixes, i18n, team
from bob import team_journal as TJ
from bob.cli import AuditConfig
from bob.scoring import Finding, FindingLevel, ScoreEngine
from bob.tui import _keys


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def _declare(**members):
    decl = team.Declaration(master="alice", members={k: list(v) for k, v in members.items()})
    TJ.append("team", op="init", account="alice", attributes=[], digest=team.write(decl))


def _act_as(monkeypatch, account, answer="n", tty=True):
    monkeypatch.setattr(team, "_actor", lambda: account)
    monkeypatch.setattr(team, "_interactive", lambda: tty)
    monkeypatch.setattr("sys.stdin", io.StringIO(answer + "\n"))


def _attempts():
    return [(e.data["action"], e.data["attribute"], e.data["outcome"])
            for e in TJ.load().events if e.kind == "attempt"]


# ---------------------------------------------------------------------------
# --fix --apply: one question per command outside the perimeter, -y or not
# ---------------------------------------------------------------------------

def _apply(monkeypatch, *keys, yes=True):
    engine = ScoreEngine()
    for i, key in enumerate(keys):
        engine.findings.append(Finding(level=FindingLevel.ALERT, message=f"m{i}", nature="action",
                                       cmd=f"sudo true {i}", key=key))
    ran = []
    monkeypatch.setattr(fixes, "_run_fix_command", lambda argv, timeout: ran.append(argv) or ("ok", 0, b""))
    monkeypatch.setattr(fixes, "_ufw_read_back", lambda argv: True)
    fixes.run_fixes(engine, AuditConfig(fix=True, apply=True, yes=yes), i18n.t)
    return ran


def test_yes_does_not_answer_the_perimeter_question(monkeypatch):
    _declare(dave=["audit", "fix:access_control"])
    _act_as(monkeypatch, "dave", answer="n")
    ran = _apply(monkeypatch, "ssh.password_auth", "auditd.not_installed", yes=True)
    assert ran == [["sudo", "true", "0"]]          # access_control ran, detection did not
    assert _attempts() == [("fix", "fix:detection", "abandoned")]


def test_a_fix_confirmed_outside_the_perimeter_runs_and_is_written(monkeypatch):
    _declare(dave=[])
    _act_as(monkeypatch, "dave", answer="y")
    assert _apply(monkeypatch, "auditd.not_installed") == [["sudo", "true", "0"]]
    assert _attempts() == [("fix", "fix:detection", "confirmed")]


def test_without_a_declaration_fix_apply_runs_as_before(monkeypatch):
    _act_as(monkeypatch, "dave", answer="n")
    assert _apply(monkeypatch, "auditd.not_installed") == [["sudo", "true", "0"]]
    assert not TJ.path().exists()


# ---------------------------------------------------------------------------
# The audit itself: asked before the machine modes redirect stdout
# ---------------------------------------------------------------------------

def _main(monkeypatch, *argv):
    import bob.__main__ as M
    monkeypatch.setattr(M, "require_root", lambda: None)
    started = []
    monkeypatch.setattr(M, "ServiceRegistry", type("R", (), {"load": staticmethod(
        lambda: started.append(1) or (_ for _ in ()).throw(SystemExit(99)))}))
    try:
        code = M._run(list(argv))
    except SystemExit as exc:
        code = exc.code
    return code, started


def test_an_audit_outside_the_perimeter_and_refused_does_not_start(monkeypatch):
    _declare(dave=["note"])
    _act_as(monkeypatch, "dave", answer="n")
    code, started = _main(monkeypatch, "--json")
    assert code == 0 and started == []
    assert _attempts() == [("audit", "audit", "abandoned")]


def test_an_audit_within_the_perimeter_starts_without_a_question(monkeypatch, capsys):
    _declare(dave=["audit"])
    _act_as(monkeypatch, "dave", answer="n")
    code, started = _main(monkeypatch, "--json")
    assert started == [1] and code == 99
    assert capsys.readouterr().err == "" and _attempts() == []


# ---------------------------------------------------------------------------
# --manage-logs: notes (one's own or another's), report deletion
# ---------------------------------------------------------------------------

@pytest.fixture
def report(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())
    r = tmp_path / "bob_20261122_100000.log"
    r.write_text("report\n", encoding="utf-8")
    return r


class _Screen:
    """The context line: answers in turn, the confirmations given by *confirm*."""

    def __init__(self, monkeypatch, answers, confirm):
        import bob.manage_logs as ml
        self.questions: "list[str]" = []
        self._answers, self._confirm = list(answers), list(confirm)
        monkeypatch.setattr(ml, "_context_input", lambda *a, **k: self._answers.pop(0))
        monkeypatch.setattr(ml, "_context_confirm", self._question)

    def _question(self, stdscr, t, actions, question):
        self.questions.append(question)
        return self._confirm.pop(0)


def _note_as(monkeypatch, report, author, text):
    monkeypatch.setattr(A, "operator", lambda: {"uid": 0, "login": author})
    A.add(report, text)


def test_adding_a_note_needs_note(monkeypatch, report):
    import bob.manage_logs as ml
    _declare(dave=["audit"])
    _act_as(monkeypatch, "dave")
    screen = _Screen(monkeypatch, ["hello"], confirm=[False])
    status = ml._notes_action(None, report, i18n.t, _keys.NOTE_ADD)
    assert status.startswith("ℹ") and A.load(report).active == []
    assert "\"note\"" in screen.questions[0]
    assert _attempts() == [("note_add", "note", "abandoned")]


def test_withdrawing_ones_own_note_needs_note_anothers_needs_note_autres(monkeypatch, report):
    import bob.manage_logs as ml
    _declare(dave=["note"])
    _note_as(monkeypatch, report, "dave", "mine")
    _note_as(monkeypatch, report, "alice", "hers")
    _act_as(monkeypatch, "dave")
    screen = _Screen(monkeypatch, ["1"], confirm=[True])
    assert ml._notes_action(None, report, i18n.t, _keys.NOTE_WITHDRAW).startswith("✔")
    assert len(screen.questions) == 1                      # the withdrawal's own, nothing more
    screen = _Screen(monkeypatch, ["2"], confirm=[True, False])
    assert ml._notes_action(None, report, i18n.t, _keys.NOTE_WITHDRAW).startswith("ℹ")
    assert "note-autres" in screen.questions[1]
    assert [n.number for n in A.load(report).active] == [2]
    assert _attempts() == [("note_withdraw", "note-autres", "abandoned")]


def test_purging_notes_needs_note_autres(monkeypatch, report):
    import bob.manage_logs as ml
    _declare(dave=["note"])
    _note_as(monkeypatch, report, "dave", "mine")
    _act_as(monkeypatch, "dave")
    _Screen(monkeypatch, ["1", "typo"], confirm=[True, False])
    assert ml._notes_action(None, report, i18n.t, _keys.NOTE_PURGE).startswith("ℹ")
    assert _attempts() == [("note_purge", "note-autres", "abandoned")]
