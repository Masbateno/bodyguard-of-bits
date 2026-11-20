"""v0.40.0 — ``--fix --apply`` writes its journal (B-031), the loop itself.

Decided with the user (19 and 20 November 2026): every command launched
leaves an entry, whatever came of it; no command runs without one. The entry
is written before the command starts and completed after, so a command during
which BOB dies still shows. A command the operator declines, or one BOB
refuses to run (shell operators), is not launched and leaves none.

The conftest sends the journal to a directory of the test's own.
"""

from __future__ import annotations

import os

import pytest

from bob import fix_journal as FJ
from bob import fixes, i18n
from bob.cli import AuditConfig
from bob.scoring import Finding, FindingLevel, ScoreEngine


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _engine(*cmds, key="ssh.root_login", action=None):
    engine = ScoreEngine()
    for cmd in cmds:
        engine.findings.append(Finding(level=FindingLevel.ALERT, message=f"about {cmd}", nature="action",
                                       cmd=cmd, key=key, fix_action=action))
    return engine


def _apply(engine, monkeypatch, answers=None, run=None):
    calls = []

    def fake_run(argv, timeout):
        calls.append(argv)
        return run(argv) if run else ("ok", 0, b"")
    monkeypatch.setattr(fixes, "_run_fix_command", fake_run)
    # `ufw enable` is read back with `sudo -n ufw status`: never asked of the
    # host (the suite's sudo spy caught it).
    monkeypatch.setattr(fixes, "_ufw_read_back", lambda argv: True)
    if answers is not None:
        it = iter(answers)
        monkeypatch.setattr(fixes, "safe_input", lambda _p: next(it))
    fixes.run_fixes(engine, AuditConfig(fix=True, apply=True, yes=answers is None), i18n.t)
    return calls


class TestEveryCommandLaunched:
    def test_one_entry_each_whatever_came_of_it(self, monkeypatch, capsys):
        outcomes = {"sudo ufw --force delete 2": ("ok", 0, b""),
                    "sudo apt-get install -y fail2ban": ("failed", 100, b"E: Unable to locate package"),
                    "sudo apt-get upgrade -y": ("timeout", None, b"")}
        _apply(_engine(*outcomes), monkeypatch, run=lambda argv: outcomes[" ".join(argv)])
        entries = FJ.load().entries
        assert {e.command: (e.status, e.rc) for e in entries} == {
            "sudo ufw --force delete 2": ("ok", 0),
            "sudo apt-get install -y fail2ban": ("failed", 100),
            "sudo apt-get upgrade -y": ("timeout", None)}
        failed = next(e for e in entries if e.status == "failed")
        assert failed.error == "E: Unable to locate package" and failed.finding == "ssh.root_login"
        assert all(e.how == "shell" and e.seconds is not None for e in entries)
        assert f"3 command(s) recorded in {FJ.path()}" in capsys.readouterr().out

    def test_written_before_the_command_starts(self, monkeypatch):
        seen = []

        def run(argv):
            seen.append([(e.command, e.status) for e in FJ.load().entries])
            return "ok", 0, b""
        _apply(_engine("sudo ufw --force enable"), monkeypatch, run=run)
        assert seen == [[("sudo ufw --force enable", FJ.STARTED)]]

    def test_a_command_that_could_not_start(self, monkeypatch):
        def run(argv):
            raise FileNotFoundError(2, "No such file or directory")
        _apply(_engine("sudo ufw --force enable"), monkeypatch, run=run)
        (entry,) = FJ.load().entries
        assert entry.status == "failed" and entry.error.startswith("FileNotFoundError")

    def test_native_says_so_and_what_ran(self, monkeypatch):
        action = {"kind": "sysctl", "param": "net.ipv4.ip_forward", "conf": "/etc/sysctl.d/99-hardening.conf"}
        monkeypatch.setattr(fixes, "_apply_native", lambda a: ("ok", 0, b""))
        _apply(_engine("sysctl -w net.ipv4.ip_forward=0 && echo ... | tee", action=action), monkeypatch)
        (entry,) = FJ.load().entries
        assert entry.how == "native" and entry.action == action and entry.status == "ok"


class TestNotLaunchedNoEntry:
    def test_declined(self, monkeypatch):
        calls = _apply(_engine("sudo ufw --force delete 1"), monkeypatch, answers=["n"])
        assert calls == [] and FJ.load().entries == []

    def test_shell_operators_refused(self, monkeypatch):
        calls = _apply(_engine("sudo ufw allow 22 && sudo ufw enable"), monkeypatch)
        assert calls == [] and FJ.load().entries == []

    def test_dry_run_writes_nothing(self, monkeypatch):
        fixes.run_fixes(_engine("sudo ufw --force delete 1"), AuditConfig(fix=True, apply=False), i18n.t)
        assert not FJ.path().exists()


class TestNoCommandWithoutItsEntry:
    def test_a_journal_that_cannot_be_written_stops_everything(self, monkeypatch, capsys):
        monkeypatch.setattr(FJ, "_JOURNAL_UID", os.geteuid() + 1)
        calls = _apply(_engine("sudo ufw --force delete 1", "sudo apt-get upgrade -y"), monkeypatch)
        out = capsys.readouterr().out
        assert calls == []
        assert "cannot be written: only root writes it. No command was run" in out

    def test_an_entry_that_cannot_be_started_stops_its_command(self, monkeypatch, capsys):
        def refuse(**_kw):
            raise OSError(28, "No space left on device")
        monkeypatch.setattr(FJ, "start", refuse)
        calls = _apply(_engine("sudo ufw --force delete 1"), monkeypatch)
        assert calls == []
        assert "not run — its entry could not be written to the journal: No space left on device" in (
            capsys.readouterr().out)

    def test_an_outcome_that_cannot_be_written_is_said(self, monkeypatch, capsys):
        def refuse(*_a, **_kw):
            raise OSError(28, "No space left on device")
        monkeypatch.setattr(FJ, "finish", refuse)
        calls = _apply(_engine("sudo ufw --force delete 1"), monkeypatch)
        out = capsys.readouterr().out
        assert len(calls) == 1 and "Applied" in out
        assert 'the entry will read "no outcome recorded"' in out     # never "interrupted": it ran
        assert FJ.load().entries[0].status == FJ.STARTED
