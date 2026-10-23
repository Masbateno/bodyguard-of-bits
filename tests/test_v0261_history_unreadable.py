"""v0.26.1 — an unreadable history is not an empty one.

Found on a Mint host (0.26.0): ~/.config/bob/history.jsonl was root:root 0600,
56 KB, and `bob --history` run without sudo printed "No score history found —
run an audit first". history.py healed the file's mode on every write but its
owner only when it created it, so a file root once created stayed root's.
"""

from __future__ import annotations

import getpass
import json

import pytest

from bob import history as h
from bob import i18n


@pytest.fixture
def hist(monkeypatch, tmp_path):
    hf = tmp_path / "history.jsonl"
    monkeypatch.setattr(h, "_HISTORY_FILE", hf)
    monkeypatch.setattr(h, "_CONFIG_DIR", tmp_path)
    return hf


def _foreign(monkeypatch):
    """The file is another account's — root's, on the Mint host."""
    real = h.os.getuid()
    monkeypatch.setattr(h.os, "getuid", lambda: real + 1)


def _deny(monkeypatch):
    def refuse(*a, **k):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(h, "read_text_capped", refuse)


def test_an_unreadable_file_is_said_with_its_owner_and_mode(hist, monkeypatch, capsys):
    hist.write_text(json.dumps({"ts": "2026-10-20T14:47:56+00:00", "score": 9, "level": "low"}) + "\n")
    hist.chmod(0o600)
    _deny(monkeypatch)
    h.display_history(t=lambda k, **kw: f"{k}|{kw.get('owner')}|{kw.get('mode')}|{kw.get('error')}")
    out = capsys.readouterr().out
    assert "history.unreadable" in out and "history.no_entries" not in out
    assert f"|{getpass.getuser()}|0600|Permission denied" in out


def test_without_strict_it_still_reads_as_no_entries(hist, monkeypatch):
    hist.write_text("{}\n")
    _deny(monkeypatch)
    assert h.load_history() == []
    with pytest.raises(h.HistoryUnreadable):
        h.load_history(strict=True)


def test_a_missing_file_is_still_no_history(hist, capsys):
    h.display_history(t=lambda k, **kw: k)
    assert capsys.readouterr().out.strip() == "history.no_entries"


@pytest.mark.parametrize("lang, words", [("en", "cannot be read"), ("fr", "ne peut pas être lu")])
def test_the_text_renders(hist, monkeypatch, capsys, lang, words):
    hist.write_text("{}\n")
    _deny(monkeypatch)
    _foreign(monkeypatch)
    i18n.init(lang)
    try:
        h.display_history()
    finally:
        i18n.init(lang="en")
    out = capsys.readouterr().out
    assert words in out and str(hist) in out and "sudo bob" in out and "chown \"" not in out


def test_the_owner_is_healed_on_every_write(hist, monkeypatch):
    hist.write_text("")                       # exists already: 0.26.0 left it alone
    calls = []
    monkeypatch.setattr(h, "chown_fd_to_sudo_user", lambda fd, *a: calls.append(fd))
    h.save_score(9, "low")
    assert len(calls) == 1          # through the descriptor it opened (v0.26.1)


def test_on_a_doas_host_the_commands_say_doas(hist, monkeypatch, capsys):
    """After review: Alpine has doas and no sudo — the advice names doas."""
    from bob import _privilege
    hist.write_text("{}\n")
    _deny(monkeypatch)
    _foreign(monkeypatch)
    monkeypatch.setattr(_privilege, "privilege_prefix", lambda: "doas")
    i18n.init("en")
    h.display_history()
    out = capsys.readouterr().out
    assert "doas bob --history" in out and "doas bob gives" in out and "sudo" not in out


def test_under_doas_the_file_goes_back_to_doas_user(monkeypatch, tmp_path):
    """chown_to_sudo_user reads DOAS_USER as it reads SUDO_USER (0.25.1)."""
    import pwd
    from bob import sysinfo
    me = pwd.getpwuid(__import__("os").getuid()).pw_name
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("DOAS_USER", me)
    calls = []
    monkeypatch.setattr(sysinfo.os, "fchown", lambda fd, u, g: calls.append(u))
    f = tmp_path / "history.jsonl"; f.write_text("")
    sysinfo.chown_to_sudo_user(f)
    assert calls == [__import__("os").getuid()]


class TestTheChownAdviceIsForWhatItFixes:
    """After review: the hand-back is said only for a regular file owned by
    another account, on its own line — and, round 12, without a chown command:
    typed with sudo it would resolve the path again, through any link."""

    def _lines(self, monkeypatch):
        _deny(monkeypatch)
        i18n.init("en")
        return h.unreadable_lines("Permission denied")

    def test_a_foreign_regular_file_gets_it_on_its_own_line(self, hist, monkeypatch):
        hist.write_text("{}\n")
        _foreign(monkeypatch)
        lines = self._lines(monkeypatch)
        assert len(lines) == 2 and "gives it back" in lines[1]
        assert 'chown "$USER"' not in "".join(lines)   # round 12: no path-based chown as root

    def test_a_link_does_not(self, hist, monkeypatch, tmp_path):
        target = tmp_path / "elsewhere.jsonl"; target.write_text("{}\n")
        hist.symlink_to(target)
        _foreign(monkeypatch)
        lines = self._lines(monkeypatch)
        assert len(lines) == 1 and "chown" not in lines[0]

    def test_a_file_already_yours_does_not(self, hist, monkeypatch):
        hist.write_text("{}\n")
        lines = self._lines(monkeypatch)
        assert len(lines) == 1 and "sudo bob --history" in lines[0]
