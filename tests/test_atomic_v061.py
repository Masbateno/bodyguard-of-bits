"""Regression tests for bob/_atomic.py + v0.6.1 atomic-write contract enforcement.

I-1: cron install paths use atomic_write
I-5: history.jsonl created with mode 0o600 (not default umask 0o644)
I-6: ignore.yml writes go through atomic_write (not raw O_TRUNC)
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


class TestAtomicWritePublicAPI:
    def test_atomic_write_creates_file_with_mode(self, tmp_path):
        from bob._atomic import atomic_write
        target = tmp_path / "test.txt"
        atomic_write(target, "hello\n", mode=0o600)
        assert target.exists()
        assert target.read_text() == "hello\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_atomic_write_respects_explicit_mode(self, tmp_path):
        """Cron files need 0o640, scripts need 0o755 — mode= is required."""
        from bob._atomic import atomic_write
        cron_target = tmp_path / "cron-file"
        script_target = tmp_path / "script"
        atomic_write(cron_target, "0 3 * * * root /bin/true\n", mode=0o640)
        atomic_write(script_target, "#!/bin/bash\necho hi\n", mode=0o755)
        assert stat.S_IMODE(cron_target.stat().st_mode) == 0o640
        assert stat.S_IMODE(script_target.stat().st_mode) == 0o755

    def test_atomic_write_overwrites_atomically(self, tmp_path):
        """Write twice — final content is the second write, no garbage."""
        from bob._atomic import atomic_write
        target = tmp_path / "data.txt"
        atomic_write(target, "first\n", mode=0o600)
        atomic_write(target, "second\n", mode=0o600)
        assert target.read_text() == "second\n"

    def test_atomic_write_does_not_corrupt_on_failure(self, tmp_path, monkeypatch):
        """Simulate os.replace failure: original file content survives."""
        from bob._atomic import atomic_write
        from bob import _atomic
        target = tmp_path / "data.txt"
        atomic_write(target, "original\n", mode=0o600)
        original_text = target.read_text()

        def boom(*args, **kwargs):
            raise OSError("simulated rename failure")

        monkeypatch.setattr(_atomic.os, "replace", boom)
        with pytest.raises(OSError, match="simulated"):
            atomic_write(target, "new content\n", mode=0o600)
        assert target.read_text() == original_text


class TestCronLegacyAliasStillWorks:
    """bob.cron._io._atomic_write must still be the public spy target for
    TestApplyCronScheduleAtomic regression tests."""

    def test_cron_io_atomic_write_aliases_bob_atomic(self):
        from bob.cron._io import _atomic_write
        from bob._atomic import atomic_write
        assert _atomic_write is atomic_write


class TestHistoryFileMode:
    """I-5 (v0.6.1): history.jsonl created with mode 0o600 on first write."""

    def test_history_file_created_with_0o600(self, tmp_path, monkeypatch):
        from bob import history
        history_file = tmp_path / "history.jsonl"
        monkeypatch.setattr(history, "_HISTORY_FILE", history_file)
        monkeypatch.setattr(history, "_CONFIG_DIR", tmp_path)
        history.save_score(8, "low")
        assert history_file.exists()
        assert stat.S_IMODE(history_file.stat().st_mode) == 0o600

    def test_history_file_mode_preserved_on_subsequent_writes(
        self, tmp_path, monkeypatch
    ):
        """After first creation at 0o600, subsequent appends don't change mode."""
        from bob import history
        history_file = tmp_path / "history.jsonl"
        monkeypatch.setattr(history, "_HISTORY_FILE", history_file)
        monkeypatch.setattr(history, "_CONFIG_DIR", tmp_path)
        history.save_score(8, "low")
        history.save_score(9, "low")
        assert stat.S_IMODE(history_file.stat().st_mode) == 0o600
        # Two lines written
        assert len(history_file.read_text().splitlines()) == 2


class TestIgnoreAtomic:
    """I-6 (v0.6.1): ignore.yml writes are atomic (tmp + replace)."""

    def test_ignore_write_creates_correct_content(self, tmp_path):
        from bob.ignore import add_ignore_key
        ignore_path = tmp_path / "ignore.yml"
        assert add_ignore_key("ssh.permit_root_login", path=ignore_path)
        assert "ssh.permit_root_login" in ignore_path.read_text()
        assert stat.S_IMODE(ignore_path.stat().st_mode) == 0o600

    def test_ignore_write_survives_simulated_replace_failure(
        self, tmp_path, monkeypatch
    ):
        from bob.ignore import add_ignore_key
        ignore_path = tmp_path / "ignore.yml"
        # First write succeeds
        assert add_ignore_key("key1.test", path=ignore_path)
        original_content = ignore_path.read_text()
        # Now break os.replace — ignore.yml content must survive
        from bob import _atomic
        monkeypatch.setattr(
            _atomic.os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError("boom"))
        )
        # The function swallows OSError and returns False
        assert add_ignore_key("key2.fail", path=ignore_path) is False
        assert ignore_path.read_text() == original_content


class TestSafeInput:
    """I-2 (v0.6.1): safe_input() returns '' on Ctrl-D instead of raising."""

    def test_safe_input_returns_empty_on_eof(self, monkeypatch):
        from bob._tty import safe_input
        def raise_eof(*a, **kw):
            raise EOFError
        monkeypatch.setattr("builtins.input", raise_eof)
        assert safe_input("prompt> ") == ""

    def test_safe_input_returns_value_on_normal_input(self, monkeypatch):
        from bob._tty import safe_input
        monkeypatch.setattr("builtins.input", lambda prompt="": "hello")
        assert safe_input("> ") == "hello"

    def test_prompt_wizard_returns_none_on_eof(self, monkeypatch):
        from bob._tty import prompt_wizard
        def raise_eof(*a, **kw):
            raise EOFError
        monkeypatch.setattr("builtins.input", raise_eof)
        assert prompt_wizard("> ") is None
