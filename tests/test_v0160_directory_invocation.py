"""
v0.16.0 — `python3 bob` answered with a bare traceback.

Running the package *directory* as a script puts ``<repo>/bob`` at the head of
``sys.path`` and leaves its parent — where the package actually lives — off it
entirely, so ``from bob import __version__`` fails. The operator got:

    ModuleNotFoundError: No module named 'bob'

which says nothing about what to run instead. It bit the maintainer twice in
ten minutes, once masked by a stale editable-install ``.pth`` that made the
form work without sudo and fail under it — so the same command behaved
differently depending on privilege, for a reason unrelated to privilege.

The form is still unsupported. Only the message changed: BOB names what
happened and the two forms that work.

Two constraints shaped it and both are tested:

  - **The message is a hardcoded English string.** i18n lives in ``bob.i18n``,
    which is precisely what cannot be imported at that point. v0.9.1 shipped a
    bracketed-fallback key on a path with the same constraint and needed a
    hotfix.
  - **Only "no module named bob" is caught.** A missing third-party dependency
    raises ImportError too, and swallowing that would replace one unhelpful
    traceback with a wrong explanation.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


class TestTheDirectoryFormExplainsItself:

    def test_it_names_the_two_supported_forms(self):
        proc = subprocess.run(
            [sys.executable, "bob", "--version"],
            cwd=_ROOT, capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 3
        assert "Traceback" not in proc.stderr
        assert "python3 -m bob" in proc.stderr
        assert "sudo bob" in proc.stderr

    def test_the_supported_form_is_unaffected(self):
        """The polarity twin — the fix must not shadow a working invocation."""
        proc = subprocess.run(
            [sys.executable, "-m", "bob", "--version"],
            cwd=_ROOT, capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0
        assert "bob v" in proc.stdout


class TestTheHandlerStaysNarrow:

    def _handler(self) -> ast.Try:
        tree = ast.parse((_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Try):
                return node
        raise AssertionError("no module-level try/except around the bob import")

    def test_only_a_missing_bob_is_caught(self):
        """
        A missing third-party dependency raises ImportError too. Catching it
        here would tell the operator to change their invocation when the real
        problem is an incomplete install.
        """
        handler = self._handler()
        source = ast.dump(handler)
        assert "ModuleNotFoundError" in source, (
            "a bare `except ImportError` would swallow a missing dependency"
        )
        assert '_exc.name' in ast.unparse(handler), (
            "the handler must re-raise when the missing module is not 'bob'"
        )

    def test_the_message_needs_no_i18n(self):
        """bob.i18n is exactly what cannot be imported at this point."""
        handler = ast.unparse(self._handler())
        assert "i18n" not in handler
        assert "_t(" not in handler and 't("' not in handler
