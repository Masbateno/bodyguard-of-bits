"""v0.14.0 F/G — colour is resolved from the environment, not assumed.

Until v0.14.0 BOB emitted ANSI unconditionally: `bob --breakdown > out.txt`
wrote escape codes into the file, `bob | less` showed them raw, and
`bob --no-color --help` still printed bold headers because print_help
hardcoded its own escapes. `output.supports_color()` had existed since early
on — correct, and called from nowhere.

This wires it, with FORCE_COLOR as the escape hatch for anyone who relied on
the old behaviour (piping into `less -R`, capturing a coloured log).

Resolution order, first match wins:
    1. --no-color / --no-colour
    2. NO_COLOR      (any non-empty value; empty is ignored, per no-color.org)
    3. FORCE_COLOR   (any non-empty value)
    4. stdout.isatty()
"""

from __future__ import annotations

import ast
import importlib
import io
import pathlib
import re
import subprocess
import sys

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ANSI = re.compile(r"\033\[")


class _FakeStdout(io.StringIO):
    def __init__(self, tty: bool):
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _resolve(monkeypatch, *, tty: bool, no_color_flag: bool = False,
             env: dict[str, str] | None = None) -> bool:
    """Return True when colour ends up enabled."""
    for var in ("NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(var, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    import bob.output as o
    importlib.reload(o)
    monkeypatch.setattr(sys, "stdout", _FakeStdout(tty))
    o.init(no_color=no_color_flag)
    enabled = not o._no_color
    importlib.reload(o)
    return enabled


class TestColourPrecedence:

    @pytest.mark.parametrize("tty,flag,env,expected,why", [
        (True,  False, {},                                   True,
         "a terminal gets colour"),
        (False, False, {},                                   False,
         "a pipe must not receive escape codes — the v0.14.0 change"),
        (False, False, {"FORCE_COLOR": "1"},                 True,
         "FORCE_COLOR is the escape hatch for `bob | less -R`"),
        (True,  False, {"NO_COLOR": "1"},                    False,
         "NO_COLOR wins over a terminal"),
        (True,  False, {"NO_COLOR": ""},                     True,
         "an empty NO_COLOR is ignored, per no-color.org"),
        (False, False, {"FORCE_COLOR": ""},                  False,
         "an empty FORCE_COLOR is ignored too — symmetry"),
        (True,  False, {"NO_COLOR": "1", "FORCE_COLOR": "1"}, False,
         "NO_COLOR outranks FORCE_COLOR"),
        (True,  True,  {"FORCE_COLOR": "1"},                 False,
         "the explicit --no-color flag outranks everything"),
    ])
    def test_matrix(self, monkeypatch, tty, flag, env, expected, why):
        got = _resolve(monkeypatch, tty=tty, no_color_flag=flag, env=env)
        assert got is expected, why


class TestSupportsColorIsWired:

    def test_init_calls_supports_color(self):
        """The whole defect was a correct helper nobody called."""
        src = (_REPO_ROOT / "bob" / "output.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        init = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "init")
        called = {
            n.func.id for n in ast.walk(init)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        assert "supports_color" in called, (
            "output.init() must consult supports_color(); leaving the helper "
            "uncalled is the v0.13.x state this release fixes"
        )

    def test_supports_color_survives_a_detached_stdout(self, monkeypatch):
        class Detached:
            def isatty(self):
                raise ValueError("I/O operation on closed file")
        import bob.output as o
        monkeypatch.setattr(sys, "stdout", Detached())
        assert o.supports_color() is False


class TestHelpObeysTheColourDecision:
    """print_help hardcoded \\033[1m, so --no-color never reached it."""

    @staticmethod
    def _help(env: dict[str, str] | None = None, args: list[str] | None = None) -> str:
        import os
        e = {**os.environ}
        e.pop("NO_COLOR", None)
        e.pop("FORCE_COLOR", None)
        e.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "bob", *(args or []), "--help"],
            capture_output=True, text=True, cwd=_REPO_ROOT, env=e,
        ).stdout

    def test_help_is_plain_when_piped(self):
        assert not _ANSI.search(self._help())

    def test_help_is_coloured_when_forced(self):
        assert _ANSI.search(self._help({"FORCE_COLOR": "1"}))

    def test_no_color_flag_silences_help(self):
        assert not _ANSI.search(self._help({"FORCE_COLOR": "1"}, ["--no-color"]))

    def test_help_does_not_hardcode_escapes(self):
        """A literal escape in cli.py bypasses the whole resolution chain."""
        src = (_REPO_ROOT / "bob" / "cli.py").read_text(encoding="utf-8")
        offenders = [
            f"  cli.py:{i}" for i, line in enumerate(src.splitlines(), 1)
            if "\\033[" in line and not line.lstrip().startswith("#")
        ]
        assert not offenders, (
            "hardcoded ANSI escapes in bob/cli.py bypass --no-color / "
            "NO_COLOR / TTY detection:\n" + "\n".join(offenders)
        )
