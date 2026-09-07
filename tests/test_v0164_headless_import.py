"""`bob-core` must import on a machine with no curses, and nothing tests it.

Three modules state it in their own words — `bob/tui/_keys.py`, `_palette.py`
and `_chrome.py` "never import curses", resolving the constants against a
module handed in instead. Two more, `explain.py` and `manage_logs.py`, import
them at **module level** and say in a comment that this is safe *because of*
that. The Debian packaging splits `bob-core` from `bob-tui` on the same
assumption.

So it is load-bearing in three places, true today — and never exercised. Every
machine that runs this suite has curses, so the branch where it is absent does
not exist for the tests. One `import curses` at the top of `_keys.py` breaks a
packaging contract with the suite entirely green, which is the same shape as
"a pipe is not a TTY": the environment guarantees you do not test the case.

Driven in a subprocess with the import blocked. Monkeypatching
``builtins.__import__`` inside pytest would leak into every test that follows,
and a bench that damages its neighbours is not one to trust.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Modules whose docstrings promise they do not need curses.
_MUST_NOT_IMPORT_CURSES = (
    "bob/tui/_keys.py",
    "bob/tui/_palette.py",
    "bob/tui/_chrome.py",
)

#: Modules a headless build imports, directly or through the ones above.
_MUST_IMPORT_HEADLESS = (
    "bob.tui._keys", "bob.tui._palette", "bob.tui._chrome",
    "bob.explain", "bob.manage_logs", "bob.tui.cron",
    "bob.__main__", "bob.runner", "bob.display", "bob.json_output",
)

_BLOCKER = '''
import builtins, importlib, sys
_real = builtins.__import__
def _guard(name, *a, **k):
    if name.split(".")[0] in ("curses", "_curses"):
        raise ModuleNotFoundError("No module named " + repr(name) + " (headless build)")
    return _real(name, *a, **k)
for _m in [m for m in sys.modules if m.split(".")[0] in ("curses", "_curses")]:
    del sys.modules[_m]
builtins.__import__ = _guard
importlib.import_module(__TARGET__)
print("OK")
'''


@pytest.mark.parametrize("rel", _MUST_NOT_IMPORT_CURSES)
def test_the_module_does_not_import_curses_at_all(rel):
    """Static half: cheap, and it names the offending line."""
    tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names
                          if a.name.split(".")[0] in ("curses", "_curses")]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in ("curses", "_curses"):
                offenders.append(node.module)
    assert not offenders, (
        f"{rel} imports {offenders} — its docstring promises it does not, and "
        f"two modules import it at top level on the strength of that promise"
    )


@pytest.mark.parametrize("module", _MUST_IMPORT_HEADLESS)
def test_it_imports_with_curses_unavailable(module):
    """The half that matters: does a headless build actually start?"""
    proc = subprocess.run(
        [sys.executable, "-c", _BLOCKER.replace("__TARGET__", repr(module))],
        cwd=_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0 and "OK" in proc.stdout, (
        f"{module} cannot be imported without curses — bob-core would not "
        f"start on a machine that has none:\n{proc.stderr[-1200:]}"
    )


def test_the_blocker_actually_blocks():
    """A negative control: without it, this bench proves nothing.

    If the subprocess could import curses after all, every test above would
    pass on a machine that has it — which is every machine that runs them.
    """
    proc = subprocess.run(
        [sys.executable, "-c", _BLOCKER.replace("__TARGET__", repr("curses"))],
        cwd=_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode != 0, (
        "the harness imported curses despite blocking it — every headless "
        "assertion in this file is meaningless"
    )
    assert "headless build" in proc.stderr


def test_the_claim_is_still_written_down():
    """The guard exists because three modules make a promise in prose.

    If the promise is deleted the guard is arbitrary; if the guard is deleted
    the promise is unbacked. They are a pair.
    """
    for rel in _MUST_NOT_IMPORT_CURSES:
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert "never imports curses" in text, (
            f"{rel} no longer states the property this file guards — the promise "
            f"belongs in the module a maintainer edits, not only in the modules "
            f"that rely on it"
        )
