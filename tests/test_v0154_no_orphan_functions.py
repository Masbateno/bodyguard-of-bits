"""Every public function in bob/ must have a caller.

Third instance of the campaign's highest-yield pattern, "declared but never
consumed": a field parsed and never read (v0.15.3), locale keys defined and
never referenced (v0.15.3), and now module-level functions defined and never
called. Two were found — ``strip_rule_index`` in checks/_ufw.py, born without a
caller and never even exercised by a test, and ``print_port_detail`` in
output.py, unused since v0.1.0 and kept alive only by its own test.

Writing the sweep is easy; writing one that does not lie took three attempts,
and both mistakes are pinned below:

* an aliased import (``from bob._tty import read_line as _rl``) hides the real
  name unless BOTH the name and the alias are counted;
* a ``FunctionDef`` produces no ``ast.Name`` node, so the definition does not
  appear in the reference count — the threshold is ``>= 1``, not ``> 1``.
  Getting that wrong flagged every function called exactly once, which inflated
  the candidate list from 2 to 17.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _public_defs() -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    for path in sorted(ROOT.joinpath("bob").rglob("*.py")):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                out.setdefault(node.name, (str(path.relative_to(ROOT)), node.lineno))
    return out


def _references() -> tuple[dict[str, int], str]:
    refs: dict[str, int] = defaultdict(int)
    literals: list[str] = []
    for path in sorted(ROOT.joinpath("bob").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                refs[node.id] += 1
            elif isinstance(node, ast.Attribute):
                refs[node.attr] += 1
            elif isinstance(node, ast.alias):
                refs[node.name.split(".")[-1]] += 1      # the real name
                if node.asname:
                    refs[node.asname] += 1               # and the alias
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                literals.append(node.value)
    return refs, "\n".join(literals)


def orphans() -> list[str]:
    defs = _public_defs()
    refs, literals = _references()
    entry_points = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    found = []
    for name, (rel, line) in sorted(defs.items()):
        if refs[name] >= 1:
            continue
        if name in literals:          # called from code this module generates
            continue
        if f'"{name}"' in entry_points or f":{name}" in entry_points:
            continue                  # console_scripts entry point
        found.append(f"{rel}:{line} {name}")
    return found


class TestNoPublicFunctionIsOrphaned:
    def test_every_public_function_has_a_caller(self):
        found = orphans()
        assert not found, "public functions with no caller anywhere: " + ", ".join(found)

    def test_the_sweep_actually_sees_the_codebase(self):
        """A sweep that found nothing to check would pass forever."""
        assert len(_public_defs()) > 150

    def test_an_aliased_import_counts_as_a_call(self):
        """`from bob._tty import read_line as _rl` must not read as dead."""
        refs, _ = _references()
        assert refs["read_line"] >= 1

    def test_a_function_called_once_is_not_flagged(self):
        """The >1 threshold bug: a FunctionDef adds nothing to the counts, so
        a single call site is a real caller, not a self-reference."""
        refs, _ = _references()
        single = [n for n, (_, _) in _public_defs().items() if refs[n] == 1]
        assert single, "harness check: no singly-called function to verify against"
        assert not (set(single) & set(o.split()[-1] for o in orphans()))

    def test_generated_code_counts_as_a_call(self):
        """cron/_io.py writes a helper script that imports from bob."""
        _, literals = _references()
        assert "send_audit_log_as_html_email" in literals
