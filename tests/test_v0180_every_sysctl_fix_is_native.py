"""Every sysctl fix a check emits carries the native action.

`--fix --apply` refuses a command carrying `&&` or `|`, and every sysctl
one-liner carries both. v0.18.0 made those fixes applicable by pairing the
command with `fix_action`, through one helper, `sysctl_fix()`. A check that
builds the command alone — `cmd=sysctl_fix_cmd(...)` — still *shows* the right
advice, still passes every test about the advice, and is silently refused by
`--apply` again: the very defect the native path closed, back one call site at
a time with nothing to say so.

The count moved once already. The v0.18.0 commit said *thirteen* fixes carried
the pattern; there were fifteen distinct keys before it and fifteen after. So
this guard does not pin a number. It pins the rule.
"""

from __future__ import annotations

import ast
from pathlib import Path

_CHECKS = Path(__file__).resolve().parent.parent / "bob" / "checks"

# The command builder lives here, and sysctl_fix() is built on it.
_DEFINES_IT = {"_run.py"}

# `kernel_hardening._fix_cmd` returns the bare command for tests that assert
# on the advice text (test_v0171_advice_is_safe_to_apply_twice). No finding is
# built from it: `_fix()`, beside it, is what the check spreads.
_TEST_SEAMS = {("kernel_hardening.py", "_fix_cmd")}


def _bare_uses() -> list[str]:
    found = []
    for path in sorted(_CHECKS.rglob("*.py")):
        if path.name in _DEFINES_IT:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if (path.name, fn.name) in _TEST_SEAMS:
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "sysctl_fix_cmd"):
                    found.append(f"{path.relative_to(_CHECKS.parent.parent)}:"
                                 f"{node.lineno} in {fn.name}()")
    return found


def test_no_check_builds_a_sysctl_command_without_its_action():
    bare = _bare_uses()
    assert not bare, (
        "these build a sysctl command with no native action, so --apply will "
        "refuse them — spread **sysctl_fix(param) instead:\n  " + "\n  ".join(bare)
    )


def test_the_seam_really_is_unused_by_the_check():
    """The allowlisted helper must stay a test seam, not become a call site."""
    tree = ast.parse((_CHECKS / "kernel_hardening.py").read_text(encoding="utf-8"))
    callers = [
        fn.name for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef)
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "_fix_cmd"
    ]
    assert callers == [], f"_fix_cmd is now called by {callers}; it needs its action"


def test_the_checks_do_use_the_paired_helper():
    """The mirror: an empty scan would make the first test vacuous."""
    uses = sum(
        (p.read_text(encoding="utf-8").count("sysctl_fix(")
         + p.read_text(encoding="utf-8").count("**_fix("))
        for p in _CHECKS.rglob("*.py") if p.name not in _DEFINES_IT
    )
    assert uses >= 15
