"""
v0.16.0 — `bob -q -d` wrote a 440-line report with no summary block.

`-q` is about stdout. `-d` is a file the operator explicitly asked for. The two
are orthogonal, and this module already states the rule:

    all ``print_*`` calls are gated by ``config.quiet`` so ``bob -q`` produces
    empty stdout. ``report.write_*`` calls always run so the .log file
    remains complete.

The rule was honoured inside `display_log_results` and defeated one level up:
`print_audit_summary` — which is what writes the summary *to the report* — sat
inside `if not config.quiet:` at the call site. So the archived report had
every section, then stopped: no score, no risk level, no counts.

The gate now lives where that sentence says it does. Two things must hold at
once, so both are tested: stdout stays empty under `-q`, and the report keeps
its summary.

**Found while fixing it, and worth its own guard:** re-indenting the print
region swallowed `_compute_posture_annotation`, whose result `write_summary`
consumes two lines later. Under `-q` that raised UnboundLocalError and the
report lost its summary again — silently, which is how it would have shipped.
v0.8.3 was a hotfix for exactly this shape in `main()`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_DISPLAY = _ROOT / "bob" / "display.py"


def _function(name: str) -> ast.FunctionDef:
    tree = ast.parse(_DISPLAY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in display.py")


class TestTheReportKeepsItsSummaryUnderQuiet:

    def test_the_call_site_does_not_gate_the_whole_function(self):
        source = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        call = source.index("print_audit_summary(")
        before = source[:call].rsplit("\n", 12)[-1:]
        preceding = source[:call].splitlines()[-12:]
        gated = any(
            line.strip() == "if not config.quiet:" and
            all(l.strip().startswith("#") or not l.strip()
                for l in preceding[preceding.index(line) + 1:])
            for line in preceding if line.strip() == "if not config.quiet:"
        )
        assert not gated, (
            "print_audit_summary writes the report's summary block; gating the "
            "whole call on --quiet leaves `bob -q -d` with a report that stops "
            "before its conclusion"
        )

    def test_write_summary_is_reached_regardless_of_quiet(self):
        """The write must not sit under any `if ... quiet` in the function."""
        func = _function("print_audit_summary")
        for node in ast.walk(func):
            if not isinstance(node, ast.If):
                continue
            if "quiet" not in ast.dump(node.test):
                continue
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Attribute)
                        and inner.func.attr == "write_summary"):
                    raise AssertionError(
                        "report.write_summary() is inside a quiet-gated branch"
                    )


class TestNothingWriteSummaryNeedsIsDefinedOnlyWhenLoud:
    """The UnboundLocalError shape, caught statically.

    A name assigned only inside `if not quiet:` and read by the call to
    write_summary crashes the report under `-q`. It is invisible in a normal
    run and in every test that does not pass `-q`.
    """

    def test_no_argument_is_bound_only_inside_a_quiet_branch(self):
        func = _function("print_audit_summary")

        # Node identity, not a `continue`. A first version skipped the If node
        # and kept walking — but ast.walk yields descendants regardless, so
        # every name inside the quiet branch also landed in "outside" and the
        # guard cancelled itself out. It stayed green when the offending line
        # was put back, which is the failure mode it exists to prevent.
        inside_quiet: set[int] = set()
        for node in ast.walk(func):
            if isinstance(node, ast.If) and "quiet" in ast.dump(node.test):
                for inner in ast.walk(node):
                    inside_quiet.add(id(inner))

        quiet_only: set[str] = set()
        outside: set[str] = set()
        for node in ast.walk(func):
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)):
                continue
            (quiet_only if id(node) in inside_quiet else outside).add(node.id)
        quiet_only -= outside

        used: set[str] = set()
        for node in ast.walk(func):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "write_summary"):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load):
                        used.add(inner.id)

        offenders = sorted(quiet_only & used)
        assert not offenders, (
            f"{offenders} are assigned only inside a quiet-gated branch and "
            f"read by report.write_summary() — `bob -q -d` would raise "
            f"UnboundLocalError and the report would lose its summary silently"
        )
