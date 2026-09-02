"""A test that runs a system binary must be skippable.

Backlog item 2. The rule comes from a real failure: a differential test read
live `ss` output, passed seventeen times locally, and failed on the CI runner —
which happened to hold an IPv6-mapped connection the dev host did not. A test
whose verdict depends on the machine it runs on has to say so.

The sweep behind this guard found three such tests and no defect. All three are
already correct, and their shapes are worth naming because they are the two
legitimate answers:

* `ss` and `openssl` are differential — they check BOB's parsing against the
  tool that owns the format. Both carry a skipif AND deterministic twins that
  keep the logic covered when the binary is absent (in the same file for `ss`,
  in test_ssl_certs.py::TestSslCertsThresholds for the expiry boundary).
* `man --warnings` has no twin on purpose. Its own docstring rejects one: an
  earlier draft counted `\\fI` against `\\fR` and failed on a page groff renders
  cleanly, because troff also closes a font with `\\fB` or `\\fP`. Counting
  escapes measures the counter, not the page.

What this guard enforces is the part that is mechanical: the skipif. Whether a
twin is needed is a judgement no test can make.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

# Running our own code or our own scripts is not a dependency on the host.
OURS = {"python3", "python", "bash", "sh", "sys.executable"}


def _argv0(node: ast.Call) -> str | None:
    if not node.args:
        return None
    first = node.args[0]
    if not isinstance(first, ast.List) or not first.elts:
        return None
    head = first.elts[0]
    if isinstance(head, ast.Constant) and isinstance(head.value, str):
        return head.value
    if isinstance(head, ast.Attribute) and head.attr == "executable":
        return "sys.executable"
    return None


def _has_skip(decorators: list[ast.expr]) -> bool:
    return any("skipif" in ast.dump(d) or "importorskip" in ast.dump(d) for d in decorators)


def live_command_calls() -> list[tuple[str, int, str, bool]]:
    """(file, line, binary, guarded) for every system binary a test invokes."""
    out = []
    for path in sorted(TESTS.glob("test_*.py")):
        src = path.read_text(encoding="utf-8")
        if "subprocess." not in src:
            continue
        tree = ast.parse(src)
        module_guarded = "pytestmark" in src and ("skipif" in src or "importorskip" in src)

        guarded_ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
               and _has_skip(node.decorator_list):
                guarded_ranges.append((node.lineno, node.end_lineno or node.lineno))

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"):
                continue
            if node.func.attr not in ("run", "check_output", "Popen", "call"):
                continue
            binary = _argv0(node)
            if binary is None or binary in OURS or binary == "which":
                continue
            guarded = module_guarded or any(lo <= node.lineno <= hi for lo, hi in guarded_ranges)
            out.append((path.name, node.lineno, binary, guarded))
    return out


class TestEveryLiveCommandIsSkippable:
    def test_no_test_invokes_a_system_binary_unguarded(self):
        naked = [
            f"{f}:{line} runs {binary!r}"
            for f, line, binary, guarded in live_command_calls()
            if not guarded
        ]
        assert not naked, (
            "a test invokes a system binary with no skipif — it will fail on a "
            "runner that lacks it, or on one whose version differs: " + ", ".join(naked)
        )

    def test_the_sweep_finds_the_known_ones(self):
        """A sweep that scraped nothing would pass forever. These three are the
        whole population as of v0.15.4."""
        found = {binary for _, _, binary, _ in live_command_calls()}
        assert {"ss", "openssl", "man"} <= found

    def test_the_expiry_boundary_keeps_a_deterministic_twin(self):
        """The openssl differential may be skipped; the boundary it protects —
        day zero is still valid, not expired — must stay covered without it."""
        src = (TESTS / "test_ssl_certs.py").read_text(encoding="utf-8")
        assert "test_exactly_0_days_is_critical_not_expired" in src
        assert "test_minus_one_day_is_expired" in src
        # The file does mention subprocess — for monkeypatching, not for
        # running anything — so the check that matters is that nothing in it
        # can be skipped away.
        assert "pytestmark" not in src
        assert not [
            f for f, _, _, _ in live_command_calls() if f == "test_ssl_certs.py"
        ]
