"""v0.15.3 — `bob --diff` printed nothing at all, since v0.3.0.

`--diff` is advertised in --help, in the man page and in EXAMPLES ("Show what
changed since last audit"), and shipped a cross-machine mode as a headline
v0.9.0 feature. It emitted zero bytes: not on a change, not on an unchanged
system, never.

`_silent_mode` sets `config.quiet = True` so the audit itself stays mute while
a post-audit view is displayed, and `display_delta` writes through
`output.print_*`. The comment above the branch states the contract — "display
post-audit views with full output (no quiet filter)" — but only `--breakdown`
implemented it. `_silent_mode` grew to cover `diff_mode` in v0.3.0, the commit
that introduced `--breakdown`: the new branch got its `output.init(quiet=False)`
and the pre-existing one did not.

Five test files touch the diff and none drove it through the CLI, so the
components were covered and the wiring between them was not. These tests pin
the mechanism rather than running a full audit, which would depend on the host.
"""

from __future__ import annotations

import ast
import contextlib
import io
from pathlib import Path

import pytest

from bob import i18n, output
from bob.compare import AuditBaseline, compute_delta, display_delta

ROOT = Path(__file__).resolve().parent.parent


def _delta(score_prev: int = 7, score_curr: int = 8):
    prev = AuditBaseline(
        timestamp="2026-09-01T12:00:00+00:00",
        score=score_prev, alert_count=1, warn_count=2,
    )
    curr = AuditBaseline(
        timestamp="2026-09-01T13:00:00+00:00",
        score=score_curr, alert_count=1, warn_count=1,
    )
    return compute_delta(prev, curr)


def _render(quiet: bool) -> str:
    i18n.init(lang="en")
    output.init(no_color=True, quiet=quiet)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        display_delta(_delta(), i18n.t, output)
    return buf.getvalue()


class TestDisplayDeltaDependsOnOutputBeingEnabled:
    def test_it_is_mute_while_output_is_quiet(self):
        """The mechanism behind the defect, pinned so it cannot be forgotten."""
        assert _render(quiet=True) == ""

    def test_it_prints_once_output_is_enabled(self):
        out = _render(quiet=False)
        assert out.strip(), "display_delta produced nothing with output enabled"
        assert "CHANGES SINCE LAST AUDIT" in out.upper()

    def test_an_unchanged_system_still_says_so(self):
        """Zero bytes is not an acceptable rendering of 'nothing changed'."""
        i18n.init(lang="en")
        output.init(no_color=True, quiet=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            display_delta(_delta(7, 7), i18n.t, output)
        assert buf.getvalue().strip()


class TestPostAuditViewsAreWiredCorrectly:
    """Anti-drift guard.

    Every post-audit view runs under `_silent_mode`, which mutes
    `output.print_*`. Each must re-enable output, and each must stay out of the
    machine modes: a human view printed after the JSON / CSV / Markdown / HTML
    payload corrupts the stream its caller parses. `--diff` was accidentally
    safe there while it was mute; `--breakdown` was not.
    """

    @staticmethod
    def _view_branches() -> list[ast.If]:
        tree = ast.parse((ROOT / "bob" / "__main__.py").read_text(encoding="utf-8"))
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test_src = ast.dump(node.test)
            # Identified by the flag alone — deliberately NOT by the presence
            # of an output.init call, or removing that call would hide the
            # branch from its own guard instead of failing it.
            if "diff_mode" in test_src or "breakdown_mode" in test_src:
                found.append(node)
        return found

    def test_the_guard_finds_both_views(self):
        """A structural check that matches nothing would pass forever."""
        assert len(self._view_branches()) == 2

    @pytest.mark.parametrize("index", [0, 1])
    def test_the_view_re_enables_output(self, index):
        node = self._view_branches()[index]
        enables = [
            c for c in ast.walk(node)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and c.func.attr == "init"
            and any(
                k.arg == "quiet" and isinstance(k.value, ast.Constant)
                and k.value.value is False
                for k in c.keywords
            )
        ]
        assert enables, "post-audit view does not call output.init(quiet=False)"

    @pytest.mark.parametrize("index", [0, 1])
    def test_the_view_is_excluded_from_machine_mode(self, index):
        node = self._view_branches()[index]
        assert "_machine_mode" in ast.dump(node.test), (
            "a human view must not print into a JSON/CSV/Markdown/HTML stream"
        )
