"""v0.16.2 — blindness must never shrink the record of blindness.

Two defects of one family, found by making directories untraversable on the
bench rather than by reading code.

**The audit died.** Service detection probes an absolute binary path from the
always-on core, which ``_sec``'s v0.14.1 fault isolation deliberately does not
cover. ``Path.is_file()`` ignores four errnos and re-raises the rest, so an
untraversable ``/usr/local/bin`` produced ``[Errno 13] Permission denied:
'/usr/local/bin/gitea'`` — exit 3, no report, no findings. v0.15.2 wrote
``path_exists`` for exactly this shape; ``is_file`` was the one method it did
not wrap.

**And the accounting was inverted.** When a section raises, ``_sec`` isolates it
and emits ``<section>.unavailable``, which was in no visibility set. Making
``/etc/cron.d`` untraversable therefore took ``unverified`` from 9 keys **down**
to 8: the cron section stopped emitting its honest ``cron.unreadable_files``
and its failure counted as nothing. A section that failed hardest read as better
verified than one that degraded gracefully.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from bob.checks._run import path_exists, path_is_file
from bob.scoring import CheckResult, FindingLevel, ScoreEngine
from bob.visibility import UNAVAILABLE_SUFFIX, VISIBILITY_KEYS, is_visibility_key

_ROOT = Path(__file__).resolve().parent.parent


class TestAFailedSectionCountsAsUnverified:

    def test_the_generated_key_is_a_visibility_limit(self):
        assert is_visibility_key("cron" + UNAVAILABLE_SUFFIX)
        assert is_visibility_key("any_future_section.unavailable")

    def test_the_enumerated_set_still_works(self):
        """Polarity: the predicate widens the rule, it does not replace it."""
        assert is_visibility_key("ssh.config_unreadable")
        for key in VISIBILITY_KEYS:
            assert is_visibility_key(key)

    def test_an_ordinary_key_is_not_one(self):
        assert not is_visibility_key("ssh.password_auth")
        assert not is_visibility_key("firewall.inactive")

    def test_a_raised_section_bounds_the_score(self):
        """The engine, not just the predicate."""
        engine = ScoreEngine()
        result = CheckResult()
        result.add_finding(level=FindingLevel.INFO, message="unavailable",
                           key="cron.unavailable")
        engine.apply(result)
        engine.finalize()
        assert "cron.unavailable" in engine.unverified
        assert engine.score_is_uncertain is True

    def test_failing_harder_never_records_less(self):
        """The defect in one assertion.

        A section that degrades honestly contributes one visibility key; the
        same section raising contributes one too. Blindness must not be able to
        reduce the count.
        """
        def count(key: str) -> int:
            engine = ScoreEngine()
            result = CheckResult()
            result.add_finding(level=FindingLevel.INFO, message="m", key=key)
            engine.apply(result)
            engine.finalize()
            return len(engine.unverified)

        degraded_gracefully = count("cron.unreadable_files")
        raised_outright     = count("cron.unavailable")
        assert raised_outright >= degraded_gracefully, (
            "a section that did not run at all counted as more verified than "
            "one that ran and said what it could not read"
        )


class TestThePathHelpersDegrade:

    def test_is_file_returns_false_instead_of_raising(self, tmp_path):
        """Behavioural: a directory whose parent cannot be traversed."""
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        target = blocked / "binary"
        target.write_text("x", encoding="utf-8")
        blocked.chmod(0o000)
        try:
            # root ignores the mode, so skip rather than assert a false pass.
            try:
                target.is_file()
            except OSError:
                pass
            else:
                pytest.skip("this user can traverse a 0000 directory (root?)")
            assert path_is_file(target) is False
            assert path_exists(target) is False
        finally:
            blocked.chmod(0o755)

    def test_it_still_answers_true_for_a_real_file(self, tmp_path):
        """Polarity: degrading must not become "always False"."""
        f = tmp_path / "real"
        f.write_text("x", encoding="utf-8")
        assert path_is_file(f) is True
        assert path_is_file(tmp_path) is False       # a directory is not a file


class TestTheAlwaysOnCoreUsesTheHelpers:
    """``_sec`` degrades a section that raises; the always-on core has no such
    net, and the code says so. A raising path probe there costs the whole
    audit, so these modules must go through the degrading helpers.
    """

    #: Modules reached from the always-on pipeline, outside _sec's isolation.
    CORE = ("bob/checks/services.py",)

    RAISING = {"is_file", "is_dir", "exists", "stat", "lstat", "is_symlink"}

    @pytest.mark.parametrize("rel", CORE)
    def test_no_raw_path_probe_outside_a_try(self, rel):
        tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))

        def guarded(stack) -> bool:
            for node in stack:
                if isinstance(node, ast.Try) and any(
                    h.type is None or "OSError" in ast.unparse(h.type)
                    or "Exception" in ast.unparse(h.type)
                    for h in node.handlers
                ):
                    return True
            return False

        offenders = []

        def visit(node, stack):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "attr", "") in self.RAISING
                    and not guarded(stack)):
                offenders.append(f"line {node.lineno}: {ast.unparse(node)[:52]}")
            for child in ast.iter_child_nodes(node):
                visit(child, stack + [node])

        visit(tree, [])
        assert not offenders, (
            f"{rel} runs outside _sec's fault isolation, so one of these "
            "raising on an untraversable directory costs the entire audit — "
            "use path_exists / path_is_file:\n  " + "\n  ".join(offenders)
        )
