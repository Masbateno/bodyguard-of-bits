"""
v0.16.0 — the cron email subject became "Score N/A" on any bounded host.

`--install-cron` with an email address writes a small Python script that reads
the audit log back, pulls the score out of it, and puts it in the subject line
before sending the report as HTML. Its pattern was::

    re.search(r'Score\\s*:\\s*(\\d+/10)', content)

This release made the report render ``Score     : ≤ 7/10`` whenever a check
could not read its input. ``\\s*`` does not consume ``≤``, so the pattern did
not match *at all* — not "matched and dropped the bound", but returned None —
and the subject silently fell back to ``[BOB] host - Score N/A``. That is most
hosts audited without full privileges, and the only visible symptom is an email
subject nobody would connect to a scoring change.

Found by reading the cron path while checking a SECURITY.md claim, not by the
suite: no test renders the report and then feeds it back to the generated
script.

The prefix is captured as "any non-digit, non-newline run" rather than the ≤
character itself, so the generated cron script stays pure ASCII and carries no
encoding assumption. ``[^\\d\\n]*`` rather than ``\\D*`` because ``\\D`` matches
newlines and would run across lines to a later number.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_IO = _ROOT / "bob" / "cron" / "_io.py"


def _generated_pattern() -> str:
    """The regex exactly as it lands in the generated cron script."""
    source = _IO.read_text(encoding="utf-8")
    m = re.search(r'"\s*m = re\.search\(r\'(.+?)\', content\)', source)
    assert m, "the score-extraction line is no longer where this guard looks"
    # The outer Python string escapes each backslash; the generated file has one.
    return m.group(1).replace("\\\\", "\\")


def _extract(line: str) -> "str | None":
    m = re.search(_generated_pattern(), line)
    if not m:
        return None
    prefix = m.group(1).strip()
    return f"{prefix} {m.group(2)}" if prefix else m.group(2)


class TestTheSubjectSurvivesABoundedScore:

    def test_a_bounded_score_is_matched_and_keeps_its_bound(self):
        assert _extract("Score     : ≤ 7/10") == "≤ 7/10"

    def test_a_plain_score_still_matches(self):
        """The polarity twin — the ordinary case must not regress."""
        assert _extract("Score   : 7/10") == "7/10"

    def test_a_perfect_bounded_score_matches(self):
        assert _extract("Score : ≤ 10/10") == "≤ 10/10"

    def test_the_prefix_does_not_run_across_lines(self):
        """
        `\\D*` would match the newline and reach a number on a later line,
        pulling an unrelated figure into the subject.
        """
        assert _extract("Risk : HIGH\nScore   : 8/10") == "8/10"


class TestTheGeneratedScriptStaysAscii:

    def test_no_non_ascii_in_the_generated_python(self):
        """
        The script is embedded in a shell heredoc and run by cron, with no
        encoding declaration of its own. Matching on the ≤ character would put
        a dependency there for no gain.
        """
        source = _IO.read_text(encoding="utf-8")
        block = source[source.index("PYTHON_EOF") - 4000: source.index("PYTHON_EOF")]
        offenders = sorted({c for c in block if ord(c) > 127})
        assert not offenders, f"non-ASCII in the generated cron script: {offenders}"
