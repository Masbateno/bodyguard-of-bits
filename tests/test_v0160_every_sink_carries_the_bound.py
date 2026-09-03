"""
v0.16.0 — one truth, six renderers, and only two of them updated.

The score became a ceiling when a check could not read its input. The change
landed in the terminal and the JSON sink. It did not land in the on-disk
report, so the artefact an operator archives said ``Score : 7/10`` where the
screen said ``≤ 7/10`` — about the same audit, at the same second. Nor in
Markdown, HTML, CSV or the webhook.

Nothing was wrong with any of those files. The defect is that six places render
the same number independently, so "update the score rendering" is six edits and
no one is told when they have made two. The report is where it hurt, because it
is the output that outlives the run.

This guard is the actual fix; the six edits are just today's instance. Any new
sink, or any new consumer of ``engine.score``, has to declare itself here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

# Every module that turns engine.score into operator- or machine-facing output.
# Adding a sink means adding it here; that is the point of the list.
_SINKS = (
    "bob/display.py",          # terminal summary box
    "bob/report.py",           # the archived .log — where the drift showed
    "bob/json_output.py",      # --format=json / json-full
    "bob/markdown_output.py",  # --format=markdown
    "bob/html_output.py",      # --format=html
    "bob/csv_output.py",       # --format=csv
    "bob/webhook.py",          # -w / --webhook
)

_RENDERS_SCORE = re.compile(r"engine\.score\b(?!_)")


class _Stub:
    """Just enough engine for a sink to render a summary."""

    def __init__(self, bounded: bool):
        from bob.scoring import RiskLevel

        self.score = 7
        self.score_is_upper_bound = bounded
        self.unverified = ["ssh.config_unreadable"] if bounded else []
        self.findings = []
        self.breakdown = []
        self.ignored_findings = []
        self.alert_count = 0
        self.warn_count = 0
        self.ok_count = 0
        self.info_count = 0
        self.level = RiskLevel.MEDIUM
        self.effective_level = RiskLevel.MEDIUM
        self.domain_scores = {}


class TestTheSinksActuallyRenderTheCeiling:
    """Behavioural, because the source-presence guard below does not bite.

    A first version of this file asserted only that "score_is_upper_bound"
    appeared in each sink. Deleting the line that renders the ceiling in
    report.py left it green — the parameter and the docstring still mentioned
    the name. That is the third guard in two releases to report confidence it
    had not earned, so the two sinks that can be driven cheaply are driven.
    """

    def _summary(self, bounded: bool) -> str:
        from bob.report import AuditReport

        captured: list[str] = []
        report = AuditReport.__new__(AuditReport)
        report._writeln = captured.append          # type: ignore[attr-defined]
        AuditReport.write_summary(
            report, score=7, risk_level="MEDIUM", network_context="local",
            public_ip="", ok_count=0, warn_count=0, alert_count=0,
            breakdown=[], labels={}, score_is_upper_bound=bounded,
            unverified_count=1 if bounded else 0,
        )
        return "\n".join(captured)

    def test_the_archived_report_renders_the_ceiling(self):
        assert "≤ 7/10" in self._summary(True)

    def test_a_measured_score_is_not_rendered_as_one(self):
        """The polarity twin — a full audit must still report a value."""
        text = self._summary(False)
        assert "7/10" in text and "≤" not in text

    def test_the_webhook_payload_carries_the_flag(self):
        """Driven with a real ScoreEngine — the payload reaches a monitoring
        stack, and a stub thin enough to build would not have exercised
        compute_domain_scores, which the builder calls."""
        from types import SimpleNamespace

        from bob.scoring import CheckResult, ScoreEngine
        from bob.webhook import build_generic_payload

        sys_info = SimpleNamespace(hostname="h", os_name="", kernel="")
        for bounded in (True, False):
            result = CheckResult()
            if bounded:
                result.info(message="x", key="ssh.config_unreadable")
            engine = ScoreEngine()
            engine.apply(result)
            payload = build_generic_payload(
                engine, sys_info, "0.16.0", profile="server",
            )
            assert payload["score_is_upper_bound"] is bounded
            assert payload["unverified"] == (
                ["ssh.config_unreadable"] if bounded else []
            )


@pytest.mark.parametrize("sink", _SINKS)
def test_every_sink_knows_whether_the_score_is_a_ceiling(sink):
    source = (_ROOT / sink).read_text(encoding="utf-8")
    assert "score_is_upper_bound" in source, (
        f"{sink} renders the score but never asks whether it is a ceiling.\n"
        f"A run that could not read part of the host would be reported there "
        f"as a measurement — which is what the on-disk report did until "
        f"v0.16.0, contradicting the terminal about the same audit."
    )


def test_no_sink_renders_the_score_without_being_listed():
    """The list must not fall behind the code it is meant to cover."""
    listed = set(_SINKS)
    unlisted: list[str] = []
    for py in (_ROOT / "bob").rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        rel = str(py.relative_to(_ROOT))
        if rel in listed:
            continue
        source = py.read_text(encoding="utf-8")
        if _RENDERS_SCORE.search(source) and "score_is_upper_bound" not in source:
            unlisted.append(rel)

    # Modules that read engine.score for something other than rendering a
    # verdict to a human or a machine. Each is an explicit decision, not an
    # oversight.
    exempt = {
        "bob/compare.py",     # stores the integer in the baseline; the bound
                              # travels as AuditBaseline.unverified instead
        "bob/history.py",     # appends the integer to history.jsonl
        "bob/scoring.py",     # defines the property
        "bob/runner.py",      # orchestration, renders nothing
        "bob/watch.py",       # re-runs the audit; rendering is delegated
        "bob/breakdown.py",   # renders deductions, not the score
        "bob/domain_scores.py",  # per-domain sub-scores, not the global one
    }
    # bob/__main__.py is NOT exempt: it compares the score against --target,
    # which is an exit code. That comparison is where this guard earned its
    # keep — a bounded score used to satisfy a target, so a CI gate went green
    # on an audit that could not read part of the host.
    unlisted = [m for m in unlisted if m not in exempt]
    assert not unlisted, (
        f"these modules render engine.score and are neither listed in _SINKS "
        f"nor exempt: {sorted(unlisted)}"
    )


def test_the_report_summary_carries_the_profile_too():
    """
    Pre-existing gap, closed in the same pass: the audit profile changes
    severities and the exit code, so two reports taken under different profiles
    are not comparable — and nothing in the file said which one produced it.
    """
    source = (_ROOT / "bob" / "report.py").read_text(encoding="utf-8")
    assert "profile_name" in source


class TestATargetCannotBeSatisfiedByACeiling:
    """`--target N` is an exit code, which is what a CI pipeline acts on.

    Found by the guard above rather than looked for: bob/__main__.py compared
    engine.score against the target and was neither a listed sink nor exempt.
    A bounded score used to satisfy the target, so an audit run without the
    privileges it needs went green. A gate fails closed.
    """

    def test_the_comparison_consults_the_bound(self):
        source = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "engine.score_is_upper_bound" in source, (
            "--target must not be satisfiable by a ceiling"
        )

    def test_a_measured_score_above_target_still_passes(self):
        """The polarity twin: the gate must still open on a full audit."""
        source = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "engine.score < config.target or engine.score_is_upper_bound" in source, (
            "the bound is an additional reason to miss the target, not a "
            "replacement for the comparison"
        )
