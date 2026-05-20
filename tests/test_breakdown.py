"""
Tests for bob/breakdown.py — display_breakdown() and its helpers.
"""

import io
from unittest.mock import MagicMock, patch

import pytest

from bob.breakdown import display_breakdown, _bar
from bob.domain_scores import apply_domain_score_override
from bob.scoring import CheckResult, ScoreEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(*key_points: tuple[int, str], cap=None) -> ScoreEngine:
    engine = ScoreEngine()
    result = CheckResult()
    for points, key in key_points:
        result.add_deduction(reason=key, points=points, context="local", key=key)
    if cap:
        maximum, reason, key = cap
        result.set_cap(maximum=maximum, reason=reason, key=key)
    engine.apply(result)
    engine.finalize()
    apply_domain_score_override(engine)
    return engine


def _t(key: str, **kw) -> str:
    """Minimal translation stub — returns the key with kwargs substituted."""
    for k, v in kw.items():
        key = key.replace(f"{{{k}}}", str(v))
    return key


def _collect_output(engine: ScoreEngine) -> list[str]:
    """Run display_breakdown and collect all printed text."""
    calls: list[str] = []
    mock_output = MagicMock()
    mock_output.print_section.side_effect  = lambda msg: calls.append(msg)
    mock_output.print_ok.side_effect       = lambda msg: calls.append(msg)
    mock_output.print_warn.side_effect     = lambda msg: calls.append(msg)
    mock_output.print_info.side_effect     = lambda msg: calls.append(msg)
    mock_output.print_dim.side_effect      = lambda msg: calls.append(msg)
    mock_output.print_alert.side_effect    = lambda msg: calls.append(msg)
    with patch("builtins.print", side_effect=lambda *a, **k: calls.append(str(a[0]) if a else "")):
        display_breakdown(engine, _t, mock_output)
    return calls


# ---------------------------------------------------------------------------
# _bar helper
# ---------------------------------------------------------------------------

class TestBar:
    # _bar() now delegates to bob.output.score_bar which returns an ANSI-coloured
    # string. Strip escape sequences before asserting visible content / length.
    import re as _re
    _ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")

    @classmethod
    def _plain(cls, s: str) -> str:
        return cls._ANSI_RE.sub("", s)

    def test_full_score_all_filled(self):
        assert self._plain(_bar(10)) == "██████████"

    def test_zero_score_all_empty(self):
        assert self._plain(_bar(0)) == "░░░░░░░░░░"

    def test_five_half_filled(self):
        bar = self._plain(_bar(5))
        assert "█" in bar
        assert "░" in bar
        assert len(bar) == 10


# ---------------------------------------------------------------------------
# display_breakdown — clean engine
# ---------------------------------------------------------------------------

class TestDisplayBreakdownClean:
    def test_no_deductions_message(self):
        engine = ScoreEngine()
        engine.finalize()
        apply_domain_score_override(engine)
        calls = _collect_output(engine)
        assert any("breakdown.no_deductions" in c for c in calls)

    def test_section_title_printed(self):
        engine = ScoreEngine()
        engine.finalize()
        apply_domain_score_override(engine)
        calls = _collect_output(engine)
        assert any("breakdown.section_title" in c for c in calls)

    def test_final_score_ten_shown(self):
        engine = ScoreEngine()
        engine.finalize()
        apply_domain_score_override(engine)
        calls = _collect_output(engine)
        assert any("breakdown.final_score" in c for c in calls)
        assert engine.score == 10


# ---------------------------------------------------------------------------
# display_breakdown — engine with deductions
# ---------------------------------------------------------------------------

class TestDisplayBreakdownWithDeductions:
    def _engine(self):
        return _make_engine(
            (1, "ssh.password_auth"),
            (1, "hardening.rp_filter_disabled"),
        )

    def test_deductions_header_shown(self):
        calls = _collect_output(self._engine())
        assert any("breakdown.deductions_header" in c for c in calls)

    def test_deduction_keys_shown(self):
        calls = _collect_output(self._engine())
        combined = "\n".join(calls)
        assert "ssh.password_auth" in combined
        assert "hardening.rp_filter_disabled" in combined

    def test_raw_score_shown(self):
        calls = _collect_output(self._engine())
        assert any("breakdown.raw_score" in c for c in calls)

    def test_domain_scores_header_shown(self):
        calls = _collect_output(self._engine())
        assert any("breakdown.domain_scores_header" in c for c in calls)

    def test_domain_average_shown(self):
        calls = _collect_output(self._engine())
        assert any("breakdown.domain_average" in c for c in calls)

    def test_final_score_shown(self):
        calls = _collect_output(self._engine())
        assert any("breakdown.final_score" in c for c in calls)


# ---------------------------------------------------------------------------
# display_breakdown — tool cap annotation
# ---------------------------------------------------------------------------

class TestDisplayBreakdownToolCap:
    def test_tool_cap_message_shown_when_exceeded(self):
        engine = _make_engine(
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),
        )
        calls = _collect_output(engine)
        assert any("breakdown.tool_cap_applied" in c for c in calls)

    def test_no_tool_cap_message_when_within_limit(self):
        engine = _make_engine((1, "rootkit.db_outdated"))
        calls = _collect_output(engine)
        assert not any("breakdown.tool_cap_applied" in c for c in calls)


# ---------------------------------------------------------------------------
# display_breakdown — engine cap
# ---------------------------------------------------------------------------

class TestDisplayBreakdownEngineCap:
    def test_engine_cap_message_shown(self):
        engine = _make_engine(
            cap=(3, "Firewall inactive", "firewall.inactive")
        )
        calls = _collect_output(engine)
        assert any("breakdown.engine_cap_applied" in c for c in calls)

    def test_engine_cap_message_not_shown_when_absent(self):
        engine = _make_engine((1, "ssh.password_auth"))
        calls = _collect_output(engine)
        assert not any("breakdown.engine_cap_applied" in c for c in calls)
