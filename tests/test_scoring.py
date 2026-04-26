"""
Unit tests for bob.scoring module.

Run with: python -m pytest tests/test_scoring.py -v
"""

import pytest
from bob.scoring import (
    CheckResult,
    Deduction,
    Finding,
    FindingLevel,
    RiskLevel,
    ScoreEngine,
    MAX_SCORE,
)


# ---------------------------------------------------------------------------
# Deduction
# ---------------------------------------------------------------------------

class TestDeduction:
    def test_valid_deduction(self):
        d = Deduction(reason="Open port", points=2, context="local")
        assert d.reason == "Open port"
        assert d.points == 2
        assert d.context == "local"

    def test_default_context_is_local(self):
        d = Deduction(reason="x", points=1)
        assert d.context == "local"

    def test_negative_points_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            Deduction(reason="x", points=-1)

    def test_zero_points_allowed(self):
        d = Deduction(reason="x", points=0)
        assert d.points == 0


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------

class TestFinding:
    def test_note_default_empty(self):
        f = Finding(level=FindingLevel.ALERT, message="test")
        assert f.note == ""

    def test_note_propagated_via_warn(self):
        r = CheckResult()
        r.warn("Warning", cmd="sudo ufw deny 9999", note="disclaimer text")
        assert r.findings[0].note == "disclaimer text"

    def test_note_propagated_via_alert(self):
        r = CheckResult()
        r.alert("Alert", cmd="sudo ufw deny 22", note="use with caution")
        assert r.findings[0].note == "use with caution"

    def test_note_not_set_when_omitted(self):
        r = CheckResult()
        r.alert("Alert")
        assert r.findings[0].note == ""

    def test_note_propagated_via_add_finding(self):
        r = CheckResult()
        r.add_finding(FindingLevel.WARN, "msg", note="my note")
        assert r.findings[0].note == "my note"


class TestCheckResult:
    def test_empty_result(self):
        r = CheckResult()
        assert r.deductions == []
        assert r.findings == []

    def test_add_deduction(self):
        r = CheckResult()
        r.add_deduction("reason", 2, "public")
        assert len(r.deductions) == 1
        assert r.deductions[0].points == 2

    def test_add_finding(self):
        r = CheckResult()
        r.add_finding(FindingLevel.ALERT, "critical issue")
        assert len(r.findings) == 1
        assert r.findings[0].level == FindingLevel.ALERT

    def test_ok_shorthand(self):
        r = CheckResult()
        r.ok("All good")
        assert r.findings[0].level == FindingLevel.OK

    def test_info_shorthand(self):
        r = CheckResult()
        r.info("Note")
        assert r.findings[0].level == FindingLevel.INFO

    def test_warn_shorthand(self):
        r = CheckResult()
        r.warn("Warning")
        assert r.findings[0].level == FindingLevel.WARN
        assert r.findings[0].nature == "improvement"

    def test_alert_shorthand(self):
        r = CheckResult()
        r.alert("Alert", cmd="sudo ufw deny 22")
        assert r.findings[0].level == FindingLevel.ALERT
        assert r.findings[0].nature == "action"
        assert r.findings[0].cmd == "sudo ufw deny 22"


# ---------------------------------------------------------------------------
# ScoreEngine
# ---------------------------------------------------------------------------

class TestScoreEngineInitial:
    def test_initial_score_is_max(self):
        engine = ScoreEngine()
        assert engine.score == MAX_SCORE

    def test_initial_level_is_low(self):
        engine = ScoreEngine()
        assert engine.level == RiskLevel.LOW

    def test_initial_breakdown_empty(self):
        engine = ScoreEngine()
        assert engine.breakdown == []

    def test_initial_findings_empty(self):
        engine = ScoreEngine()
        assert engine.findings == []


class TestScoreEngineApply:
    def test_apply_deduction(self):
        engine = ScoreEngine()
        result = CheckResult()
        result.add_deduction("reason", 2)
        engine.apply(result)
        assert engine.score == MAX_SCORE - 2

    def test_apply_accumulates_findings(self):
        engine = ScoreEngine()
        r1 = CheckResult()
        r1.ok("Good")
        r2 = CheckResult()
        r2.warn("Warning")
        engine.apply(r1)
        engine.apply(r2)
        assert len(engine.findings) == 2

    def test_apply_accumulates_breakdown(self):
        engine = ScoreEngine()
        r1 = CheckResult()
        r1.add_deduction("first", 1)
        r2 = CheckResult()
        r2.add_deduction("second", 2)
        engine.apply(r1)
        engine.apply(r2)
        assert len(engine.breakdown) == 2
        assert engine.score == MAX_SCORE - 3

    def test_score_never_below_zero(self):
        engine = ScoreEngine()
        result = CheckResult()
        result.add_deduction("massive", 100)
        engine.apply(result)
        assert engine.score == 0

    def test_multiple_deductions(self):
        engine = ScoreEngine()
        for i in range(5):
            r = CheckResult()
            r.add_deduction(f"reason {i}", 1)
            engine.apply(r)
        assert engine.score == MAX_SCORE - 5


class TestScoreEngineDeduct:
    def test_direct_deduct(self):
        engine = ScoreEngine()
        engine.deduct("Open port", 2, "public")
        assert engine.score == MAX_SCORE - 2
        assert engine.breakdown[0].context == "public"


class TestScoreEngineCap:
    def test_cap_enforced(self):
        engine = ScoreEngine()
        engine.cap(3, "Firewall inactive")
        engine.finalize()
        assert engine.score == 3

    def test_cap_not_applied_if_score_already_below(self):
        engine = ScoreEngine()
        engine.deduct("reason", 8)
        engine.cap(3, "Firewall inactive")
        engine.finalize()
        assert engine.score == 2

    def test_lowest_cap_wins(self):
        engine = ScoreEngine()
        engine.cap(5, "First cap")
        engine.cap(3, "Stricter cap")
        engine.finalize()
        assert engine.score == 3

    def test_cap_stored(self):
        engine = ScoreEngine()
        engine.cap(3, "Firewall inactive")
        assert engine.cap_info is not None
        assert engine.cap_info.maximum == 3

    def test_no_cap_by_default(self):
        engine = ScoreEngine()
        assert engine.cap_info is None


class TestScoreEngineFinalize:
    def test_finalize_idempotent(self):
        engine = ScoreEngine()
        engine.deduct("reason", 2)
        engine.finalize()
        score_after_first = engine.score
        engine.finalize()
        assert engine.score == score_after_first

    def test_score_implicitly_finalizes(self):
        engine = ScoreEngine()
        engine.cap(3, "reason")
        _ = engine.score  # triggers finalize
        assert engine._finalized


class TestRiskLevel:
    @pytest.mark.parametrize("deductions,expected_level", [
        (0,  RiskLevel.LOW),
        (1,  RiskLevel.LOW),
        (2,  RiskLevel.LOW),
        (3,  RiskLevel.MEDIUM),
        (4,  RiskLevel.MEDIUM),
        (5,  RiskLevel.MEDIUM),
        (6,  RiskLevel.HIGH),
        (7,  RiskLevel.HIGH),
        (8,  RiskLevel.CRITICAL),
        (9,  RiskLevel.CRITICAL),
        (10, RiskLevel.CRITICAL),
    ])
    def test_risk_levels(self, deductions, expected_level):
        engine = ScoreEngine()
        engine.deduct("reason", deductions)
        assert engine.level == expected_level


class TestCounts:
    def test_alert_count(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.alert("a1")
        r.alert("a2")
        r.warn("w1")
        engine.apply(r)
        assert engine.alert_count == 2

    def test_warn_count(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.warn("w1")
        r.warn("w2")
        r.ok("ok")
        engine.apply(r)
        assert engine.warn_count == 2

    def test_ok_count(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.ok("ok1")
        r.ok("ok2")
        r.ok("ok3")
        engine.apply(r)
        assert engine.ok_count == 3
