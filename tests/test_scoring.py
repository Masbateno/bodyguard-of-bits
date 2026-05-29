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

    def test_post_finalize_deduction_is_discarded(self, caplog):
        """v0.5.5 I-2: deductions applied after finalize() bypass the cap
        silently. The engine now logs a WARNING and drops the deduction.
        """
        import logging
        engine = ScoreEngine()
        engine.cap(3, "test cap")
        engine.deduct("first deduction", 2)
        engine.finalize()
        score_before = engine.score

        # Apply a deduction after finalize — should be discarded.
        result = CheckResult()
        result.add_deduction("late deduction", 5, key="ssh.late")
        with caplog.at_level(logging.WARNING, logger="bob.scoring"):
            engine.apply(result)

        assert engine.score == score_before  # unchanged
        assert any("after finalize" in rec.message for rec in caplog.records)


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


# ---------------------------------------------------------------------------
# set_global_score / domain-average override
# ---------------------------------------------------------------------------

class TestSetGlobalScore:
    def test_override_replaces_raw_score(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.add_deduction("many issues", 8)
        engine.apply(r)
        engine.finalize()
        assert engine.score == 2     # raw
        engine.set_global_score(7)
        assert engine.score == 7     # overridden

    def test_no_override_by_default(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.add_deduction("reason", 3)
        engine.apply(r)
        engine.finalize()
        assert engine.score == MAX_SCORE - 3

    def test_override_clamps_above_max(self):
        engine = ScoreEngine()
        engine.finalize()
        engine.set_global_score(15)
        assert engine.score == MAX_SCORE

    def test_override_clamps_below_zero(self):
        engine = ScoreEngine()
        engine.finalize()
        engine.set_global_score(-5)
        assert engine.score == 0

    def test_level_reflects_overridden_score(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.add_deduction("many issues", 8)
        engine.apply(r)
        engine.finalize()
        assert engine.level == RiskLevel.CRITICAL   # raw score 2
        engine.set_global_score(9)
        assert engine.level == RiskLevel.LOW        # overridden score 9

    def test_raw_score_unchanged_after_override(self):
        engine = ScoreEngine()
        r = CheckResult()
        r.add_deduction("reason", 5)
        engine.apply(r)
        engine.finalize()
        engine.set_global_score(8)
        assert engine._raw_score == 5               # internal raw untouched
        assert engine.score == 8                    # public property overridden


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


# ---------------------------------------------------------------------------
# Scoring invariants
# ---------------------------------------------------------------------------

class TestScoringInvariants:
    """Structural invariants that must hold regardless of input combinations."""

    def test_score_floor_is_zero_on_huge_deduction(self):
        engine = ScoreEngine()
        engine.deduct("flood", 999)
        assert engine.score == 0

    def test_score_ceiling_is_max_on_no_deductions(self):
        engine = ScoreEngine()
        engine.finalize()
        assert engine.score == MAX_SCORE

    def test_deductions_are_monotone_decreasing(self):
        """Each additional deduction must not increase the score."""
        engine = ScoreEngine()
        prev = engine.score
        for pts in (3, 1, 2, 1, 4):
            engine.deduct("step", pts)
            assert engine.score <= prev
            prev = engine.score

    def test_cap_above_current_score_is_noop(self):
        """A cap set above the current score must not alter it."""
        engine = ScoreEngine()
        engine.deduct("reason", 3)   # score = 7
        score_before = engine.score
        engine.cap(maximum=9, reason="lenient cap")
        engine.finalize()
        assert engine.score == score_before

    def test_score_after_domain_override_in_valid_range(self):
        from bob.domain_scores import apply_domain_score_override
        engine = ScoreEngine()
        engine.deduct("reason", 5)
        engine.finalize()
        apply_domain_score_override(engine)
        assert 0 <= engine.score <= MAX_SCORE


# ---------------------------------------------------------------------------
# v0.7.0 — Posture escalation
# ---------------------------------------------------------------------------

class TestPostureEscalation:
    """Posture state lifts the displayed risk level out of LOW when the
    firewall is structurally broken even if the score stays high."""

    def test_default_no_escalation(self):
        e = ScoreEngine()
        e.finalize()
        assert e.posture_escalation == (None, "")
        assert e.effective_level == e.level

    def test_firewall_inactive_raises_to_high(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(firewall_inactive=True)
        floor, key = e.posture_escalation
        assert floor == RiskLevel.HIGH
        assert key == "scoring.posture.firewall_inactive"

    def test_iptables_input_accept_raises_to_high(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(iptables_input_accept=True)
        floor, key = e.posture_escalation
        assert floor == RiskLevel.HIGH
        assert key == "scoring.posture.iptables_input_accept"

    def test_firewall_domain_low_raises_to_medium(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(firewall_domain_score=3)
        floor, key = e.posture_escalation
        assert floor == RiskLevel.MEDIUM
        assert key == "scoring.posture.firewall_domain_low"

    def test_firewall_domain_4_does_not_trigger(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(firewall_domain_score=4)
        assert e.posture_escalation == (None, "")

    def test_firewall_inactive_takes_priority_over_low_domain(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(firewall_inactive=True, firewall_domain_score=1)
        floor, key = e.posture_escalation
        assert floor == RiskLevel.HIGH
        assert key == "scoring.posture.firewall_inactive"

    def test_iptables_takes_priority_over_low_domain(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(iptables_input_accept=True, firewall_domain_score=2)
        floor, key = e.posture_escalation
        assert floor == RiskLevel.HIGH
        assert key == "scoring.posture.iptables_input_accept"

    def test_effective_level_lifts_low_to_high_when_fw_inactive(self):
        """The Ubuntu VM case: score=8 (LOW) but UFW OFF must display HIGH."""
        e = ScoreEngine()
        # No deductions → MAX_SCORE = 10 → LOW
        e.finalize()
        assert e.level == RiskLevel.LOW
        e.set_posture(firewall_inactive=True)
        assert e.effective_level == RiskLevel.HIGH

    def test_effective_level_never_downgrades(self):
        """A CRITICAL score must stay CRITICAL even when posture is MEDIUM."""
        e = ScoreEngine()
        for _ in range(15):
            e.deduct("dummy", 1)
        e.finalize()
        assert e.level == RiskLevel.CRITICAL
        e.set_posture(firewall_domain_score=3)  # would push to MEDIUM
        assert e.effective_level == RiskLevel.CRITICAL

    def test_set_posture_is_idempotent(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(firewall_inactive=True)
        first = e.effective_level
        e.set_posture(firewall_inactive=True)
        assert e.effective_level == first

    def test_set_posture_overrides_previous_state(self):
        e = ScoreEngine()
        e.finalize()
        e.set_posture(firewall_inactive=True)
        assert e.effective_level == RiskLevel.HIGH
        # Second call with all defaults clears state
        e.set_posture()
        assert e.effective_level == e.level
        assert e.posture_escalation == (None, "")

    def test_low_plus_medium_escalates_to_medium(self):
        """Score LOW (=8) + posture MEDIUM floor → effective MEDIUM."""
        e = ScoreEngine()
        e.deduct("two", 2)  # 10 - 2 = 8 → LOW
        e.finalize()
        assert e.level == RiskLevel.LOW
        e.set_posture(firewall_domain_score=3)  # MEDIUM floor
        assert e.effective_level == RiskLevel.MEDIUM

    def test_medium_plus_high_escalates_to_high(self):
        e = ScoreEngine()
        for _ in range(5):
            e.deduct("dummy", 1)  # 10-5 = 5 → MEDIUM
        e.finalize()
        assert e.level == RiskLevel.MEDIUM
        e.set_posture(firewall_inactive=True)  # HIGH floor
        assert e.effective_level == RiskLevel.HIGH

    def test_high_floor_with_high_score_no_change(self):
        """HIGH score + HIGH floor stays HIGH (no escalation to CRITICAL)."""
        e = ScoreEngine()
        for _ in range(7):
            e.deduct("dummy", 1)  # 10-7=3 → HIGH
        e.finalize()
        assert e.level == RiskLevel.HIGH
        e.set_posture(firewall_inactive=True)
        assert e.effective_level == RiskLevel.HIGH


class TestRiskMax:
    """The _risk_max helper that drives effective_level."""

    def test_none_floor_returns_base(self):
        from bob.scoring import _risk_max
        assert _risk_max(RiskLevel.LOW, None) == RiskLevel.LOW
        assert _risk_max(RiskLevel.CRITICAL, None) == RiskLevel.CRITICAL

    def test_picks_stricter(self):
        from bob.scoring import _risk_max
        assert _risk_max(RiskLevel.LOW, RiskLevel.MEDIUM) == RiskLevel.MEDIUM
        assert _risk_max(RiskLevel.MEDIUM, RiskLevel.HIGH) == RiskLevel.HIGH
        assert _risk_max(RiskLevel.HIGH, RiskLevel.CRITICAL) == RiskLevel.CRITICAL

    def test_picks_base_when_base_is_stricter(self):
        from bob.scoring import _risk_max
        assert _risk_max(RiskLevel.HIGH, RiskLevel.LOW) == RiskLevel.HIGH
        assert _risk_max(RiskLevel.CRITICAL, RiskLevel.MEDIUM) == RiskLevel.CRITICAL

    def test_equal_levels(self):
        from bob.scoring import _risk_max
        assert _risk_max(RiskLevel.MEDIUM, RiskLevel.MEDIUM) == RiskLevel.MEDIUM
