"""v0.15.2 — the number on screen must follow from the reasons on screen.

The rest of this release is about BOB not stating what it never established.
The scoring layer is the same promise arithmetically: a score the operator
cannot derive from the findings shown to them is a claim without evidence,
even when the number happens to be right.

These are property tests. Each generates finding sets over a seeded range and
asserts an invariant across all of them, rather than pinning a handful of
worked examples — the sampling lesson of this cycle applies to arithmetic too.
The generators are checked for bite: `test_the_generator_exercises_the_space`
fails if the scenarios stop covering caps, clamps and the full score range,
so a future refactor cannot quietly turn these into assertions about nothing.
"""

import random

import pytest

from bob.domain_scores import _DOMAIN_SECTIONS, apply_domain_score_override
from bob.profiles import AuditProfile
from bob.scoring import MAX_SCORE, CheckResult, FindingLevel, ScoreCap, ScoreEngine

_SECTIONS = sorted({s for secs in _DOMAIN_SECTIONS.values() for s in secs})
_RANGE = range(400)


def _random_result(rng: random.Random, index: int, *, with_caps: bool) -> CheckResult:
    result = CheckResult()
    for slot in range(rng.randint(0, 4)):
        key = f"{rng.choice(_SECTIONS)}.f{index}{slot}"
        roll = rng.random()
        if roll < 0.30:
            result.warn_with_deduction(key=key, message=key, reason=key,
                                       points=rng.randint(0, 4), nature="action")
        elif roll < 0.50:
            result.alert_with_deduction(key=key, message=key, reason=key,
                                        points=rng.randint(0, 4), nature="action")
        elif roll < 0.65:
            result.warn(message=key, key=key)
        elif roll < 0.80:
            result.info(message=key, key=key)
        else:
            result.ok(message=key, key=key)
    if with_caps and rng.random() < 0.15:
        result.caps.append(ScoreCap(maximum=rng.randint(0, MAX_SCORE),
                                    reason=f"cap{index}", key=f"firewall.cap{index}"))
    return result


def _engine(seed: int, *, with_caps: bool = True) -> ScoreEngine:
    rng = random.Random(seed)
    engine = ScoreEngine()
    for index in range(rng.randint(1, 6)):
        engine.apply(_random_result(rng, index, with_caps=with_caps))
    engine.finalize()
    return engine


class TestTheBreakdownExplainsTheScore:
    """The listed reasons must add up to the raw score, cap included.

    `finalize` appends the cap as a synthetic deduction precisely so the
    breakdown stays a complete account of the arithmetic; this pins that.
    """

    def test_raw_score_is_the_sum_of_the_breakdown(self):
        for seed in _RANGE:
            engine = _engine(seed)
            total = sum(d.points for d in engine.breakdown)
            assert engine.raw_score == max(0, min(MAX_SCORE, MAX_SCORE - total)), seed

    def test_the_score_stays_within_bounds(self):
        for seed in _RANGE:
            assert 0 <= _engine(seed).raw_score <= MAX_SCORE, seed

    def test_no_deduction_ever_raises_the_score(self):
        for seed in _RANGE:
            assert all(d.points >= 0 for d in _engine(seed).breakdown), seed

    def test_the_counts_match_the_findings(self):
        for seed in _RANGE:
            engine = _engine(seed)
            for level, count in (
                (FindingLevel.ALERT, engine.alert_count),
                (FindingLevel.WARN, engine.warn_count),
                (FindingLevel.INFO, engine.info_count),
            ):
                assert count == sum(1 for f in engine.findings if f.level == level), seed

    def test_the_generator_exercises_the_space(self):
        """Bite check: without caps and clamps these assertions prove nothing."""
        scores, capped, clamped = set(), 0, 0
        for seed in _RANGE:
            engine = _engine(seed)
            scores.add(engine.raw_score)
            total = sum(d.points for d in engine.breakdown)
            if engine.cap_info is not None:
                capped += 1
            if total > MAX_SCORE:
                clamped += 1
        assert len(scores) >= 8, f"only {len(scores)} distinct scores reached"
        assert capped >= 20, f"only {capped} scenarios registered a cap"
        assert clamped >= 20, f"only {clamped} scenarios hit the zero floor"


class TestTheDisplayedScore:
    """The domain-averaged score is what the operator actually reads."""

    def _displayed(self, seed: int) -> ScoreEngine:
        engine = _engine(seed, with_caps=False)
        apply_domain_score_override(engine)
        return engine

    def test_within_bounds(self):
        for seed in _RANGE:
            assert 0 <= self._displayed(seed).score <= MAX_SCORE, seed

    def test_a_perfect_score_means_nothing_was_deducted(self):
        """v0.12.0 F1: 10/10 is reserved for an audit with nothing to fix."""
        for seed in _RANGE:
            engine = self._displayed(seed)
            if engine.raw_score < MAX_SCORE:
                assert engine.score <= MAX_SCORE - 1, seed

    def test_an_undeducted_audit_is_not_marked_down(self):
        for seed in _RANGE:
            engine = self._displayed(seed)
            if engine.raw_score == MAX_SCORE:
                assert engine.score == MAX_SCORE, seed


def _fixed_points(seed: int) -> "tuple[dict[str, int], str]":
    """Deterministic points plus one key to silence.

    Both engines must receive byte-identical input: drawing the points twice
    from the same seeded generator desynchronises them and measures the
    generator rather than the filter.
    """
    rng = random.Random(seed)
    keys = [f"ssh.k{i}" for i in range(rng.randint(1, 5))]
    points = {key: rng.randint(1, 3) for key in keys}
    return points, rng.choice(keys)


class TestIgnoreRemovesThePenaltyToo:
    """Silencing a finding must not keep charging for it.

    Otherwise the operator hides a finding and quietly keeps its deduction:
    the score drops for a reason no longer on screen.
    """

    def _ignored(self, points: dict, key: str) -> ScoreEngine:
        result = CheckResult()
        for k, pts in points.items():
            result.warn_with_deduction(key=k, message=k, reason=k,
                                       points=pts, nature="action")
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({key})
        engine.apply(result)
        engine.finalize()
        return engine

    def test_the_deduction_leaves_the_breakdown(self):
        for seed in _RANGE:
            points, silenced = _fixed_points(seed)
            engine = self._ignored(points, silenced)
            assert not any(d.key == silenced for d in engine.breakdown), seed

    def test_the_finding_leaves_the_report(self):
        for seed in _RANGE:
            points, silenced = _fixed_points(seed)
            engine = self._ignored(points, silenced)
            assert not any(f.key == silenced for f in engine.findings), seed

    def test_the_score_recovers_exactly_those_points(self):
        for seed in _RANGE:
            points, silenced = _fixed_points(seed)
            engine = self._ignored(points, silenced)
            remaining = sum(points.values()) - points[silenced]
            assert engine.raw_score == max(0, min(MAX_SCORE, MAX_SCORE - remaining)), seed

    def test_no_other_finding_is_disturbed(self):
        for seed in _RANGE:
            points, silenced = _fixed_points(seed)
            engine = self._ignored(points, silenced)
            kept = {d.key: d.points for d in engine.breakdown}
            assert kept == {k: v for k, v in points.items() if k != silenced}, seed


class TestProfileDowngradeDropsTheDeduction:
    """"info" and "skip" promise no score impact; "alert" promises the opposite."""

    def _with_override(self, points: dict, key: str, level: str) -> ScoreEngine:
        result = CheckResult()
        for k, pts in points.items():
            result.warn_with_deduction(key=k, message=k, reason=k,
                                       points=pts, nature="action")
        engine = ScoreEngine(profile=AuditProfile(name="t", overrides={key: level}))
        engine.apply(result)
        engine.finalize()
        return engine

    @pytest.mark.parametrize("level", ["info", "skip"])
    def test_a_downgrade_removes_the_points(self, level):
        for seed in _RANGE:
            points, target = _fixed_points(seed)
            engine = self._with_override(points, target, level)
            remaining = sum(points.values()) - points[target]
            assert engine.raw_score == max(0, min(MAX_SCORE, MAX_SCORE - remaining)), seed
            assert not any(d.key == target for d in engine.breakdown), seed

    def test_skip_also_removes_the_finding(self):
        for seed in _RANGE:
            points, target = _fixed_points(seed)
            engine = self._with_override(points, target, "skip")
            assert not any(f.key == target for f in engine.findings), seed

    def test_info_keeps_the_finding_at_info_level(self):
        for seed in _RANGE:
            points, target = _fixed_points(seed)
            engine = self._with_override(points, target, "info")
            levels = [f.level for f in engine.findings if f.key == target]
            assert levels and levels[0] is FindingLevel.INFO, seed

    def test_an_escalation_keeps_the_points(self):
        for seed in _RANGE:
            points, target = _fixed_points(seed)
            engine = self._with_override(points, target, "alert")
            total = sum(points.values())
            assert engine.raw_score == max(0, min(MAX_SCORE, MAX_SCORE - total)), seed
