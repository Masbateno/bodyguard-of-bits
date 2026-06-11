"""v0.12.0 F1 — "10/10 means a flawless audit" headline cap.

The global score is the rounded mean of active domain scores. Rounding could
push a real deduction away: a host with one pending firmware update has
raw score 9/10 and a domain average of (6×10 + 9)/7 = 9.857 → round → 10,
so the headline read "10/10 LOW" while the summary said "Action required".

F1 (Option A): when ANY deduction was applied (engine.raw_score < MAX_SCORE),
the headline is capped at MAX_SCORE-1, reserving a perfect score for an audit
with nothing to fix. Lower averages are unaffected. The pre-cap average is
kept (engine.domain_average_precap) so --breakdown shows the average and the
cap as two distinct steps.
"""

from __future__ import annotations

import pytest

from bob.scoring import ScoreEngine, CheckResult, MAX_SCORE
from bob.domain_scores import apply_domain_score_override


def _engine(ok_domains, deductions):
    """Build a finalised engine: an OK finding per domain in *ok_domains*,
    plus (points, key) deductions (each also adds an ALERT finding)."""
    engine = ScoreEngine()
    result = CheckResult()
    for dom in ok_domains:
        result.ok(message=f"{dom} clean", key=f"{dom}.ok")
    for points, key in deductions:
        result.alert(message=f"Finding {key}", key=key)
        result.add_deduction(reason=f"Deduction {key}", points=points, key=key)
    engine.apply(result)
    engine.finalize()
    apply_domain_score_override(engine)
    return engine


class TestF1FlawlessAuditCap:
    def test_deduction_caps_headline_below_ten(self):
        """6 domains at 10 + 1 domain at 9 → average rounds to 10, capped to 9."""
        engine = _engine(
            ok_domains=["ssh", "samba", "file_perms", "updates", "disk", "firewall"],
            deductions=[(1, "hardening.dmesg_exposed")],
        )
        assert engine.raw_score == MAX_SCORE - 1          # one deduction
        assert engine.domain_average_precap == MAX_SCORE  # average really rounds to 10
        assert engine.score == MAX_SCORE - 1              # ...but the headline is capped

    def test_clean_audit_keeps_perfect_score(self):
        """No deduction anywhere → 10/10, no cap (precap == final)."""
        engine = _engine(
            ok_domains=["ssh", "samba", "file_perms", "updates", "disk", "firewall", "hardening"],
            deductions=[],
        )
        assert engine.raw_score == MAX_SCORE
        assert engine.score == MAX_SCORE
        assert engine.domain_average_precap == MAX_SCORE

    def test_lower_score_unaffected_by_cap(self):
        """A heavily-deducted audit whose average already rounds below 9 is
        unchanged — the cap is a no-op there (min(avg, 9) == avg)."""
        engine = _engine(
            ok_domains=["ssh", "samba", "file_perms", "updates", "disk", "firewall"],
            deductions=[(4, "hardening.rp_filter_disabled")],   # hardening = 6
        )
        # average = (6×10 + 6)/7 = 9.43 → round 9; cap min(9,9) = 9, no change.
        assert engine.score == engine.domain_average_precap == 9

    def test_cap_never_lifts_a_score(self):
        """The cap only lowers; a sub-9 average is never raised to 9."""
        engine = _engine(
            ok_domains=["ssh", "samba"],
            deductions=[(6, "hardening.rp_filter_disabled")],   # hardening = 4
        )
        # average = (10 + 10 + 4)/3 = 8 → final 8, well below the 9 cap.
        assert engine.score == 8


class TestF1Precap:
    def test_set_global_score_records_precap(self):
        engine = ScoreEngine()
        engine.finalize()
        engine.set_global_score(9, precap=10)
        assert engine.score == 9
        assert engine.domain_average_precap == 10

    def test_precap_defaults_to_score_when_no_cap(self):
        engine = ScoreEngine()
        engine.finalize()
        engine.set_global_score(7)
        assert engine.domain_average_precap == 7
