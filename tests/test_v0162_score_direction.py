"""v0.16.2 — a ceiling claims a direction, and blindness does not always have one.

v0.16.0 reasoned: a check unable to read its input makes deductions that are
unknown rather than zero, so the score can only be too high — a ceiling. That is
true while the blinded check's domain is still scored.

It stops being true when the *whole domain* leaves the average. The global score
is a mean over active domains; a domain whose every finding fell to INFO because
the file never opened is dropped, so the denominator changes rather than the
numerator, and the result moves in a direction nobody can predict. Masking
`/etc/passwd` drops `file_perms` (10/10) and takes the score from 7 **down** to
6 — so `≤ 6` claimed a ceiling below the true value, and the domain rendered as
`no action needed`, a clean pass on something BOB never looked at.

The span needs no invented data: a domain scores in [0, MAX_SCORE] by
construction, so placing the missing ones at both extremes brackets the truth.
It also says how much is at stake, which a bare `~` does not.
"""

from __future__ import annotations

import pytest

from bob.domain_scores import (
    REASON_INFO_ONLY,
    REASON_UNREADABLE,
    _uncertainty,
    domain_inactive_reason,
)
from bob.scoring import MAX_SCORE, ScoreEngine


def _engine(score: int, unverified: list[str]) -> ScoreEngine:
    e = ScoreEngine()
    e.finalize()
    e.set_global_score(score, precap=score)
    e.unverified = list(unverified)
    return e


# ---------------------------------------------------------------------------
# Three states, not two
# ---------------------------------------------------------------------------

class TestTheBoundOnlyClaimsWhatItCanProve:

    def test_a_fully_read_host_is_neither_bounded_nor_uncertain(self):
        e = _engine(7, [])
        assert e.score_is_upper_bound is False
        assert e.score_is_uncertain is False
        assert e.score_span == (7, 7)

    def test_blindness_inside_a_scored_domain_is_still_a_ceiling(self):
        """The v0.16.0 case, unchanged: sshd_config unreadable, SSH still scored."""
        e = _engine(8, ["ssh.config_unreadable"])
        e.set_score_uncertainty([], (8, 8))
        assert e.score_is_upper_bound is True
        assert e.score_is_uncertain is True

    def test_a_domain_leaving_the_average_is_not_a_ceiling(self):
        e = _engine(6, ["user_accounts.no_passwd"])
        e.set_score_uncertainty(["file_perms"], (5, 7))
        assert e.score_is_upper_bound is False, (
            "6 is not a ceiling when the sighted score is 7"
        )
        assert e.score_is_uncertain is True, (
            "it is still not a verified number — a gate must fail closed"
        )
        assert e.score_span == (5, 7)

    def test_the_span_collapses_when_nothing_is_blind(self):
        """Callers use score_span unconditionally; it must be safe to."""
        assert _engine(7, []).score_span == (7, 7)


# ---------------------------------------------------------------------------
# The span is arithmetic, not a guess
# ---------------------------------------------------------------------------

class _FakeEngine:
    def __init__(self, unverified, raw=5):
        self.unverified = list(unverified)
        self.raw_score = raw
        self.score = 6


class TestTheSpanBracketsTheTruth:

    @staticmethod
    def _scores(**kw):
        return {k: {"score": v} for k, v in kw.items()}

    def test_the_real_case(self):
        """5 scored domains totalling 32, file_perms blinded → 32/6 .. 42/6."""
        scores = self._scores(ssh=5, samba=10, hardening=4, disk=10,
                              firewall=3, file_perms=10)
        active = {"ssh", "samba", "hardening", "disk", "firewall"}
        blinded, span = _uncertainty(
            _FakeEngine(["user_accounts.no_passwd"]), scores, active)
        assert blinded == ["file_perms"]
        assert span == (5, 7), f"expected the sighted 7 inside the span, got {span}"

    def test_the_sighted_score_lies_inside_the_span(self):
        """The property that makes the span worth printing."""
        scores = self._scores(ssh=5, samba=10, hardening=4, disk=10,
                              firewall=3, file_perms=10)
        active = {"ssh", "samba", "hardening", "disk", "firewall"}
        _, (low, high) = _uncertainty(
            _FakeEngine(["user_accounts.no_passwd"]), scores, active)
        sighted = round(sum(scores[d]["score"] for d in scores) / len(scores))
        assert low <= sighted <= high

    def test_nothing_blind_collapses_the_span(self):
        scores = self._scores(ssh=5, samba=10)
        blinded, span = _uncertainty(_FakeEngine([]), scores, {"ssh", "samba"})
        assert blinded == []
        assert span[0] == span[1]

    def test_the_span_never_leaves_the_scale(self):
        scores = self._scores(ssh=0, file_perms=0)
        _, (low, high) = _uncertainty(
            _FakeEngine(["user_accounts.no_passwd"]), scores, {"ssh"})
        assert 0 <= low <= high <= MAX_SCORE


# ---------------------------------------------------------------------------
# The domain must not read as a clean pass
# ---------------------------------------------------------------------------

class TestADomainBobCouldNotReadSaysSo:

    def test_unreadable_beats_info_only(self):
        """Both states emit INFO and nothing scoreable; only one is a pass."""
        e = _engine(6, ["user_accounts.no_passwd"])
        assert domain_inactive_reason("file_perms", e) == REASON_UNREADABLE

    def test_a_genuinely_quiet_domain_still_reads_as_no_action(self):
        """Polarity: the new reason must not swallow the old one."""
        from bob.scoring import Finding, FindingLevel

        e = _engine(7, [])
        e.findings.append(Finding(
            level=FindingLevel.INFO, message="nothing to do", key="updates.none"))
        assert domain_inactive_reason("updates", e) == REASON_INFO_ONLY

    def test_both_locales_name_the_new_reason(self):
        import json
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        for loc in ("en", "fr"):
            data = json.loads((root / "bob" / "locales" / f"{loc}.json").read_text(encoding="utf-8"))
            assert "unreadable" in data["domain_scores"]["reason"], loc


# ---------------------------------------------------------------------------
# Every sink, again — the v0.16.0 lesson applied to the new state
# ---------------------------------------------------------------------------

class TestEverySinkCarriesTheSpan:
    """v0.16.0 found the archived report saying `7/10` where the screen said
    `≤ 7/10`. The same drift is one edit away for a state added later, so each
    sink is pinned to rendering the span or the fields that carry it.
    """

    @pytest.mark.parametrize("rel,needle", [
        ("bob/json_output.py",     '"score_low"'),
        ("bob/csv_output.py",      '"score_low"'),
        ("bob/webhook.py",         '"score_low"'),
        ("bob/markdown_output.py", "score_span"),
        ("bob/html_output.py",     "score_span"),
        ("bob/report.py",          "score_span"),
        ("bob/display.py",         "score_span"),
    ])
    def test_the_sink_knows_about_the_span(self, rel, needle):
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        assert needle in (root / rel).read_text(encoding="utf-8"), (
            f"{rel} renders the score but not what the score is worth"
        )

    def test_the_json_pair_is_always_present(self):
        """`score_low == score_high` is how a consumer reads "fully verified" —
        so the pair must not be conditional on blindness."""
        from bob.json_output import build_json_data

        src = (__import__("pathlib").Path(__file__).resolve().parent.parent
               / "bob" / "json_output.py").read_text(encoding="utf-8")
        assert "engine.score_span[0]" in src and "engine.score_span[1]" in src
        assert "if " not in src.split('"score_low"')[1].split("\n")[0]
