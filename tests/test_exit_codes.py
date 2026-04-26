"""Tests for bob.__main__ exit code constants and --target exit-code logic."""

from __future__ import annotations

import pytest

from bob.__main__ import (
    EXIT_OK,
    EXIT_WARNINGS,
    EXIT_ALERTS,
    EXIT_ERROR,
    EXIT_TARGET_MISSED,
)


# ---------------------------------------------------------------------------
# Exit code constants
# ---------------------------------------------------------------------------

class TestExitCodeConstants:
    def test_exit_ok_is_0(self):
        assert EXIT_OK == 0

    def test_exit_warnings_is_1(self):
        assert EXIT_WARNINGS == 1

    def test_exit_alerts_is_2(self):
        assert EXIT_ALERTS == 2

    def test_exit_error_is_3(self):
        assert EXIT_ERROR == 3

    def test_exit_target_missed_is_4(self):
        assert EXIT_TARGET_MISSED == 4

    def test_all_distinct(self):
        codes = [EXIT_OK, EXIT_WARNINGS, EXIT_ALERTS, EXIT_ERROR, EXIT_TARGET_MISSED]
        assert len(codes) == len(set(codes))


# ---------------------------------------------------------------------------
# --target exit code logic (unit test on the decision logic itself)
# ---------------------------------------------------------------------------

def _decide_exit(score: int, target: int, alert_count: int, warn_count: int) -> int:
    """
    Replicate the exit-code decision block from _run() so we can unit-test it
    without mocking the entire audit pipeline.
    """
    if target > 0 and score < target:
        return EXIT_TARGET_MISSED
    if alert_count > 0:
        return EXIT_ALERTS
    if warn_count > 0:
        return EXIT_WARNINGS
    return EXIT_OK


class TestTargetExitCode:
    def test_score_below_target_returns_4(self):
        assert _decide_exit(score=7, target=8, alert_count=0, warn_count=0) == EXIT_TARGET_MISSED

    def test_score_equals_target_returns_0(self):
        assert _decide_exit(score=8, target=8, alert_count=0, warn_count=0) == EXIT_OK

    def test_score_above_target_returns_0(self):
        assert _decide_exit(score=9, target=8, alert_count=0, warn_count=0) == EXIT_OK

    def test_target_zero_disables_target_check(self):
        # target=0 means --target not specified
        assert _decide_exit(score=5, target=0, alert_count=0, warn_count=0) == EXIT_OK

    def test_target_missed_takes_priority_over_alerts(self):
        """EXIT_TARGET_MISSED is checked before alerts."""
        assert _decide_exit(score=5, target=8, alert_count=2, warn_count=0) == EXIT_TARGET_MISSED

    def test_target_missed_takes_priority_over_warnings(self):
        assert _decide_exit(score=6, target=9, alert_count=0, warn_count=3) == EXIT_TARGET_MISSED

    def test_no_target_with_alerts_returns_2(self):
        assert _decide_exit(score=5, target=0, alert_count=1, warn_count=0) == EXIT_ALERTS

    def test_no_target_with_warnings_returns_1(self):
        assert _decide_exit(score=8, target=0, alert_count=0, warn_count=2) == EXIT_WARNINGS

    def test_target_met_with_warnings_returns_1(self):
        """Score meets target but there are warnings → standard exit 1."""
        assert _decide_exit(score=8, target=7, alert_count=0, warn_count=1) == EXIT_WARNINGS

    def test_target_met_with_alerts_returns_2(self):
        assert _decide_exit(score=8, target=7, alert_count=1, warn_count=0) == EXIT_ALERTS

    def test_perfect_score_target_10_returns_0(self):
        assert _decide_exit(score=10, target=10, alert_count=0, warn_count=0) == EXIT_OK

    def test_score_1_below_target_1_returns_4(self):
        """Edge: score=0, target=1."""
        assert _decide_exit(score=0, target=1, alert_count=0, warn_count=0) == EXIT_TARGET_MISSED
