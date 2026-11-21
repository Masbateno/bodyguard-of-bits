"""v0.41.0 — --history with partial runs only says there is no trend (B-030).

Measured on the test Mint (17 November 2026), the 0.39.0 history block over
four --check runs: an empty line under the title, where the trend goes — the
trend leaves partial runs out, and printed nothing. It says so now.
"""

from __future__ import annotations

from bob import i18n
from bob.history import render_history


def _entry(score, partial):
    return {"ts": "2026-11-17T10:00:00+00:00", "score": score, "level": "medium", "partial": partial}


def test_partial_runs_only_say_there_is_no_trend():
    i18n.init("en")
    lines = render_history([_entry(7, True), _entry(6, True)], i18n.t)
    assert lines[2] == "  " + i18n.t("history.no_trend")


def test_a_full_run_draws_its_trend():
    i18n.init("en")
    lines = render_history([_entry(7, True), _entry(6, False)], i18n.t)
    assert lines[2].strip() and lines[2] != "  " + i18n.t("history.no_trend")
