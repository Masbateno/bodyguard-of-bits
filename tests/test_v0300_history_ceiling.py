"""v0.30.0 — `--history` keeps the score's uncertainty with the score.

0.29.0 wrote the limit: the history recorded each score, not its "≤" (since
0.16.0); the JSON and the CSV carried `score_is_upper_bound`. Measured on this
workstation (31 October 2026, `~/.cache/bob-fieldtest/history_ub_bench.txt`),
two full audits in a user namespace, each a ceiling (`score_is_upper_bound`
true): 0.29.0's `--history` printed "7/10 →", a firm score with a trend arrow;
now "≤ 7/10" with no arrow and a legend, and each new line carries
`"upper_bound": true`. A run whose blindness dropped a whole domain (the
terminal's "~") keeps its span instead.
"""

from __future__ import annotations

import inspect
import json

import pytest

from bob import i18n
from bob.history import render_history, save_score


@pytest.fixture
def history(tmp_path, monkeypatch):
    monkeypatch.setattr("bob.history._CONFIG_DIR", tmp_path)
    hf = tmp_path / "history.jsonl"
    monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
    return hf


def _lines(hf):
    return [json.loads(line) for line in hf.read_text().splitlines()]


class TestWhatIsWritten:

    def test_a_ceiling(self, history):
        save_score(7, "high", upper_bound=True)
        assert _lines(history)[0]["upper_bound"] is True
        assert "span" not in _lines(history)[0]

    def test_a_span(self, history):
        save_score(6, "medium", span=(5, 8))
        assert _lines(history)[0]["span"] == [5, 8]
        assert "upper_bound" not in _lines(history)[0]

    def test_a_firm_score_writes_neither(self, history):
        save_score(8, "low")
        assert not {"upper_bound", "span"} & set(_lines(history)[0])

    @pytest.mark.parametrize("kw", [{}, {"upper_bound": True}, {"span": (5, 8)}], ids=["firm", "ceiling", "span"])
    def test_every_line_says_it_kept_the_mark(self, history, kw):
        """So that a line without it is known to predate 0.30.0."""
        save_score(8, "low", **kw)
        assert _lines(history)[0]["bound_known"] is True

    def test_the_audit_hands_them(self):
        from bob import __main__ as main
        src = inspect.getsource(main)
        assert "upper_bound=engine.score_is_upper_bound," in src
        assert "span=(engine.score_span if getattr(engine, \"score_is_uncertain\", False)" in src


def _e(score, ts, **kw):
    return {"ts": f"2026-10-31T{ts}:00+00:00", "score": score, "level": "low", "bound_known": True, **kw}


class TestWhatIsShown:

    def test_the_marks(self):
        out = "\n".join(render_history([_e(8, "10:00"), _e(7, "11:00", upper_bound=True),
                                        _e(6, "12:00", span=[5, 8])], t=lambda k, **kw: k))
        assert "≤ 7/10" in out and "~ 6/10" in out
        assert "history.upper_bound_legend" in out and "history.span_legend" in out

    @pytest.mark.parametrize("second", [{"upper_bound": True}, {"span": [5, 8]}], ids=["ceiling", "span"])
    def test_no_arrow_beside_an_uncertain_score(self, second):
        lines = render_history([_e(8, "10:00"), _e(7, "11:00", **second)], t=lambda k, **kw: k)
        newest = next(line for line in lines if "11:00" in line)
        assert not any(a in newest for a in "↑↓→")

    def test_no_arrow_measured_against_one(self):
        lines = render_history([_e(7, "10:00", upper_bound=True), _e(8, "11:00")], t=lambda k, **kw: k)
        newest = next(line for line in lines if "11:00" in line)
        assert not any(a in newest for a in "↑↓→")

    def test_firm_scores_keep_their_arrow_and_no_legend(self):
        lines = render_history([_e(7, "10:00"), _e(8, "11:00")], t=lambda k, **kw: k)
        assert "↑" in next(line for line in lines if "11:00" in line)
        assert not any("legend" in line for line in lines)

    @pytest.mark.parametrize("bad", [{"upper_bound": "yes"}, {"span": "5-8"}, {"span": [5]}, {"span": [True, 8]}])
    def test_a_mark_bob_did_not_write_is_not_read_as_one(self, bad):
        lines = render_history([_e(7, "10:00", **bad)], t=lambda k, **kw: k)
        assert not any("≤ 7" in line or "~ 7" in line for line in lines)


class TestALineWrittenBefore030:
    """Decided with the maintainer (1 November 2026): a line 0.29.0 wrote
    kept the number alone. Shown as firm, with an arrow, it said what was not
    measured — whether that score was a ceiling. It is shown "?", without an
    arrow, and the legend says why."""

    @staticmethod
    def _old(score, ts):
        return {"ts": f"2026-10-30T{ts}:00+00:00", "score": score, "level": "low"}

    def test_shown_unknown_without_an_arrow(self):
        lines = render_history([self._old(8, "10:00"), self._old(7, "11:00")], t=lambda k, **kw: k)
        rows = [line for line in lines if "2026-10-30" in line]
        assert all("? " in r for r in rows) and not any(a in r for r in rows for a in "↑↓→")
        assert "  history.bound_unknown_legend" in lines

    def test_a_new_firm_score_is_not_measured_against_one(self):
        lines = render_history([self._old(8, "10:00"), _e(7, "11:00")], t=lambda k, **kw: k)
        newest = next(line for line in lines if "2026-10-31" in line)
        assert "? " not in newest and not any(a in newest for a in "↑↓→")

    @pytest.mark.parametrize("bad", ["yes", 1, None])
    def test_only_the_value_bob_writes_counts(self, bad):
        lines = render_history([{**self._old(8, "10:00"), "bound_known": bad}], t=lambda k, **kw: k)
        assert "? 8/10" in next(line for line in lines if "2026-10-30" in line)


@pytest.mark.parametrize("lang, key, words", [
    ("en", "history.bound_unknown_legend", "written before 0.30.0, which kept the number alone: whether this score was a ceiling is not known"),
    ("fr", "history.bound_unknown_legend", "écrit avant 0.30.0, qui ne gardait que le nombre : que ce score ait été une borne supérieure n'est pas connu"),
    ("en", "history.upper_bound_legend", "the true score can only be lower"),
    ("fr", "history.upper_bound_legend", "le vrai score ne peut être que plus bas"),
    ("en", "history.span_legend", "moved in an unknown direction"),
    ("fr", "history.span_legend", "a bougé dans un sens inconnu"),
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key)
    finally:
        i18n.init(lang="en")
