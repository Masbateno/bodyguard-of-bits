"""A history line BOB cannot read is not a record of a past audit.

``load_history`` repaired every field it could not read instead of skipping
the line: a score that was null, absent, a string or out of range became
``0``, and a timestamp that was not a string was handed to the renderer,
which crashed on it.

The substituted score is the one that matters, because it does not merely
sit in a table — it feeds the trend arrows. Three audits of 8/10 with the
middle line's score field lost rendered a collapse and a recovery that
never happened.
"""

from __future__ import annotations

import json

import pytest

from bob.history import _trend, load_history, render_history


def _write(tmp_path, monkeypatch, *lines: str):
    hf = tmp_path / "history.jsonl"
    hf.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
    return hf


def _entry(ts: str, score, level: str = "low") -> str:
    return json.dumps({"ts": ts, "score": score, "level": level})


# ---------------------------------------------------------------------------
# The measured consequence
# ---------------------------------------------------------------------------

def test_a_lost_score_no_longer_invents_a_collapse(tmp_path, monkeypatch):
    """The defect, stated as the operator saw it."""
    _write(
        tmp_path, monkeypatch,
        _entry("2026-09-08T10:00:00+00:00", 8),
        _entry("2026-09-09T10:00:00+00:00", None),   # the field was lost
        _entry("2026-09-10T10:00:00+00:00", 8),
    )
    entries = load_history()

    assert [e["score"] for e in entries] == [8, 8], (
        "the unreadable line is skipped, not repaired into a score of 0"
    )
    arrows = [_trend(entries, i) for i in range(len(entries))]
    assert "↓" not in arrows, "BOB reported a collapse that never happened"
    assert "↑" not in arrows, "and a recovery to match it"
    assert arrows == [" ", "→"]


def test_two_real_audits_still_produce_their_arrow(tmp_path, monkeypatch):
    """The mirror: nothing was skipped, so the trend is still reported."""
    _write(
        tmp_path, monkeypatch,
        _entry("2026-09-08T10:00:00+00:00", 8),
        _entry("2026-09-10T10:00:00+00:00", 5),
    )
    entries = load_history()
    assert [e["score"] for e in entries] == [8, 5]
    assert _trend(entries, 1) == "↓", "a real drop must still show as one"


# ---------------------------------------------------------------------------
# What counts as unreadable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score", [None, "bad", "8", 999, -5, [8], {"n": 8}, True])
def test_a_score_bob_never_wrote_is_skipped(score, tmp_path, monkeypatch):
    _write(tmp_path, monkeypatch, _entry("2026-01-01T00:00:00+00:00", score))
    assert load_history() == [], f"{score!r} was accepted as a score"


@pytest.mark.parametrize("score", [0, 5, 10])
def test_every_score_bob_does_write_is_kept(score, tmp_path, monkeypatch):
    _write(tmp_path, monkeypatch, _entry("2026-01-01T00:00:00+00:00", score))
    assert [e["score"] for e in load_history()] == [score]


@pytest.mark.parametrize("ts", ["null", "12345", "[1,2]", '""'])
def test_a_timestamp_that_is_not_one_is_skipped(ts, tmp_path, monkeypatch):
    _write(tmp_path, monkeypatch, f'{{"ts":{ts},"score":8,"level":"low"}}')
    assert load_history() == []


def test_a_line_without_a_level_is_still_a_record(tmp_path, monkeypatch):
    """``level`` arrived in v0.7.0; its absence costs a label, not a fact."""
    _write(tmp_path, monkeypatch, '{"ts":"2026-01-01T00:00:00+00:00","score":8}')
    assert [e["score"] for e in load_history()] == [8]


# ---------------------------------------------------------------------------
# The render, not the loader
# ---------------------------------------------------------------------------

def test_history_survives_a_timestamp_that_is_not_a_string():
    """``bob --history`` aborted outright on this before v0.18.0."""
    for ts in (None, 12345, [1, 2]):
        lines = render_history([{"ts": ts, "score": 8, "level": "low"}])
        assert lines
        body = " ".join(lines)
        assert "12345" not in body, "a number was printed where a date belongs"
        assert "[1, 2]" not in body, "a Python repr reached the operator"


def test_a_null_level_does_not_print_the_word_none():
    lines = render_history(
        [{"ts": "2026-01-01T00:00:00+00:00", "score": 8, "level": None}]
    )
    assert "None" not in " ".join(lines), (
        "Python's None reached the screen where a risk level belongs"
    )
