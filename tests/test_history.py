"""Tests for score history (--history feature)."""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from bob.history import (
    save_score, load_history, render_history, _score_to_spark, _trend,
    _MAX_HISTORY_ENTRIES,
)


class TestScoreToSpark:
    def test_zero_is_space(self):
        assert _score_to_spark(0) == " "

    def test_ten_is_filled(self):
        assert _score_to_spark(10) == "█"

    def test_nine_is_filled(self):
        # New formula: min(8, int(9*9/10)) = min(8,8) = 8 → "█"
        assert _score_to_spark(9) == "█"

    def test_eight_is_partial(self):
        # min(8, int(8*9/10)) = min(8, 7) = 7 → "▇"
        assert _score_to_spark(8) == "▇"

    def test_five_is_middle(self):
        # int(5*9/10) = int(4.5) = 4 → "▄"
        assert _score_to_spark(5) == "▄"

    def test_one_is_space(self):
        # int(1*9/10) = int(0.9) = 0 → " "
        assert _score_to_spark(1) == " "

    def test_two_is_first_bar(self):
        # int(2*9/10) = int(1.8) = 1 → "▁"
        assert _score_to_spark(2) == "▁"

    def test_clamps_above_ten(self):
        assert _score_to_spark(11) == _score_to_spark(10)

    def test_clamps_below_zero(self):
        assert _score_to_spark(-1) == _score_to_spark(0)

    def test_all_values_valid_chars(self):
        for s in range(11):
            assert _score_to_spark(s) in _score_to_spark.__globals__["_SPARK_CHARS"]

    def test_monotone_non_decreasing(self):
        chars = [_score_to_spark(s) for s in range(11)]
        spark = " ▁▂▃▄▅▆▇█"
        idxs = [spark.index(c) for c in chars]
        for i in range(1, len(idxs)):
            assert idxs[i] >= idxs[i - 1], f"Score {i} maps lower than {i-1}"


class TestSaveLoadHistory:
    def test_save_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.history._CONFIG_DIR", tmp_path)
        monkeypatch.setattr("bob.history._HISTORY_FILE", tmp_path / "history.jsonl")
        save_score(8, "low")
        assert (tmp_path / "history.jsonl").exists()

    def test_save_writes_valid_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.history._CONFIG_DIR", tmp_path)
        hf = tmp_path / "history.jsonl"
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        save_score(9, "low")
        entry = json.loads(hf.read_text().strip())
        assert entry["score"] == 9
        assert entry["level"] == "low"
        assert "ts" in entry

    def test_load_returns_empty_if_no_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("bob.history._HISTORY_FILE", tmp_path / "missing.jsonl")
        assert load_history() == []

    def test_load_returns_entries(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        hf.write_text(
            '{"ts":"2026-01-01T00:00:00+00:00","score":8,"level":"low"}\n'
            '{"ts":"2026-01-02T00:00:00+00:00","score":9,"level":"low"}\n'
        )
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        entries = load_history()
        assert len(entries) == 2
        assert entries[0]["score"] == 8

    def test_load_skips_malformed_lines(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        hf.write_text('not-json\n{"ts":"2026-01-01T00:00:00+00:00","score":7,"level":"medium"}\n')
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        entries = load_history()
        assert len(entries) == 1

    def test_load_respects_max_entries(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        lines = [f'{{"ts":"2026-01-0{i}T00:00:00+00:00","score":{i},"level":"low"}}' for i in range(1, 9)]
        hf.write_text("\n".join(lines) + "\n")
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        entries = load_history(max_entries=3)
        assert len(entries) == 3
        assert entries[-1]["score"] == 8

    def test_load_clamps_score_overflow(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        hf.write_text('{"ts":"2026-01-01T00:00:00+00:00","score":999,"level":"low"}\n')
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        entries = load_history()
        assert entries[0]["score"] == 10

    def test_load_clamps_score_negative(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        hf.write_text('{"ts":"2026-01-01T00:00:00+00:00","score":-5,"level":"low"}\n')
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        entries = load_history()
        assert entries[0]["score"] == 0

    def test_load_clamps_score_invalid_type(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        hf.write_text('{"ts":"2026-01-01T00:00:00+00:00","score":"bad","level":"low"}\n')
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        entries = load_history()
        assert entries[0]["score"] == 0

    def test_rotation_truncates_old_entries(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        monkeypatch.setattr("bob.history._CONFIG_DIR", tmp_path)
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        # Write _MAX_HISTORY_ENTRIES + 10 lines
        lines = [
            f'{{"ts":"2026-01-01T00:00:00+00:00","score":5,"level":"low"}}'
            for _ in range(_MAX_HISTORY_ENTRIES + 10)
        ]
        hf.write_text("\n".join(lines) + "\n")
        save_score(8, "low")  # triggers rotation
        count = len([l for l in hf.read_text().splitlines() if l.strip()])
        assert count == _MAX_HISTORY_ENTRIES

    def test_rotation_keeps_newest_entries(self, tmp_path, monkeypatch):
        hf = tmp_path / "history.jsonl"
        monkeypatch.setattr("bob.history._CONFIG_DIR", tmp_path)
        monkeypatch.setattr("bob.history._HISTORY_FILE", hf)
        # First line has score 1 (old), last lines have score 9 (new)
        old = '{"ts":"2020-01-01T00:00:00+00:00","score":1,"level":"low"}'
        new = '{"ts":"2026-01-01T00:00:00+00:00","score":9,"level":"low"}'
        lines = [old] + [new] * _MAX_HISTORY_ENTRIES
        hf.write_text("\n".join(lines) + "\n")
        save_score(9, "low")  # triggers rotation
        first_line = hf.read_text().splitlines()[0]
        entry = json.loads(first_line)
        assert entry["score"] == 9  # old entry (score=1) was dropped


class TestTrend:
    def _entries(self, scores: list[int]) -> list[dict]:
        return [{"score": s, "ts": "", "level": "low"} for s in scores]

    def test_first_entry_is_neutral(self):
        assert _trend(self._entries([8]), 0) == " "

    def test_improvement_is_up(self):
        assert _trend(self._entries([7, 9]), 1) == "↑"

    def test_regression_is_down(self):
        assert _trend(self._entries([9, 7]), 1) == "↓"

    def test_stable_is_arrow(self):
        assert _trend(self._entries([8, 8]), 1) == "→"

    def test_out_of_bounds_is_neutral(self):
        assert _trend(self._entries([8, 9]), 5) == " "


class TestRenderHistory:
    def test_no_entries_shows_message(self):
        lines = render_history([])
        assert any("no" in l.lower() or "aucun" in l.lower() for l in lines)

    def test_sparkline_present(self):
        entries = [{"ts": "2026-01-01T00:00:00+00:00", "score": 8, "level": "low"}]
        lines = render_history(entries)
        spark_line = lines[2]
        assert any(c in spark_line for c in "▁▂▃▄▅▆▇█ ")

    def test_score_in_output(self):
        entries = [{"ts": "2026-01-01T00:00:00+00:00", "score": 7, "level": "medium"}]
        lines = render_history(entries)
        combined = " ".join(lines)
        assert "7/10" in combined

    def test_level_in_output(self):
        entries = [{"ts": "2026-01-01T00:00:00+00:00", "score": 7, "level": "medium"}]
        lines = render_history(entries)
        combined = " ".join(lines)
        assert "medium" in combined

    def test_trend_arrow_in_output(self):
        entries = [
            {"ts": "2026-01-01T00:00:00+00:00", "score": 7, "level": "low"},
            {"ts": "2026-01-02T00:00:00+00:00", "score": 9, "level": "low"},
        ]
        lines = render_history(entries)
        combined = " ".join(lines)
        assert "↑" in combined

    def test_trend_stable_in_output(self):
        entries = [
            {"ts": "2026-01-01T00:00:00+00:00", "score": 8, "level": "low"},
            {"ts": "2026-01-02T00:00:00+00:00", "score": 8, "level": "low"},
        ]
        lines = render_history(entries)
        combined = " ".join(lines)
        assert "→" in combined

    def test_multiple_entries(self):
        entries = [
            {"ts": f"2026-01-0{i}T00:00:00+00:00", "score": i + 5, "level": "low"}
            for i in range(1, 5)
        ]
        lines = render_history(entries)
        assert len(lines) > 4

    def test_corrupt_score_clamped_in_sparkline(self):
        # Score 999 must not crash sparkline rendering
        entries = [{"ts": "2026-01-01T00:00:00+00:00", "score": 999, "level": "low"}]
        lines = render_history(entries)
        assert lines  # no exception

    def test_sparkline_length_matches_entry_count(self):
        entries = [
            {"ts": f"2026-01-0{i}T00:00:00+00:00", "score": i + 2, "level": "low"}
            for i in range(1, 8)
        ]
        # Remove the 2-space indent; scores 3-9 all produce non-space chars
        lines = render_history(entries)
        spark_line = lines[2][2:]
        assert len(spark_line) == 7
