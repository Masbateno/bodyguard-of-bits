"""Tests for bob.recurrence — recurring finding tracker."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from bob.recurrence import load_recurrence, save_recurrence, update_recurrence


# ---------------------------------------------------------------------------
# update_recurrence
# ---------------------------------------------------------------------------

class TestUpdateRecurrence:
    def test_empty_prev_empty_active(self):
        assert update_recurrence({}, set()) == {}

    def test_new_key_starts_at_one(self):
        result = update_recurrence({}, {"ssh.root_login"})
        assert result == {"ssh.root_login": 1}

    def test_existing_key_increments(self):
        result = update_recurrence({"ssh.root_login": 3}, {"ssh.root_login"})
        assert result["ssh.root_login"] == 4

    def test_resolved_key_dropped(self):
        result = update_recurrence({"ssh.root_login": 5}, set())
        assert "ssh.root_login" not in result

    def test_multiple_keys_mixed(self):
        prev = {"a": 2, "b": 1, "c": 4}
        active = {"a", "d"}
        result = update_recurrence(prev, active)
        assert result["a"] == 3   # incremented
        assert result["d"] == 1   # new
        assert "b" not in result  # resolved
        assert "c" not in result  # resolved

    def test_all_resolved(self):
        prev = {"x": 10, "y": 5}
        result = update_recurrence(prev, set())
        assert result == {}

    def test_does_not_mutate_prev(self):
        prev = {"k": 2}
        update_recurrence(prev, {"k"})
        assert prev == {"k": 2}

    def test_large_counter(self):
        result = update_recurrence({"k": 999}, {"k"})
        assert result["k"] == 1000

    def test_keys_equal_active_keys(self):
        prev = {"a": 1, "b": 2}
        active = {"b", "c"}
        result = update_recurrence(prev, active)
        assert set(result.keys()) == active

    def test_consecutive_runs_increment(self):
        r1 = update_recurrence({}, {"a"})
        r2 = update_recurrence(r1, {"a"})
        r3 = update_recurrence(r2, {"a"})
        assert r3["a"] == 3

    def test_negative_counter_clamped_to_one(self):
        result = update_recurrence({"k": -5}, {"k"})
        assert result["k"] == 1

    def test_non_int_value_in_prev_resets_to_one(self):
        result = update_recurrence({"k": "oops"}, {"k"})
        assert result["k"] == 1

    def test_float_value_in_prev_is_normalized(self):
        result = update_recurrence({"k": 1.9}, {"k"})
        assert result["k"] == 2  # int(1.9)=1, then +1


# ---------------------------------------------------------------------------
# save_recurrence / load_recurrence round-trip
# ---------------------------------------------------------------------------

class TestSaveLoadRecurrence:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "rec.json"
        data = {"ssh.root_login": 3, "firewall.default_allow": 1}
        save_recurrence(data, path=path)
        loaded = load_recurrence(path=path)
        assert loaded == data

    def test_load_missing_file_returns_empty(self, tmp_path):
        result = load_recurrence(path=tmp_path / "nonexistent.json")
        assert result == {}

    def test_load_malformed_json_returns_empty(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        assert load_recurrence(path=path) == {}

    def test_load_non_dict_returns_empty(self, tmp_path):
        path = tmp_path / "list.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        assert load_recurrence(path=path) == {}

    def test_load_skips_non_numeric_values(self, tmp_path):
        path = tmp_path / "mixed.json"
        path.write_text(json.dumps({"good": 5, "bad": "text"}), encoding="utf-8")
        result = load_recurrence(path=path)
        assert result == {"good": 5}
        assert "bad" not in result

    def test_load_accepts_float_values(self, tmp_path):
        path = tmp_path / "float.json"
        path.write_text(json.dumps({"k": 2.9}), encoding="utf-8")
        result = load_recurrence(path=path)
        assert result["k"] == 2

    def test_load_skips_negative_values(self, tmp_path):
        path = tmp_path / "neg.json"
        path.write_text(json.dumps({"good": 3, "bad": -1}), encoding="utf-8")
        result = load_recurrence(path=path)
        assert result == {"good": 3}
        assert "bad" not in result

    def test_load_skips_negative_float_value(self, tmp_path):
        path = tmp_path / "neg_float.json"
        path.write_text(json.dumps({"good": 3, "bad": -2.9}), encoding="utf-8")
        result = load_recurrence(path=path)
        assert result == {"good": 3}
        assert "bad" not in result

    def test_load_skips_empty_string_key(self, tmp_path):
        path = tmp_path / "empty_key.json"
        path.write_text('{"": 5, "valid": 1}', encoding="utf-8")
        result = load_recurrence(path=path)
        assert result == {"valid": 1}
        assert "" not in result

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "nested" / "rec.json"
        save_recurrence({"k": 1}, path=path)
        assert path.exists()

    def test_save_overwrites_existing(self, tmp_path):
        path = tmp_path / "rec.json"
        save_recurrence({"k": 1}, path=path)
        save_recurrence({"k": 99}, path=path)
        assert load_recurrence(path=path) == {"k": 99}

    def test_save_empty_dict(self, tmp_path):
        path = tmp_path / "rec.json"
        save_recurrence({}, path=path)
        assert load_recurrence(path=path) == {}

    def test_no_tmp_file_leftover(self, tmp_path):
        path = tmp_path / "rec.json"
        save_recurrence({"k": 1}, path=path)
        assert not (tmp_path / "rec.json.tmp").exists()

    def test_load_returns_int_values(self, tmp_path):
        path = tmp_path / "rec.json"
        save_recurrence({"a": 7}, path=path)
        result = load_recurrence(path=path)
        assert isinstance(result["a"], int)

    def test_large_volume_round_trip(self, tmp_path):
        path = tmp_path / "rec.json"
        data = {f"k{i}": i for i in range(10_000)}
        save_recurrence(data, path=path)
        loaded = load_recurrence(path=path)
        assert len(loaded) == 10_000
        assert loaded["k42"] == 42

    def test_repeated_overwrite_preserves_last(self, tmp_path):
        path = tmp_path / "rec.json"
        for v in range(5):
            save_recurrence({"k": v}, path=path)
        assert load_recurrence(path=path) == {"k": 4}
