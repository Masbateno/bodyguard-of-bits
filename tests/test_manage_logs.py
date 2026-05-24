"""
Tests for manage_logs.py — log management UI.

Covers:
- parse_log_selection
- Change location: no-logs, same-path, move yes/no, cancel
- Extra directories: display, auto-cleanup, cross-dir delete
- All: deletes from all directories
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Captured before any test runs so the real implementation is always available
# inside the targeted stat mock (Python 3.12: Path.exists() calls self.stat()).
_real_path_stat = Path.stat


def _stat_raises_for_logs(self, **kwargs):
    """Raise OSError for .log files; delegate to real stat for everything else."""
    if self.suffix == ".log":
        raise OSError("race: file disappeared between scan and display")
    return _real_path_stat(self, **kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user_config(log_dir: str, extra_dirs: list[str] | None = None):
    """Minimal UserConfig stand-in backed by a plain dict."""
    store: dict[str, str] = {"log_dir": log_dir}
    if extra_dirs is not None:
        store["log_dirs_extra"] = json.dumps(extra_dirs)
    uc = MagicMock()
    uc.get.side_effect = lambda k: store.get(k)
    uc.set.side_effect = lambda k, v: store.update({k: v})
    return uc, store


def _make_config():
    return SimpleNamespace(no_color=True)


def _t(key, **kwargs):
    from bob.i18n import t
    return t(key, **kwargs)


def _make_log(directory: Path, name: str) -> Path:
    f = directory / name
    f.write_text("x")
    return f


# ---------------------------------------------------------------------------
# parse_log_selection
# ---------------------------------------------------------------------------

class TestParseLogSelection:
    def _parse(self, answer, max_idx):
        from bob.manage_logs import parse_log_selection
        return parse_log_selection(answer, max_idx)

    def test_single(self):
        assert self._parse("1", 3) == [1]

    def test_multiple_csv(self):
        assert self._parse("1,3", 3) == [1, 3]

    def test_range(self):
        assert self._parse("2-4", 5) == [2, 3, 4]

    def test_mixed(self):
        assert self._parse("1,3-5", 5) == [1, 3, 4, 5]

    def test_out_of_bounds_ignored(self):
        assert self._parse("9", 3) == []

    def test_invalid_string(self):
        assert self._parse("abc", 3) == []

    def test_empty(self):
        assert self._parse("", 3) == []


# ---------------------------------------------------------------------------
# _get_extra_dirs / _set_extra_dirs / _add_extra_dir
# ---------------------------------------------------------------------------

class TestExtraDirsHelpers:
    def test_get_empty(self, tmp_path):
        from bob.manage_logs import _get_extra_dirs
        uc, _ = _make_user_config(str(tmp_path))
        assert _get_extra_dirs(uc) == []

    def test_get_returns_paths(self, tmp_path):
        from bob.manage_logs import _get_extra_dirs
        d1 = tmp_path / "a"
        d2 = tmp_path / "b"
        uc, _ = _make_user_config(str(tmp_path), extra_dirs=[str(d1), str(d2)])
        assert _get_extra_dirs(uc) == [d1, d2]

    def test_add_new(self, tmp_path):
        from bob.manage_logs import _add_extra_dir, _get_extra_dirs
        uc, _ = _make_user_config(str(tmp_path))
        d = tmp_path / "extra"
        _add_extra_dir(uc, d)
        assert _get_extra_dirs(uc) == [d]

    def test_add_duplicate_ignored(self, tmp_path):
        from bob.manage_logs import _add_extra_dir, _get_extra_dirs
        uc, _ = _make_user_config(str(tmp_path))
        d = tmp_path / "extra"
        _add_extra_dir(uc, d)
        _add_extra_dir(uc, d)
        assert _get_extra_dirs(uc) == [d]

    def test_invalid_json_returns_empty(self, tmp_path):
        from bob.manage_logs import _get_extra_dirs
        uc, store = _make_user_config(str(tmp_path))
        store["log_dirs_extra"] = "not-json"
        assert _get_extra_dirs(uc) == []


# ---------------------------------------------------------------------------
# Change location — no existing logs → no move prompt
# ---------------------------------------------------------------------------

class TestChangeLocationNoLogs:
    def test_no_logs_no_move_prompt(self, tmp_path):
        """Empty current dir: no move question, config updated."""
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)

    def test_same_path_no_move_prompt(self, tmp_path):
        """Choosing same path: no extras added, no move question."""
        old_dir = tmp_path / "logs"
        old_dir.mkdir()
        _make_log(old_dir, "bob_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[old_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(old_dir)
        assert (old_dir / "bob_2026-01-01.log").exists()


# ---------------------------------------------------------------------------
# Change location — move YES
# ---------------------------------------------------------------------------

class TestMoveLogsYes:
    def test_logs_moved_to_new_dir(self, tmp_path):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        log1 = _make_log(old_dir, "bob_2026-01-01.log")
        log2 = _make_log(old_dir, "bob_2026-01-02.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "y", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)
        assert (new_dir / "bob_2026-01-01.log").exists()
        assert (new_dir / "bob_2026-01-02.log").exists()
        assert not log1.exists()
        assert not log2.exists()

    def test_moved_count_in_output(self, tmp_path, capsys):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        for i in range(3):
            _make_log(old_dir, f"bob_2026-01-0{i+1}.log")

        uc, _ = _make_user_config(str(old_dir))
        inputs = iter(["c", "y", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert "3" in capsys.readouterr().out

    def test_move_includes_extra_dir_logs(self, tmp_path):
        """Logs from previous (extra) dirs are also moved when user says yes."""
        old_dir = tmp_path / "old"
        extra_dir = tmp_path / "extra"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        extra_dir.mkdir()
        _make_log(old_dir, "bob_2026-01-01.log")
        ex_log = _make_log(extra_dir, "bob_2026-01-02.log")

        uc, store = _make_user_config(str(old_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["c", "y", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert (new_dir / "bob_2026-01-01.log").exists()
        assert (new_dir / "bob_2026-01-02.log").exists()
        assert not ex_log.exists()


# ---------------------------------------------------------------------------
# Change location — move NO
# ---------------------------------------------------------------------------

class TestMoveLogsNo:
    def test_logs_stay_in_old_dir(self, tmp_path):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        log = _make_log(old_dir, "bob_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "n", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)
        assert log.exists()
        assert not (new_dir / "bob_2026-01-01.log").exists()

    def test_old_dir_added_to_extras(self, tmp_path):
        """When user declines move, old dir is tracked in log_dirs_extra."""
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        _make_log(old_dir, "bob_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "n", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        from bob.manage_logs import _get_extra_dirs
        assert old_dir in _get_extra_dirs(uc)

    def test_empty_answer_treated_as_no(self, tmp_path):
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        _make_log(old_dir, "bob_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(new_dir)
        assert (old_dir / "bob_2026-01-01.log").exists()


# ---------------------------------------------------------------------------
# Extra directories: display and auto-cleanup
# ---------------------------------------------------------------------------

class TestExtraDirectoriesDisplay:
    def test_extra_logs_shown_in_output(self, tmp_path, capsys):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(extra_dir, "bob_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "bob_2026-01-01.log" in out
        assert str(extra_dir) in out

    def test_extra_dir_header_shown(self, tmp_path, capsys):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(extra_dir, "bob_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        # The ─── separator is hardcoded in the UI (not translated) and the
        # extra dir path always appears in the header line.
        assert "───" in out
        assert str(extra_dir) in out

    def test_empty_extra_dir_auto_removed(self, tmp_path):
        """Extra dir that is empty should be dropped from the list."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "empty_extra"
        cur_dir.mkdir()
        extra_dir.mkdir()  # exists but no logs

        uc, store = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        from bob.manage_logs import _get_extra_dirs
        assert _get_extra_dirs(uc) == []

    def test_nonexistent_extra_dir_auto_removed(self, tmp_path):
        cur_dir = tmp_path / "current"
        cur_dir.mkdir()
        ghost = tmp_path / "ghost"  # does not exist

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(ghost)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        from bob.manage_logs import _get_extra_dirs
        assert _get_extra_dirs(uc) == []

    def test_flat_index_spans_all_dirs(self, tmp_path):
        """Index numbers must be contiguous across current + extra dirs."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(cur_dir, "bob_2026-01-01.log")
        _make_log(cur_dir, "bob_2026-01-02.log")
        _make_log(extra_dir, "bob_2026-01-03.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs), \
             __import__("io").StringIO() as _:
            import io
            from unittest.mock import patch as _patch
            import bob.manage_logs as ml
            with _patch("builtins.print") as mock_print:
                with _patch("builtins.input", side_effect=["q"]):
                    ml.run_manage_logs(uc, _make_config(), _t)

            printed = " ".join(str(c) for c in mock_print.call_args_list)
            assert "[ 3]" in printed


# ---------------------------------------------------------------------------
# Delete by index from extra directory
# ---------------------------------------------------------------------------

class TestDeleteFromExtraDir:
    def test_delete_extra_dir_log_by_index(self, tmp_path):
        """A log in an extra dir can be deleted by its flat index."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(cur_dir, "bob_2026-01-01.log")
        ex_log = _make_log(extra_dir, "bob_2026-01-02.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        # Index 2 = first log in extra dir
        inputs = iter(["2", "q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert not ex_log.exists()
        assert (cur_dir / "bob_2026-01-01.log").exists()


# ---------------------------------------------------------------------------
# 'all' deletes from all directories
# ---------------------------------------------------------------------------

class TestDeleteAll:
    def test_all_deletes_across_dirs(self, tmp_path):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        cur_log = _make_log(cur_dir, "bob_2026-01-01.log")
        ex_log = _make_log(extra_dir, "bob_2026-01-02.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["all", "y", "q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert not cur_log.exists()
        assert not ex_log.exists()

    def test_all_cancel_leaves_files(self, tmp_path):
        cur_dir = tmp_path / "current"
        cur_dir.mkdir()
        log = _make_log(cur_dir, "bob_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir))
        inputs = iter(["all", "n", "q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert log.exists()


# ---------------------------------------------------------------------------
# Change location — cancel
# ---------------------------------------------------------------------------

class TestChangeLocationCancel:
    def test_cancel_does_not_update_config(self, tmp_path):
        old_dir = tmp_path / "old"
        old_dir.mkdir()
        _make_log(old_dir, "bob_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        inputs = iter(["c", "q"])

        with patch("builtins.input", side_effect=inputs), \
             patch("bob.manage_logs.prompt_path", side_effect=[None]):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        assert store["log_dir"] == str(old_dir)


# ---------------------------------------------------------------------------
# Score history helpers
# ---------------------------------------------------------------------------

class TestExtractScoreFromLog:
    def test_standard_format(self, tmp_path):
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("Score   : 7/10\n")
        assert _extract_score_from_log(f) == 7

    def test_compact_format(self, tmp_path):
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("Score: 10/10\n")
        assert _extract_score_from_log(f) == 10

    def test_score_embedded_in_text(self, tmp_path):
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("some header\nOK: 5\nScore   : 3/10\nRisk: low\n")
        assert _extract_score_from_log(f) == 3

    def test_score_zero(self, tmp_path):
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("Score   : 0/10\n")
        assert _extract_score_from_log(f) == 0

    def test_no_score_returns_none(self, tmp_path):
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("no score line here\n")
        assert _extract_score_from_log(f) is None

    def test_missing_file_returns_none(self, tmp_path):
        from bob.manage_logs import _extract_score_from_log
        assert _extract_score_from_log(tmp_path / "missing.log") is None

    def test_partial_match_not_returned(self, tmp_path):
        """'notScore   : 7/10' should not match (line-start anchor)."""
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("notScore   : 7/10\n")
        assert _extract_score_from_log(f) is None

    def test_first_score_wins(self, tmp_path):
        """Only the first Score line is returned."""
        from bob.manage_logs import _extract_score_from_log
        f = tmp_path / "log.log"
        f.write_text("Score   : 5/10\nScore   : 9/10\n")
        assert _extract_score_from_log(f) == 5


class TestParseLogDate:
    def test_standard_filename(self):
        from bob.manage_logs import _parse_log_date
        p = Path("bob_20260413_170724.log")
        assert _parse_log_date(p) == "2026-04-13 17:07"

    def test_midnight(self):
        from bob.manage_logs import _parse_log_date
        p = Path("bob_20260101_000000.log")
        assert _parse_log_date(p) == "2026-01-01 00:00"

    def test_end_of_day(self):
        from bob.manage_logs import _parse_log_date
        p = Path("bob_20261231_235959.log")
        assert _parse_log_date(p) == "2026-12-31 23:59"

    def test_malformed_falls_back_to_stem(self):
        from bob.manage_logs import _parse_log_date
        p = Path("notavalidname.log")
        assert _parse_log_date(p) == "notavalidname"


class TestBuildScoreHistory:
    def _make_log_with_score(self, directory: Path, name: str, score: int) -> Path:
        f = directory / name
        f.write_text(f"Score   : {score}/10\n")
        return f

    def test_empty_list(self):
        from bob.manage_logs import _build_score_history
        assert _build_score_history([]) == []

    def test_single_log(self, tmp_path):
        from bob.manage_logs import _build_score_history
        f = self._make_log_with_score(tmp_path, "bob_20260413_170000.log", 7)
        result = _build_score_history([f])
        assert result == [("2026-04-13 17:00", 7)]

    def test_sorted_chronologically(self, tmp_path):
        from bob.manage_logs import _build_score_history
        f1 = self._make_log_with_score(tmp_path, "bob_20260413_100000.log", 5)
        f2 = self._make_log_with_score(tmp_path, "bob_20260414_100000.log", 8)
        f3 = self._make_log_with_score(tmp_path, "bob_20260415_100000.log", 9)
        result = _build_score_history([f3, f1, f2])
        assert [s for _, s in result] == [5, 8, 9]

    def test_logs_without_score_skipped(self, tmp_path):
        from bob.manage_logs import _build_score_history
        good = self._make_log_with_score(tmp_path, "bob_20260413_100000.log", 6)
        bad = tmp_path / "bob_20260414_100000.log"
        bad.write_text("no score here")
        result = _build_score_history([good, bad])
        assert len(result) == 1
        assert result[0][1] == 6

    def test_all_without_score(self, tmp_path):
        from bob.manage_logs import _build_score_history
        f = tmp_path / "bob_20260413_100000.log"
        f.write_text("no score")
        assert _build_score_history([f]) == []

    def test_dates_correct(self, tmp_path):
        from bob.manage_logs import _build_score_history
        f1 = self._make_log_with_score(tmp_path, "bob_20260101_090000.log", 4)
        f2 = self._make_log_with_score(tmp_path, "bob_20260201_140530.log", 9)
        result = _build_score_history([f1, f2])
        assert result[0][0] == "2026-01-01 09:00"
        assert result[1][0] == "2026-02-01 14:05"


class TestRenderScoreChart:
    def _t(self, key, **kwargs):
        from bob import i18n
        i18n.init(lang="en")
        return i18n.t(key, **kwargs)

    def test_empty_history_returns_no_lines(self):
        from bob.manage_logs import _render_score_chart
        assert _render_score_chart([], self._t) == []

    def test_single_entry_renders(self):
        from bob.manage_logs import _render_score_chart
        lines = _render_score_chart([("2026-04-13 17:00", 7)], self._t)
        assert len(lines) >= 3  # title, sep, entry, sep
        combined = "\n".join(lines)
        assert "7" in combined
        assert "2026-04-13" in combined

    def test_bar_length_10(self):
        from bob.manage_logs import _render_score_chart
        lines = _render_score_chart([("2026-04-13 17:00", 5)], self._t)
        data_line = next(l for l in lines if "2026-04-13" in l)
        assert data_line.count("█") + data_line.count("░") == 10

    def test_score_10_all_filled(self):
        from bob.manage_logs import _render_score_chart
        lines = _render_score_chart([("2026-04-13 17:00", 10)], self._t)
        data_line = next(l for l in lines if "2026-04-13" in l)
        assert "░" not in data_line
        assert data_line.count("█") == 10

    def test_score_0_all_empty(self):
        from bob.manage_logs import _render_score_chart
        lines = _render_score_chart([("2026-04-13 17:00", 0)], self._t)
        data_line = next(l for l in lines if "2026-04-13" in l)
        assert "█" not in data_line
        assert data_line.count("░") == 10

    def test_at_most_20_entries_shown(self):
        from bob.manage_logs import _render_score_chart
        history = [(f"2026-01-{i+1:02d} 10:00", 5) for i in range(25)]
        lines = _render_score_chart(history, self._t)
        data_lines = [l for l in lines if "2026-01-" in l]
        assert len(data_lines) == 20

    def test_last_20_kept(self):
        from bob.manage_logs import _render_score_chart
        history = [(f"2026-{i+1:02d}-01 10:00", i) for i in range(25)]
        lines = _render_score_chart(history, self._t)
        combined = "\n".join(lines)
        assert "2026-01-01" not in combined
        assert "2026-25-01" in combined

    def test_title_contains_count(self):
        from bob.manage_logs import _render_score_chart
        history = [("2026-04-13 17:00", 7), ("2026-04-14 17:00", 8)]
        lines = _render_score_chart(history, self._t)
        title_line = lines[0]
        assert "2" in title_line

    def test_separators_present(self):
        from bob.manage_logs import _render_score_chart
        lines = _render_score_chart([("2026-04-13 17:00", 5)], self._t)
        sep_lines = [l for l in lines if "─" in l]
        assert len(sep_lines) >= 2

    def test_score_shown_as_n_over_10(self):
        from bob.manage_logs import _render_score_chart
        lines = _render_score_chart([("2026-04-13 17:00", 6)], self._t)
        data_line = next(l for l in lines if "2026-04-13" in l)
        assert "6/10" in data_line


class TestScoreHistoryDisplayedInUI:
    """Integration: score history chart appears in manage-logs output."""

    def _make_log_with_score(self, directory: Path, name: str, score: int) -> Path:
        f = directory / name
        f.write_text(f"Score   : {score}/10\n")
        return f

    def test_chart_shown_when_logs_have_scores(self, tmp_path, capsys):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        self._make_log_with_score(log_dir, "bob_20260413_170000.log", 7)
        self._make_log_with_score(log_dir, "bob_20260414_170000.log", 9)

        uc, _ = _make_user_config(str(log_dir))
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "7/10" in out
        assert "9/10" in out

    def test_chart_absent_when_no_logs(self, tmp_path, capsys):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        uc, _ = _make_user_config(str(log_dir))
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "/10" not in out

    def test_chart_includes_extra_dir_logs(self, tmp_path, capsys):
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        self._make_log_with_score(cur_dir, "bob_20260413_170000.log", 5)
        self._make_log_with_score(extra_dir, "bob_20260412_170000.log", 8)

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "5/10" in out
        assert "8/10" in out


# ---------------------------------------------------------------------------
# _extract_summary_view
# ---------------------------------------------------------------------------

class TestExtractSummaryView:
    """Unit tests for the summary extraction helper."""

    _SEP = "=" * 62

    def _make_log(self, findings: list[str], score: int = 7,
                  ok: int = 10, warn: int = 2, alert: int = 1) -> list[str]:
        lines = [
            self._SEP,
            "[SYSTEM INFORMATION]",
            "Host        : testhost",
            "",
            self._SEP,
            "",
        ]
        lines.extend(findings)
        lines += [
            "",
            self._SEP,
            "[AUDIT SUMMARY]",
            f"OK      : {ok}",
            f"Warning : {warn}",
            f"Alert   : {alert}",
            f"Score   : {score}/10",
            "Risk    : Medium",
            "Context : local",
            "",
        ]
        return lines

    def test_summary_block_included(self):
        from bob.manage_logs import _extract_summary_view
        lines = self._make_log([], score=8, ok=5, warn=0, alert=0)
        result = _extract_summary_view(lines)
        combined = "\n".join(result)
        assert "Score   : 8/10" in combined
        assert "OK      : 5" in combined

    def test_alert_finding_included(self):
        from bob.manage_logs import _extract_summary_view
        findings = ["2026-04-24 [ALERT] SSH password auth enabled"]
        lines = self._make_log(findings, alert=1)
        result = _extract_summary_view(lines)
        combined = "\n".join(result)
        assert "ALERTS" in combined
        assert "SSH password auth enabled" in combined

    def test_warn_finding_included(self):
        from bob.manage_logs import _extract_summary_view
        findings = ["2026-04-24 [WARN] Unattended-upgrades not configured"]
        lines = self._make_log(findings, warn=1)
        result = _extract_summary_view(lines)
        combined = "\n".join(result)
        assert "WARNINGS" in combined
        assert "Unattended-upgrades" in combined

    def test_ok_info_findings_not_in_alerts_or_warnings(self):
        from bob.manage_logs import _extract_summary_view
        findings = [
            "2026-04-24 [OK] Firewall active",
            "2026-04-24 [INFO] GeoIP not installed",
        ]
        lines = self._make_log(findings, ok=1, warn=0, alert=0)
        result = _extract_summary_view(lines)
        combined = "\n".join(result)
        assert "ALERTS" not in combined
        assert "WARNINGS" not in combined
        assert "✔  No alerts or warnings" in combined

    def test_continuation_lines_included(self):
        from bob.manage_logs import _extract_summary_view
        findings = [
            "2026-04-24 [ALERT] SSH issue",
            "    Detail: PasswordAuthentication yes",
        ]
        lines = self._make_log(findings, alert=1)
        result = _extract_summary_view(lines)
        combined = "\n".join(result)
        assert "PasswordAuthentication yes" in combined

    def test_empty_log_returns_fallback(self):
        from bob.manage_logs import _extract_summary_view
        result = _extract_summary_view([])
        assert result  # never empty

    def test_no_summary_block_still_returns_findings(self):
        from bob.manage_logs import _extract_summary_view
        lines = ["2026-04-24 [ALERT] Critical issue"]
        result = _extract_summary_view(lines)
        combined = "\n".join(result)
        assert "Critical issue" in combined


# ---------------------------------------------------------------------------
# .stat() OSError fallback — regression for v0.2.1 fix
# ---------------------------------------------------------------------------

class TestStatFallback:
    """
    Verify the OSError fallback for .stat() in the plain-text display loops.

    A log file can disappear between the glob scan and the display loop
    (e.g. logrotate running concurrently).  Both loops must fall back to
    (size_kb=0, mtime="?") instead of propagating the OSError.
    """

    def test_cur_logs_stat_oserror_uses_fallback(self, tmp_path, capsys):
        """cur_logs loop: OSError on .stat() → output shows 0 KB and '?'."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _make_log(log_dir, "bob_20260101_120000.log")

        uc, _ = _make_user_config(str(log_dir))
        inputs = iter(["q"])

        with patch.object(Path, "stat", _stat_raises_for_logs), \
             patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "(0 " in out
        assert "?" in out

    def test_extra_logs_stat_oserror_uses_fallback(self, tmp_path, capsys):
        """extra_sections loop: OSError on .stat() → output shows 0 KB and '?'."""
        cur_dir = tmp_path / "current"
        extra_dir = tmp_path / "previous"
        cur_dir.mkdir()
        extra_dir.mkdir()
        _make_log(extra_dir, "bob_20260101_120000.log")

        uc, _ = _make_user_config(str(cur_dir), extra_dirs=[str(extra_dir)])
        inputs = iter(["q"])

        with patch.object(Path, "stat", _stat_raises_for_logs), \
             patch("builtins.input", side_effect=inputs):
            from bob.manage_logs import run_manage_logs
            run_manage_logs(uc, _make_config(), _t)

        out = capsys.readouterr().out
        assert "(0 " in out
        assert "?" in out


# ---------------------------------------------------------------------------
# I-2 (v0.5.7): Ctrl-D (EOFError) at input() prompts must not crash with
# a Python traceback. Match the _rl() convention: treat as empty answer.
# ---------------------------------------------------------------------------

class TestEOFErrorOnPromptPath:
    def test_eoferror_returns_default(self, tmp_path):
        """prompt_path() must treat Ctrl-D as 'use default', not crash."""
        from bob.manage_logs import prompt_path
        default = tmp_path / "default-logs"
        with patch("builtins.input", side_effect=EOFError):
            result = prompt_path("ignored", default)
        assert result == default

    def test_eoferror_returns_default_with_allow_cancel(self, tmp_path):
        """Even with allow_cancel=True, Ctrl-D is not 'cancel' — it's 'empty
        input' which falls through to the default. Explicit 'q'/'quit' is
        still the cancel signal."""
        from bob.manage_logs import prompt_path
        default = tmp_path / "default-logs"
        with patch("builtins.input", side_effect=EOFError):
            result = prompt_path("ignored", default, allow_cancel=True)
        assert result == default


class TestEOFErrorOnMoveConfirm:
    def test_ctrl_d_at_move_prompt_does_not_crash(self, tmp_path):
        """Ctrl-D at the [y/N] move prompt must be treated as 'no' and the
        loop continues without raising EOFError."""
        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        log_path = _make_log(old_dir, "bob_2026-01-01.log")

        uc, store = _make_user_config(str(old_dir))
        # 'c' enters change-location; move prompt sees EOFError → cancel; 'q' quits
        responses = ["c", EOFError, "q"]
        it = iter(responses)

        def _next(*_, **__):
            v = next(it)
            if isinstance(v, type) and issubclass(v, BaseException):
                raise v()
            return v

        with patch("builtins.input", side_effect=_next), \
             patch("bob.manage_logs.prompt_path", side_effect=[new_dir]):
            from bob.manage_logs import run_manage_logs
            rc = run_manage_logs(uc, _make_config(), _t)

        assert rc == 0
        assert store["log_dir"] == str(new_dir)  # dir change still applied
        assert log_path.exists()  # but log NOT moved (Ctrl-D == decline)


class TestEOFErrorOnDeleteAllConfirm:
    def test_ctrl_d_at_delete_all_prompt_does_not_crash(self, tmp_path):
        """Ctrl-D at the 'all' confirmation must cancel the deletion without
        raising EOFError out of _run_manage_logs_plain."""
        cur_dir = tmp_path / "logs"
        cur_dir.mkdir()
        log_path = _make_log(cur_dir, "bob_2026-01-01.log")

        uc, _ = _make_user_config(str(cur_dir))
        responses = ["all", EOFError, "q"]
        it = iter(responses)

        def _next(*_, **__):
            v = next(it)
            if isinstance(v, type) and issubclass(v, BaseException):
                raise v()
            return v

        with patch("builtins.input", side_effect=_next):
            from bob.manage_logs import run_manage_logs
            rc = run_manage_logs(uc, _make_config(), _t)

        assert rc == 0
        assert log_path.exists()  # NOT deleted — Ctrl-D was treated as 'no'


# ---------------------------------------------------------------------------
# M-1 (v0.5.7): when 'deleted_one' is shown, the displayed name must be the
# file that was actually deleted, not pending_delete[0] which might be a
# different (failed) entry under selective permission errors.
# ---------------------------------------------------------------------------

class TestDeletedOneCorrectName:
    def test_unlink_logic_picks_first_success(self, tmp_path):
        """Direct unit test of the M-1 fix logic — iterate over a reverse-
        sorted index list, skip OSError, capture the FIRST successful name."""
        files = [tmp_path / f"bob_{i}.log" for i in range(3)]
        for f in files:
            f.write_text("x")
        # Simulate the marked-for-delete indices (the user marked all 3)
        pending_delete = [0, 1, 2]
        # Make index 0 and 1 fail on unlink (e.g., permission denied);
        # only index 2 succeeds. Pre-M-1 code displayed files[0].name; post-fix
        # must display files[2].name.
        deleted = 0
        deleted_name = None
        for li in sorted(pending_delete, reverse=True):  # iterates 2, 1, 0
            try:
                name = files[li].name
                if li in (0, 1):
                    raise OSError("simulated permission denied")
                files[li].unlink()
                deleted += 1
                if deleted_name is None:
                    deleted_name = name
            except OSError:
                pass
        assert deleted == 1
        assert deleted_name == "bob_2.log"  # NOT bob_0.log (the pre-M-1 bug)
