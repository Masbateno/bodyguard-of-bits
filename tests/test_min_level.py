"""
Tests for --min-level filtering and score trend arrow.

Covers:
  - output._passes_threshold: level filtering logic
  - output.init: min_level parameter sets threshold
  - display_result: OK/INFO suppressed when min_level=warn
  - display_result: WARN also suppressed when min_level=alert
  - display_result: report.write_finding always called (log unaffected)
  - CLI: --min-level=warn, --min-level=alert, --min-level warn
  - CLI: invalid value raises CLIError
  - AuditConfig default min_level is empty string
  - Score trend: prev_score None → no arrow
  - Score trend: improved → ↑, degraded → ↓, stable → = N
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from bob import output as output_mod
from bob.output import _passes_threshold, init as output_init
from bob.cli import AuditConfig, CLIError, parse_args


# ---------------------------------------------------------------------------
# _passes_threshold
# ---------------------------------------------------------------------------

class TestPassesThreshold:
    def setup_method(self):
        output_init(min_level="")  # reset to show-all before each test

    def test_all_pass_when_no_threshold(self):
        output_init(min_level="")
        for lvl in ("ok", "info", "warn", "alert"):
            assert _passes_threshold(lvl)

    def test_warn_threshold_blocks_ok(self):
        output_init(min_level="warn")
        assert not _passes_threshold("ok")

    def test_warn_threshold_blocks_info(self):
        output_init(min_level="warn")
        assert not _passes_threshold("info")

    def test_warn_threshold_passes_warn(self):
        output_init(min_level="warn")
        assert _passes_threshold("warn")

    def test_warn_threshold_passes_alert(self):
        output_init(min_level="warn")
        assert _passes_threshold("alert")

    def test_alert_threshold_blocks_warn(self):
        output_init(min_level="alert")
        assert not _passes_threshold("warn")

    def test_alert_threshold_passes_alert(self):
        output_init(min_level="alert")
        assert _passes_threshold("alert")

    def test_unknown_level_passes_when_no_threshold(self):
        output_init(min_level="")
        assert _passes_threshold("unknown")

    def test_unknown_level_blocked_when_threshold_set(self):
        """Unknown level has rank 0 — blocked when any threshold is active."""
        output_init(min_level="warn")
        assert not _passes_threshold("unknown")

    def test_case_insensitive_init(self):
        """init() lowercases the min_level value."""
        output_init(min_level="WARN")
        assert not _passes_threshold("ok")
        assert _passes_threshold("warn")

    def teardown_method(self):
        output_init(min_level="")  # reset after each test


# ---------------------------------------------------------------------------
# display_result with min_level filtering
# ---------------------------------------------------------------------------

class TestDisplayResultFiltering:
    def setup_method(self):
        output_init(min_level="")

    def teardown_method(self):
        output_init(min_level="")

    def _make_findings(self):
        from bob.scoring import Finding, FindingLevel
        return [
            Finding(level=FindingLevel.OK,    message="UFW active"),
            Finding(level=FindingLevel.INFO,   message="Port 22 covered"),
            Finding(level=FindingLevel.WARN,   message="MaxAuthTries = 6"),
            Finding(level=FindingLevel.ALERT,  message="UFW inactive"),
        ]

    def _make_result(self, findings):
        r = MagicMock()
        r.findings = findings
        return r

    def test_min_level_warn_suppresses_ok_from_terminal(self):
        output_init(min_level="warn")
        report = MagicMock()
        result = self._make_result(self._make_findings())

        from bob.display import display_result
        with patch("bob.output.print_ok") as mock_ok:
            display_result(result, report, verbose=False)
            mock_ok.assert_not_called()

    def test_min_level_warn_suppresses_info_from_terminal(self):
        output_init(min_level="warn")
        report = MagicMock()
        result = self._make_result(self._make_findings())

        from bob.display import display_result
        with patch("bob.output.print_info") as mock_info:
            display_result(result, report, verbose=False)
            mock_info.assert_not_called()

    def test_min_level_warn_still_shows_warn(self):
        output_init(min_level="warn")
        report = MagicMock()
        result = self._make_result(self._make_findings())

        from bob.display import display_result
        with patch("bob.output.print_warn") as mock_warn:
            display_result(result, report, verbose=False)
            mock_warn.assert_called_once()

    def test_min_level_warn_still_shows_alert(self):
        output_init(min_level="warn")
        report = MagicMock()
        result = self._make_result(self._make_findings())

        from bob.display import display_result
        with patch("bob.output.print_alert") as mock_alert:
            display_result(result, report, verbose=False)
            mock_alert.assert_called_once()

    def test_report_write_called_for_all_levels_regardless_of_threshold(self):
        """Log file always gets all findings, even if terminal suppresses them."""
        output_init(min_level="alert")
        report = MagicMock()
        result = self._make_result(self._make_findings())

        from bob.display import display_result
        display_result(result, report, verbose=False)

        written_levels = [c.args[0] for c in report.write_finding.call_args_list]
        assert "OK"    in written_levels
        assert "INFO"  in written_levels
        assert "WARN"  in written_levels
        assert "ALERT" in written_levels

    def test_no_threshold_shows_all(self):
        output_init(min_level="")
        report = MagicMock()
        result = self._make_result(self._make_findings())

        from bob.display import display_result
        with (
            patch("bob.output.print_ok")    as m_ok,
            patch("bob.output.print_info")  as m_info,
            patch("bob.output.print_warn")  as m_warn,
            patch("bob.output.print_alert") as m_alert,
        ):
            display_result(result, report, verbose=False)
            m_ok.assert_called_once()
            m_info.assert_called_once()
            m_warn.assert_called_once()
            m_alert.assert_called_once()

    def test_output_order_respected(self):
        """Findings must be displayed in the order they appear in result.findings."""
        output_init(min_level="")
        report = MagicMock()
        result = self._make_result(self._make_findings())  # [OK, INFO, WARN, ALERT]
        calls: list[str] = []

        from bob.display import display_result
        with (
            patch("bob.output.print_ok",    side_effect=lambda *a, **kw: calls.append("ok")),
            patch("bob.output.print_info",  side_effect=lambda *a, **kw: calls.append("info")),
            patch("bob.output.print_warn",  side_effect=lambda *a, **kw: calls.append("warn")),
            patch("bob.output.print_alert", side_effect=lambda *a, **kw: calls.append("alert")),
        ):
            display_result(result, report, verbose=False)

        assert calls == ["ok", "info", "warn", "alert"]


# ---------------------------------------------------------------------------
# CLI: --min-level parsing
# ---------------------------------------------------------------------------

class TestMinLevelCLIParsing:
    def test_min_level_warn_equals(self):
        cfg = parse_args(["--min-level=warn"])
        assert cfg.min_level == "warn"

    def test_min_level_alert_equals(self):
        cfg = parse_args(["--min-level=alert"])
        assert cfg.min_level == "alert"

    def test_min_level_warn_space(self):
        cfg = parse_args(["--min-level", "warn"])
        assert cfg.min_level == "warn"

    def test_min_level_default_empty(self):
        cfg = AuditConfig()
        assert cfg.min_level == ""

    def test_min_level_combined_with_verbose(self):
        cfg = parse_args(["--min-level=warn", "--verbose"])
        assert cfg.min_level == "warn"
        assert cfg.verbose

    def test_min_level_compatible_with_output_csv(self):
        cfg = parse_args(["--min-level=warn", "--output=csv"])
        assert cfg.min_level == "warn"
        assert cfg.csv_mode

    def test_min_level_compatible_with_quiet(self):
        """--min-level + --quiet is legal — quiet silences everything anyway."""
        cfg = parse_args(["--min-level=warn", "--quiet"])
        assert cfg.min_level == "warn"
        assert cfg.quiet

    def test_min_level_combined_with_french(self):
        cfg = parse_args(["--min-level=warn", "--french"])
        assert cfg.min_level == "warn"
        assert cfg.lang == "fr"


# ---------------------------------------------------------------------------
# CLI: --min-level validation
# ---------------------------------------------------------------------------

class TestMinLevelCLIValidation:
    def test_invalid_value_raises(self):
        with pytest.raises(CLIError, match="warn.*alert|alert.*warn"):
            parse_args(["--min-level=info"])

    def test_ok_value_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--min-level=ok"])

    def test_empty_value_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--min-level="])

    def test_uppercase_warn_lowercased(self):
        """Value is lowercased — WARN is accepted."""
        cfg = parse_args(["--min-level=WARN"])
        assert cfg.min_level == "warn"


# ---------------------------------------------------------------------------
# Score trend arrow in summary box
# ---------------------------------------------------------------------------

class TestScoreTrend:
    """print_audit_summary builds the score string based on prev_score."""

    def _score_str_for(self, score: int, prev: "int | None") -> str:
        """Extract the score value string that goes into the summary box."""
        from bob.display import print_audit_summary
        from bob import output as out_mod

        out_mod.init(no_color=True)

        engine = MagicMock()
        engine.score = score
        engine.findings = []
        engine._deductions = []
        engine.alert_count = 0
        engine.warn_count  = 0

        from bob.scoring import RiskLevel
        engine.level = RiskLevel.LOW

        captured: list[list] = []
        def fake_box(lines):
            captured.extend(lines)

        config = AuditConfig()

        with patch("bob.output.print_summary_box", side_effect=fake_box):
            print_audit_summary(
                engine, "local", None, config, lambda k, **kw: k,
                MagicMock(), {}, profile_name="server",
                prev_score=prev,
            )

        score_row = next((v for label, v in captured if "score_label" in label), "")
        return score_row

    def test_no_prev_score_no_arrow(self):
        val = self._score_str_for(7, None)
        assert val == "7/10"

    def test_improved_shows_up_arrow(self):
        val = self._score_str_for(8, 7)
        assert "↑" in val
        assert "+1" in val

    def test_degraded_shows_down_arrow(self):
        val = self._score_str_for(6, 7)
        assert "↓" in val

    def test_stable_shows_no_annotation(self):
        # Score unchanged: no delta annotation (the score itself is enough).
        val = self._score_str_for(7, 7)
        assert val == "7/10"
        assert "↑" not in val
        assert "↓" not in val

    def test_improved_by_two(self):
        val = self._score_str_for(9, 7)
        assert "+2" in val

    def test_degraded_by_three(self):
        val = self._score_str_for(4, 7)
        assert "-3" in val
