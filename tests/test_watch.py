"""
Tests for bob/watch.py — --watch mode.

Covers:
  - _score_bar: output format and edge cases
  - _NullReport: silently accepts any method call
  - CLI parsing: --watch, --watch=N, --watch N
  - CLI validation: interval < 10s, non-integer
  - Mutual exclusion: --watch + --diff, --watch + --fix
  - run_watch: KeyboardInterrupt during sleep exits cleanly
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from bob.report import NullReport
from bob.watch import _score_bar
from bob.cli import AuditConfig, CLIError, parse_args


# ---------------------------------------------------------------------------
# _score_bar
# ---------------------------------------------------------------------------

@pytest.fixture
def _no_color_output():
    """Force monochrome output so bar assertions see only block chars.

    bob.output._c defaults to _COLOURS_ON; these tests assert the bare
    "█"/"░" glyphs, so they only passed when an unrelated test happened to
    leave _c = _COLOURS_OFF. Under deterministic ordering that leak isn't
    guaranteed — make the colour state explicit and restore it after."""
    from bob import output
    output.init(no_color=True)
    yield
    output.init(no_color=False)


@pytest.mark.usefixtures("_no_color_output")
class TestScoreBar:
    def test_zero_is_all_empty(self):
        assert _score_bar(0) == "░░░░░░░░░░"

    def test_ten_is_all_filled(self):
        assert _score_bar(10) == "██████████"

    def test_seven_has_seven_filled(self):
        bar = _score_bar(7)
        assert bar.count("█") == 7
        assert bar.count("░") == 3

    def test_length_always_10(self):
        for score in range(11):
            assert len(_score_bar(score)) == 10

    def test_negative_clamped_to_zero(self):
        assert _score_bar(-5) == "░░░░░░░░░░"

    def test_above_10_clamped(self):
        assert _score_bar(15) == "██████████"

    def test_filled_before_empty(self):
        """Filled blocks precede empty blocks."""
        bar = _score_bar(5)
        assert bar == "█████░░░░░"

    def test_one_filled(self):
        assert _score_bar(1) == "█░░░░░░░░░"

    def test_nine_filled(self):
        assert _score_bar(9) == "█████████░"


# ---------------------------------------------------------------------------
# NullReport (used by watch loop) — M-2 (v0.5.5): bob.watch._NullReport
# removed in favour of bob.report.NullReport (the canonical Protocol impl
# introduced in v0.5.0 alongside the Report Protocol).
# ---------------------------------------------------------------------------

class TestNullReport:
    def test_write_section_does_not_raise(self):
        r = NullReport()
        r.write_section("anything")  # must not raise

    def test_write_finding_does_not_raise(self):
        r = NullReport()
        r.write_finding("INFO", "msg")

    def test_multiple_calls_no_error(self):
        r = NullReport()
        for i in range(100):
            r.write_section(f"section {i}")

    def test_enabled_flag_is_false(self):
        """NullReport.enabled must be False so write-guards behave correctly."""
        assert NullReport().enabled is False


# ---------------------------------------------------------------------------
# CLI: --watch parsing
# ---------------------------------------------------------------------------

class TestWatchCLIParsing:
    def test_watch_alone_defaults_60(self):
        cfg = parse_args(["--watch"])
        assert cfg.watch_mode
        assert cfg.watch_interval == 60

    def test_watch_equals_30(self):
        cfg = parse_args(["--watch=30"])
        assert cfg.watch_mode
        assert cfg.watch_interval == 30

    def test_watch_equals_10_minimum(self):
        cfg = parse_args(["--watch=10"])
        assert cfg.watch_mode
        assert cfg.watch_interval == 10

    def test_watch_space_separated(self):
        cfg = parse_args(["--watch", "120"])
        assert cfg.watch_mode
        assert cfg.watch_interval == 120

    def test_watch_large_interval(self):
        cfg = parse_args(["--watch=3600"])
        assert cfg.watch_mode
        assert cfg.watch_interval == 3600

    def test_watch_default_interval_is_60(self):
        """Interval field defaults to 60 even without --watch."""
        cfg = AuditConfig()
        assert cfg.watch_interval == 60

    def test_watch_mode_default_false(self):
        cfg = AuditConfig()
        assert not cfg.watch_mode


# ---------------------------------------------------------------------------
# CLI: --watch validation errors
# ---------------------------------------------------------------------------

class TestWatchCLIValidation:
    def test_interval_below_10_raises(self):
        with pytest.raises(CLIError, match="10 seconds"):
            parse_args(["--watch=9"])

    def test_interval_zero_raises(self):
        with pytest.raises(CLIError, match="10 seconds"):
            parse_args(["--watch=0"])

    def test_non_integer_raises(self):
        with pytest.raises(CLIError, match="integer"):
            parse_args(["--watch=abc"])

    def test_float_raises(self):
        with pytest.raises(CLIError, match="integer"):
            parse_args(["--watch=1.5"])

    def test_empty_value_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--watch="])

    def test_space_separated_below_10_raises(self):
        with pytest.raises(CLIError, match="10 seconds"):
            parse_args(["--watch", "5"])

    def test_space_separated_non_integer_raises(self):
        with pytest.raises(CLIError, match="integer"):
            parse_args(["--watch", "xyz"])


# ---------------------------------------------------------------------------
# CLI: mutual exclusion
# ---------------------------------------------------------------------------

class TestWatchMutualExclusion:
    def test_watch_and_diff_raises(self):
        with pytest.raises(CLIError, match="Incompatible"):
            parse_args(["--watch", "--diff"])

    def test_watch_and_fix_raises(self):
        with pytest.raises(CLIError, match="Incompatible"):
            parse_args(["--watch", "--fix"])

    def test_watch_and_manage_logs_raises(self):
        with pytest.raises(CLIError, match="Incompatible"):
            parse_args(["--watch", "--manage-logs"])

    def test_watch_and_install_cron_raises(self):
        with pytest.raises(CLIError, match="Incompatible"):
            parse_args(["--watch", "--install-cron"])

    def test_watch_compatible_with_verbose(self):
        cfg = parse_args(["--watch", "--verbose"])
        assert cfg.watch_mode
        assert cfg.verbose

    def test_watch_compatible_with_french(self):
        cfg = parse_args(["--watch", "--french"])
        assert cfg.watch_mode
        assert cfg.lang == "fr"

    def test_watch_compatible_with_offline(self):
        cfg = parse_args(["--watch", "--offline"])
        assert cfg.watch_mode
        assert cfg.offline

    def test_watch_compatible_with_profile(self):
        cfg = parse_args(["--watch", "--profile=desktop"])
        assert cfg.watch_mode
        assert cfg.profile == "desktop"

    def test_watch_and_json_raises(self):
        with pytest.raises(CLIError, match="Incompatible|incompatible"):
            parse_args(["--watch", "--json"])

    def test_watch_and_csv_raises(self):
        with pytest.raises(CLIError, match="incompatible"):
            parse_args(["--watch", "--output=csv"])

    def test_json_then_watch_raises(self):
        with pytest.raises(CLIError, match="incompatible"):
            parse_args(["--json", "--watch"])

    def test_csv_then_watch_raises(self):
        with pytest.raises(CLIError, match="incompatible"):
            parse_args(["--output=csv", "--watch"])


# ---------------------------------------------------------------------------
# CLI: --watch duplicate detection
# ---------------------------------------------------------------------------

class TestWatchDuplicate:
    def test_watch_equals_twice_raises(self):
        with pytest.raises(CLIError, match="more than once"):
            parse_args(["--watch=30", "--watch=60"])

    def test_watch_standalone_then_equals_raises(self):
        with pytest.raises(CLIError, match="more than once"):
            parse_args(["--watch", "--watch=60"])

    def test_watch_space_then_equals_raises(self):
        with pytest.raises(CLIError, match="more than once"):
            parse_args(["--watch", "30", "--watch=60"])

    def test_watch_standalone_twice_raises(self):
        with pytest.raises(CLIError, match="more than once"):
            parse_args(["--watch", "--watch"])


# ---------------------------------------------------------------------------
# CLI: --watch exotic but valid inputs
# ---------------------------------------------------------------------------

class TestWatchExoticInputs:
    def test_watch_space_separated_with_surrounding_spaces(self):
        """Value is stripped before parsing — '  30  ' → 30."""
        cfg = parse_args(["--watch", "  30  "])
        assert cfg.watch_interval == 30

    def test_watch_plus_sign_prefix(self):
        """Python int('+30') == 30 — explicit positive sign is accepted."""
        cfg = parse_args(["--watch=+30"])
        assert cfg.watch_interval == 30

    def test_watch_leading_zero(self):
        """'010' → int 10 in Python 3 (no octal interpretation)."""
        cfg = parse_args(["--watch=010"])
        assert cfg.watch_interval == 10

    def test_watch_very_large_interval(self):
        """No overflow — arbitrarily large intervals are accepted."""
        cfg = parse_args(["--watch=999999999"])
        assert cfg.watch_interval == 999999999

    def test_watch_interval_is_int_type(self):
        """watch_interval must always be an int, never a string or float."""
        cfg = parse_args(["--watch=30"])
        assert isinstance(cfg.watch_interval, int)

    def test_watch_interval_not_none_after_standalone_watch(self):
        cfg = parse_args(["--watch"])
        assert cfg.watch_interval is not None
        assert isinstance(cfg.watch_interval, int)

    def test_watch_followed_by_flag_not_consumed_as_interval(self):
        """'--watch --verbose': --verbose starts with '-' → not consumed as N."""
        cfg = parse_args(["--watch", "--verbose"])
        assert cfg.watch_mode
        assert cfg.watch_interval == 60
        assert cfg.verbose


# ---------------------------------------------------------------------------
# _score_bar: type enforcement
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("_no_color_output")
class TestScoreBarTypes:
    def test_float_raises_type_error(self):
        """_score_bar enforces int — float input must raise TypeError."""
        with pytest.raises(TypeError):
            _score_bar(7.8)

    def test_string_raises_type_error(self):
        with pytest.raises(TypeError):
            _score_bar("5")

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError):
            _score_bar(None)

    def test_bool_raises_type_error(self):
        """I-4 (v0.7.1): bool is a subclass of int in Python — without an
        explicit ``isinstance(score, bool)`` guard, ``isinstance(True, int)``
        returns True and ``_score_bar(True)`` silently produced "█░░░░░░░░░".
        v0.7.1 rejects bool explicitly, matching the v0.7.0 Phase 2.1 I-3
        guard on ``ScoreEngine.set_posture``."""
        with pytest.raises(TypeError):
            _score_bar(True)
        with pytest.raises(TypeError):
            _score_bar(False)

    def test_only_expected_unicode_chars(self):
        """Output must contain only the two block characters, nothing else."""
        for score in range(11):
            bar = _score_bar(score)
            assert set(bar) <= {"█", "░"}, f"Unexpected char in bar for score={score}"


# M-2 (v0.5.5): TestNullReportIsolation removed — those tests exercised
# the `__getattr__` magic of the old `bob.watch._NullReport`, which no
# longer exists. The replacement `bob.report.NullReport` has explicit
# write_* methods (the Report protocol contract), not catch-all attr
# access; isolation tests are no longer applicable.

# ---------------------------------------------------------------------------
# run_watch: KeyboardInterrupt exits cleanly
# ---------------------------------------------------------------------------

class TestWatchKeyboardInterrupt:
    """run_watch must catch KeyboardInterrupt and return 0."""

    def _make_minimal_result(self):
        """Minimal object that satisfies build_baseline(engine, ports, snapshots)."""
        ns = SimpleNamespace()
        ns.ports_snapshot = None
        ns.snapshots      = {}
        return ns

    def test_keyboard_interrupt_during_sleep_returns_0(self):
        """time.sleep raises KeyboardInterrupt → run_watch returns 0, no exception."""
        from bob.watch import run_watch
        from bob.cli import AuditConfig

        config   = AuditConfig()
        t        = lambda key, **kw: key
        output   = MagicMock()

        fake_engine = MagicMock()
        fake_engine.score    = 8
        fake_engine.finalize = MagicMock()
        fake_engine.raw_score = 10  # numeric for the F1 cap check in apply_domain_score_override

        fake_baseline = MagicMock()

        minimal_result = self._make_minimal_result()

        with (
            patch("bob.watch.detect_network_context", return_value=(MagicMock(), None)),
            patch("bob.watch.run_checks",             return_value=minimal_result),
            patch("bob.watch.ScoreEngine",            return_value=fake_engine),
            patch("bob.watch.build_baseline",         return_value=fake_baseline),
            patch("bob.watch.save_baseline"),
            patch("bob.watch.time.sleep",             side_effect=KeyboardInterrupt),
        ):
            rc = run_watch(
                config,
                interval=10,
                t=t,
                output_mod=output,
                registry=MagicMock(),
                active_profile=MagicMock(),
                VERSION="test",
            )

        assert rc == 0

    def test_keyboard_interrupt_calls_stopped_message(self):
        """run_watch prints the 'watch.stopped' translation key on Ctrl+C."""
        from bob.watch import run_watch
        from bob.cli import AuditConfig

        config   = AuditConfig()
        t        = lambda key, **kw: key
        output   = MagicMock()

        fake_engine = MagicMock()
        fake_engine.score    = 5
        fake_engine.finalize = MagicMock()
        fake_engine.raw_score = 10  # numeric for the F1 cap check in apply_domain_score_override

        minimal_result = self._make_minimal_result()

        with (
            patch("bob.watch.detect_network_context", return_value=(MagicMock(), None)),
            patch("bob.watch.run_checks",             return_value=minimal_result),
            patch("bob.watch.ScoreEngine",            return_value=fake_engine),
            patch("bob.watch.build_baseline",         return_value=MagicMock()),
            patch("bob.watch.save_baseline"),
            patch("bob.watch.time.sleep",             side_effect=KeyboardInterrupt),
        ):
            run_watch(
                config,
                interval=10,
                t=t,
                output_mod=output,
                registry=MagicMock(),
                active_profile=MagicMock(),
                VERSION="test",
            )

        output.print_info.assert_called_once_with("watch.stopped")


# ---------------------------------------------------------------------------
# I-1 (v0.7.1): watch mode must propagate ignore_keys + posture escalation
# ---------------------------------------------------------------------------

class TestWatchContractParity:
    """I-1 (v0.7.1): watch loop must propagate ``ignore_keys`` and call
    ``engine.set_posture(...)`` the same way ``bob/__main__.py`` does for
    the non-watch audit path.

    Pre-v0.7.1, the watch loop created a fresh ``ScoreEngine()`` per
    iteration and never set ``ignore_keys`` nor called ``set_posture``.
    Result: a host whose UFW just went down kept showing ``LOW risk`` on
    ``bob --watch`` even though the next non-watch audit would correctly
    escalate to HIGH; previously ignored findings reappeared and inflated
    the visible deductions every iteration."""

    def _make_minimal_result(self, fw_active: bool = True):
        ns = SimpleNamespace()
        ns.ports_snapshot = None
        ns.snapshots      = {}
        ns.fw_active      = fw_active
        return ns

    def test_watch_loads_ignore_keys_into_engine(self):
        """I-1: ``engine.ignore_keys = load_ignore_keys()`` must be called
        per iteration so user-suppressed findings stay suppressed."""
        from bob.watch import run_watch
        from bob.cli import AuditConfig

        config   = AuditConfig()
        t        = lambda key, **kw: key
        output   = MagicMock()

        fake_engine = MagicMock()
        fake_engine.score    = 8
        fake_engine.findings = []
        fake_engine.domain_scores = {}
        fake_engine.finalize = MagicMock()
        fake_engine.raw_score = 10  # numeric for the F1 cap check in apply_domain_score_override
        fake_engine.effective_level.value = "low"

        minimal_result = self._make_minimal_result(fw_active=True)
        sentinel_ignore = frozenset({"ssh.permit_root_login"})

        with (
            patch("bob.watch.detect_network_context", return_value=(MagicMock(), None)),
            patch("bob.watch.run_checks",             return_value=minimal_result),
            patch("bob.watch.ScoreEngine",            return_value=fake_engine),
            patch("bob.watch.build_baseline",         return_value=MagicMock()),
            patch("bob.watch.save_baseline"),
            patch("bob.watch.load_ignore_keys",       return_value=sentinel_ignore) as mock_load,
            patch("bob.watch.time.sleep",             side_effect=KeyboardInterrupt),
        ):
            run_watch(
                config, interval=10, t=t, output_mod=output,
                registry=MagicMock(), active_profile=MagicMock(), VERSION="test",
            )

        mock_load.assert_called_once()
        # The engine must have received the same frozenset.
        assert fake_engine.ignore_keys == sentinel_ignore

    def test_watch_calls_set_posture_with_firewall_state(self):
        """I-1: ``engine.set_posture(firewall_inactive=not fw_active, ...)``
        must fire per iteration so posture escalation propagates."""
        from bob.watch import run_watch
        from bob.cli import AuditConfig

        config   = AuditConfig()
        t        = lambda key, **kw: key
        output   = MagicMock()

        fake_engine = MagicMock()
        fake_engine.score    = 8
        fake_engine.findings = []
        fake_engine.domain_scores = {"firewall": {"score": 3}}
        fake_engine.finalize = MagicMock()
        fake_engine.raw_score = 10  # numeric for the F1 cap check in apply_domain_score_override
        fake_engine.effective_level.value = "high"

        # firewall_inactive scenario
        minimal_result = self._make_minimal_result(fw_active=False)

        with (
            patch("bob.watch.detect_network_context", return_value=(MagicMock(), None)),
            patch("bob.watch.run_checks",             return_value=minimal_result),
            patch("bob.watch.ScoreEngine",            return_value=fake_engine),
            patch("bob.watch.build_baseline",         return_value=MagicMock()),
            patch("bob.watch.save_baseline"),
            patch("bob.watch.load_ignore_keys",       return_value=frozenset()),
            patch("bob.watch.time.sleep",             side_effect=KeyboardInterrupt),
        ):
            run_watch(
                config, interval=10, t=t, output_mod=output,
                registry=MagicMock(), active_profile=MagicMock(), VERSION="test",
            )

        fake_engine.set_posture.assert_called_once()
        call_kwargs = fake_engine.set_posture.call_args.kwargs
        assert call_kwargs["firewall_inactive"] is True  # not fw_active
        assert call_kwargs["firewall_domain_score"] == 3
