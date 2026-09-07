"""How long the audit took, on screen and in the payload.

A figure an operator reads has to have a machine trace. That is the lesson
v0.16.2 took from `--target`, which printed a verdict on screen and left
nothing in the JSON for anything to check it against, so a CI gate could not
see what the human saw.

The measurement is monotonic and starts at the checks, not at process entry:
argument parsing and the root check are not the audit, and a wall clock
adjusted mid-run could otherwise produce a negative duration on the summary
line — a statement about the audit that is not true.
"""

from __future__ import annotations

import pytest


class TestTheFormatter:
    """Sub-minute runs are the normal case; a minute is where a decimal stops
    carrying information and starts being noise."""

    @staticmethod
    def _t():
        from bob import i18n
        i18n.init("en")
        return i18n.t

    @pytest.mark.parametrize("seconds,expected", [
        (0.0, "0.0 s"),
        (4.24, "4.2 s"),
        (41.0, "41.0 s"),
        (59.94, "59.9 s"),
    ])
    def test_short_runs_keep_a_decimal(self, seconds, expected):
        from bob.display import format_duration
        assert format_duration(seconds, self._t()) == expected

    @pytest.mark.parametrize("seconds,expected", [
        (60.0, "1 min 00 s"),
        (127.4, "2 min 07 s"),
        (3599.0, "59 min 59 s"),
    ])
    def test_long_runs_drop_it(self, seconds, expected):
        from bob.display import format_duration
        assert format_duration(seconds, self._t()) == expected

    def test_a_negative_duration_is_never_rendered(self):
        """Impossible from a monotonic clock, and a lie if it ever appeared."""
        from bob.display import format_duration
        assert format_duration(-3.0, self._t()) == "0.0 s"

    def test_both_locales_have_the_strings(self):
        import json
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        for lang in ("en", "fr"):
            data = json.loads((root / "bob" / "locales" / f"{lang}.json")
                              .read_text(encoding="utf-8"))
            scoring = data["scoring"]
            for key in ("duration_label", "duration_seconds", "duration_minutes"):
                assert key in scoring and scoring[key].strip(), f"{lang}: {key}"


class TestThePayloadCarriesIt:

    def test_it_is_a_required_key(self):
        """Not optional: a consumer must be able to read it without probing."""
        from bob.json_output import SCHEMA_V3_REQUIRED_KEYS
        assert "duration_seconds" in SCHEMA_V3_REQUIRED_KEYS

    def test_the_builder_accepts_and_rounds_it(self):
        import inspect
        from bob.json_output import build_json_data, _build_v3
        for fn in (build_json_data, _build_v3):
            params = inspect.signature(fn).parameters
            assert "audit_seconds" in params, f"{fn.__name__} cannot receive it"
            assert params["audit_seconds"].default is None, (
                f"{fn.__name__}: a run that did not time itself must yield null, "
                f"not a fabricated zero"
            )

    def test_a_run_that_did_not_time_itself_yields_null(self):
        """`null` and `0.0` are different claims — one is 'unknown'."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "json_output.py").read_text(encoding="utf-8")
        assert '"duration_seconds": (None if audit_seconds is None' in src

    def test_it_cannot_be_negative_in_the_payload_either(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "json_output.py").read_text(encoding="utf-8")
        assert "max(0.0, float(audit_seconds))" in src


class TestTheMeasurementIsHonest:

    @staticmethod
    def _main_src() -> str:
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent
                / "bob" / "__main__.py").read_text(encoding="utf-8")

    def test_it_uses_a_monotonic_clock(self):
        """`time.time()` can go backwards; a duration that does is a lie."""
        src = self._main_src()
        assert "_time.monotonic()" in src
        assert "_audit_started = _time.monotonic()" in src

    def test_it_starts_at_the_checks_not_at_process_entry(self):
        """Argument parsing and the root gate are not the audit."""
        src = self._main_src()
        start = src.index("_audit_started = _time.monotonic()")
        banner = src.index('t("audit.starting")')
        assert banner < start, (
            "the clock starts before the audit announces itself, so it would "
            "be counting startup rather than checks"
        )

    def test_the_summary_and_the_payload_read_the_same_number(self):
        src = self._main_src()
        assert src.count("audit_seconds = _time.monotonic() - _audit_started") == 1, (
            "the duration is computed more than once, so the screen and the "
            "payload could disagree about the same run"
        )
        assert "audit_seconds=audit_seconds" in src
