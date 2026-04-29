"""
Unit tests for bob.cron module.

Run with: python -m pytest tests/test_cron.py -v
"""

import pytest
from pathlib import Path
from unittest.mock import patch
from bob.cron import (
    CronEntry,
    build_schedule_expr,
    cron_to_human,
    make_slug,
    parse_cron_file,
    suggest_name,
    _detect_mta,
    _ordinal,
    _parse_day_names,
    _parse_dom,
)


# ---------------------------------------------------------------------------
# build_schedule_expr
# ---------------------------------------------------------------------------

class TestBuildScheduleExpr:
    def test_daily(self):
        assert build_schedule_expr(1, hour=3, minute=0) == "0 3 * * *"

    def test_daily_custom_time(self):
        assert build_schedule_expr(1, hour=23, minute=45) == "45 23 * * *"

    def test_weekdays_single(self):
        assert build_schedule_expr(2, hour=2, minute=30, week_days=[1]) == "30 2 * * 1"

    def test_weekdays_multiple(self):
        result = build_schedule_expr(2, hour=3, minute=0, week_days=[1, 3, 5])
        assert result == "0 3 * * 1,3,5"

    def test_weekdays_sorted(self):
        result = build_schedule_expr(2, hour=3, minute=0, week_days=[5, 1, 3])
        assert result == "0 3 * * 1,3,5"

    def test_monthdays_single(self):
        assert build_schedule_expr(3, hour=4, minute=0, month_days=[1]) == "0 4 1 * *"

    def test_monthdays_multiple(self):
        result = build_schedule_expr(3, hour=4, minute=0, month_days=[1, 15])
        assert result == "0 4 1,15 * *"

    def test_monthdays_sorted(self):
        result = build_schedule_expr(3, hour=4, minute=0, month_days=[28, 1, 15])
        assert result == "0 4 1,15,28 * *"

    def test_custom_expression(self):
        expr = "0 */6 * * *"
        assert build_schedule_expr(4, hour=0, minute=0, custom_expr=expr) == expr

    def test_custom_with_whitespace(self):
        expr = "  0 3 * * 1  "
        assert build_schedule_expr(4, hour=0, minute=0, custom_expr=expr) == "0 3 * * 1"

    def test_invalid_choice_raises(self):
        with pytest.raises(ValueError):
            build_schedule_expr(9, hour=3, minute=0)


# ---------------------------------------------------------------------------
# cron_to_human
# ---------------------------------------------------------------------------

class TestCronToHuman:
    def test_every_day_en(self):
        assert cron_to_human("0 3 * * *", "en") == "every day at 03:00"

    def test_every_day_fr(self):
        assert cron_to_human("0 3 * * *", "fr") == "tous les jours à 03:00"

    def test_every_day_midnight(self):
        assert cron_to_human("0 0 * * *", "en") == "every day at 00:00"

    def test_single_weekday_en(self):
        result = cron_to_human("0 3 * * 1", "en")
        assert "Monday" in result
        assert "03:00" in result

    def test_multiple_weekdays_en(self):
        result = cron_to_human("0 3 * * 1,3,5", "en")
        assert "Monday" in result
        assert "Wednesday" in result
        assert "Friday" in result

    def test_weekday_fr(self):
        result = cron_to_human("0 2 * * 2", "fr")
        assert "mardi" in result
        assert "02:00" in result

    def test_single_monthday_en(self):
        result = cron_to_human("0 4 1 * *", "en")
        assert "1st" in result
        assert "every month" in result

    def test_multiple_monthdays_en(self):
        result = cron_to_human("0 4 1,15 * *", "en")
        assert "1st" in result
        assert "15th" in result

    def test_monthday_fr(self):
        result = cron_to_human("0 4 1 * *", "fr")
        assert "1" in result
        assert "mois" in result

    def test_custom_fallback_en(self):
        expr = "0 */6 * * 1-5"
        result = cron_to_human(expr, "en")
        assert "custom expression" in result
        assert expr in result

    def test_custom_fallback_fr(self):
        expr = "0 */6 * * 1-5"
        result = cron_to_human(expr, "fr")
        assert "personnalisée" in result

    def test_invalid_expr_returned_as_is(self):
        assert cron_to_human("not-a-cron", "en") == "not-a-cron"

    def test_time_padding(self):
        result = cron_to_human("5 9 * * *", "en")
        assert "09:05" in result

    def test_multiple_weekdays_fr(self):
        """Multiple weekdays should be comma-joined using French day names."""
        result = cron_to_human("0 3 * * 1,3,5", "fr")
        assert "lundi" in result
        assert "mercredi" in result
        assert "vendredi" in result
        assert "03:00" in result

    def test_unknown_lang_does_not_crash(self):
        """An unrecognised language code must return a non-empty string."""
        result = cron_to_human("0 3 * * *", "de")
        assert result  # non-empty — falls back to French branch


# ---------------------------------------------------------------------------
# make_slug
# ---------------------------------------------------------------------------

class TestMakeSlug:
    def test_simple_name(self):
        assert make_slug("nightly") == "nightly"

    def test_spaces_replaced(self):
        assert make_slug("my audit") == "my-audit"

    def test_uppercase_lowercased(self):
        assert make_slug("Nightly") == "nightly"

    def test_special_chars_stripped(self):
        assert make_slug("my/audit!") == "my-audit"

    def test_leading_trailing_hyphens_removed(self):
        assert make_slug("--nightly--") == "nightly"

    def test_empty_returns_custom(self):
        assert make_slug("") == "custom"

    def test_only_special_chars(self):
        assert make_slug("!!!") == "custom"

    def test_numbers_preserved(self):
        assert make_slug("audit-2") == "audit-2"


# ---------------------------------------------------------------------------
# suggest_name
# ---------------------------------------------------------------------------

class TestSuggestName:
    def test_suggests_nightly_when_empty(self):
        assert suggest_name([]) == "nightly"

    def test_skips_existing_nightly(self):
        assert suggest_name(["nightly"]) == "daily"

    def test_skips_multiple(self):
        assert suggest_name(["nightly", "daily", "weekly", "monthly"]) == "audit-2"

    def test_increments_suffix(self):
        assert suggest_name(["nightly", "daily", "weekly", "monthly", "audit-2"]) == "audit-3"


# ---------------------------------------------------------------------------
# parse_cron_file
# ---------------------------------------------------------------------------

class TestParseCronFile:
    def _write_cron(self, tmp_path, content, name="bob-test"):
        p = tmp_path / name
        p.write_text(content)
        return p

    def test_parses_v013_cron(self, tmp_path):
        content = (
            "# BOB cron — generated 2026-03-24 by bob --install-cron\n"
            "# name: nightly\n"
            "# email: user@example.com\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin\n\n"
            "0 3 * * *  root  /usr/local/bin/bob-nightly\n"
        )
        p = self._write_cron(tmp_path, content)
        entry = parse_cron_file(p)
        assert entry is not None
        assert entry.name == "nightly"
        assert entry.email == "user@example.com"
        assert entry.schedule_expr == "0 3 * * *"
        assert entry.hour == 3
        assert entry.minute == 0
        assert entry.script_path == Path("/usr/local/bin/bob-nightly")

    def test_parses_no_email(self, tmp_path):
        content = (
            "# name: weekly\n"
            "# email: \n"
            "SHELL=/bin/bash\n\n"
            "0 2 * * 1  root  /usr/local/bin/bob-weekly\n"
        )
        p = self._write_cron(tmp_path, content, "bob-weekly")
        entry = parse_cron_file(p)
        assert entry is not None
        assert entry.email == ""
        assert entry.schedule_expr == "0 2 * * 1"

    def test_legacy_cron_name_fallback(self, tmp_path):
        content = (
            "# BOB daily audit — generated 2025-01-01\n"
            "SHELL=/bin/bash\n\n"
            "0 3 * * *  root  /usr/local/bin/bob-nightly\n"
        )
        p = self._write_cron(tmp_path, content, "bob")
        entry = parse_cron_file(p, legacy=True)
        assert entry is not None
        assert entry.name == "nightly"
        assert entry.legacy

    def test_returns_none_for_missing_cron_line(self, tmp_path):
        content = "# name: broken\n# email: \nSHELL=/bin/bash\n"
        p = self._write_cron(tmp_path, content)
        assert parse_cron_file(p) is None

    def test_returns_none_for_unreadable_file(self, tmp_path):
        p = tmp_path / "ghost"
        assert parse_cron_file(p) is None

    def test_name_derived_from_filename_when_no_metadata(self, tmp_path):
        content = (
            "SHELL=/bin/bash\n\n"
            "0 3 * * *  root  /usr/local/bin/bob-monthly\n"
        )
        p = self._write_cron(tmp_path, content, "bob-monthly")
        entry = parse_cron_file(p)
        assert entry is not None
        assert entry.name == "monthly"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class TestOrdinal:
    @pytest.mark.parametrize("n,expected", [
        (1,  "1st"),
        (2,  "2nd"),
        (3,  "3rd"),
        (4,  "4th"),
        (11, "11th"),  # teen exceptions — must use "th" regardless of last digit
        (12, "12th"),
        (13, "13th"),
        (21, "21st"),  # non-teen: last digit 1 → "st"
        (22, "22nd"),
        (31, "31st"),
    ])
    def test_ordinal(self, n, expected):
        assert _ordinal(n) == expected


class TestParseDayNames:
    def test_single_day_en(self):
        from bob.cron import _DAYS_EN
        assert _parse_day_names("1", _DAYS_EN) == ["Monday"]

    def test_multiple_days_en(self):
        from bob.cron import _DAYS_EN
        assert _parse_day_names("1,3,5", _DAYS_EN) == ["Monday", "Wednesday", "Friday"]

    def test_sunday_is_7(self):
        from bob.cron import _DAYS_EN
        assert _parse_day_names("7", _DAYS_EN) == ["Sunday"]


class TestParseDom:
    def test_single(self):
        assert _parse_dom("1") == [1]

    def test_multiple_comma(self):
        assert _parse_dom("1,15,28") == [1, 15, 28]

    def test_sorted(self):
        assert _parse_dom("28,1,15") == [1, 15, 28]

    def test_ignores_non_digits(self):
        assert _parse_dom("1,abc,15") == [1, 15]

    def test_empty_string_returns_empty(self):
        """An empty DOM field must not crash and must return an empty list."""
        assert _parse_dom("") == []


# ---------------------------------------------------------------------------
# _detect_mta
# ---------------------------------------------------------------------------

class TestDetectMta:
    def _which(self, available: list[str]):
        """Return a shutil.which mock that finds only the listed binaries."""
        def _mock(cmd, **_kw):
            return f"/usr/bin/{cmd}" if cmd in available else None
        return _mock

    def test_no_sendmail_returns_false(self):
        with patch("shutil.which", side_effect=self._which([])):
            ok, name = _detect_mta()
        assert ok is False
        assert name == ""

    def test_postfix_detected_via_config_file(self):
        with (
            patch("shutil.which", side_effect=self._which(["sendmail"])),
            patch("pathlib.Path.exists", return_value=True),
        ):
            ok, name = _detect_mta()
        assert ok is True
        assert name == "Postfix"

    def test_exim_detected(self):
        with (
            patch("shutil.which", side_effect=self._which(["sendmail", "exim4"])),
            patch("pathlib.Path.exists", return_value=False),
        ):
            ok, name = _detect_mta()
        assert ok is True
        assert name == "Exim"

    def test_msmtp_detected(self):
        with (
            patch("shutil.which", side_effect=self._which(["sendmail", "msmtp"])),
            patch("pathlib.Path.exists", return_value=False),
        ):
            ok, name = _detect_mta()
        assert ok is True
        assert name == "msmtp"

    def test_ssmtp_detected(self):
        with (
            patch("shutil.which", side_effect=self._which(["sendmail", "ssmtp"])),
            patch("pathlib.Path.exists", return_value=False),
        ):
            ok, name = _detect_mta()
        assert ok is True
        assert name == "ssmtp"

    def test_unknown_mta_returns_empty_name(self):
        with (
            patch("shutil.which", side_effect=self._which(["sendmail"])),
            patch("pathlib.Path.exists", return_value=False),
        ):
            ok, name = _detect_mta()
        assert ok is True
        assert name == ""
