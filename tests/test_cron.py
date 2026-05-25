"""
Unit tests for bob.cron module.

Run with: python -m pytest tests/test_cron.py -v
"""

import pytest
from pathlib import Path
from unittest.mock import patch
from bob.cron import (
    CronEntry,
    apply_cron_email,
    apply_cron_schedule,
    build_schedule_expr,
    build_script_content,
    cron_to_human,
    make_slug,
    parse_cron_file,
    suggest_name,
    _detect_mta,
    _ordinal,
    _parse_day_names,
    _parse_dom,
    _validate_cron_field,
    _validate_custom_cron,
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


# ---------------------------------------------------------------------------
# _validate_cron_field — pure validation for one cron field
# ---------------------------------------------------------------------------

class TestValidateCronField:
    """Pre-Phase-5 coverage for the pure cron-field validator.

    Targets all branches: wildcard, plain integer, range, step, list,
    out-of-bounds rejection (the v0.4.3 regression that the function
    was originally written to close).
    """

    def test_wildcard_is_valid(self):
        assert _validate_cron_field("*", "minute", 0, 59) == ""

    def test_plain_integer_in_range(self):
        assert _validate_cron_field("30", "minute", 0, 59) == ""

    def test_plain_integer_out_of_range_returns_error(self):
        err = _validate_cron_field("70", "minute", 0, 59)
        assert err
        assert "out of range" in err

    def test_range_valid(self):
        assert _validate_cron_field("0-30", "minute", 0, 59) == ""

    def test_range_out_of_bounds_rejected(self):
        # v0.4.3 regression: 0-1000 used to pass the original isdigit check.
        err = _validate_cron_field("0-1000", "minute", 0, 59)
        assert err
        assert "out of bounds" in err

    def test_range_reversed_rejected(self):
        err = _validate_cron_field("30-10", "minute", 0, 59)
        assert err
        assert "reversed" in err

    def test_step_valid(self):
        assert _validate_cron_field("*/5", "minute", 0, 59) == ""

    def test_step_zero_rejected(self):
        err = _validate_cron_field("*/0", "minute", 0, 59)
        assert err
        assert "positive integer" in err

    def test_step_non_numeric_rejected(self):
        err = _validate_cron_field("*/abc", "minute", 0, 59)
        assert err

    def test_list_all_valid(self):
        assert _validate_cron_field("0,15,30,45", "minute", 0, 59) == ""

    def test_list_one_out_of_range_rejected(self):
        err = _validate_cron_field("0,15,99", "minute", 0, 59)
        assert err

    def test_empty_entry_rejected(self):
        err = _validate_cron_field("0,,30", "minute", 0, 59)
        assert err
        assert "empty entry" in err

    def test_garbage_rejected(self):
        err = _validate_cron_field("xyz", "minute", 0, 59)
        assert err
        assert "not understood" in err


# ---------------------------------------------------------------------------
# _validate_custom_cron — full 5-field cron expression
# ---------------------------------------------------------------------------

class TestValidateCustomCron:
    def test_valid_daily_3am(self):
        assert _validate_custom_cron("0 3 * * *") == ""

    def test_valid_weekly(self):
        assert _validate_custom_cron("0 3 * * 0") == ""

    def test_valid_with_steps(self):
        assert _validate_custom_cron("*/15 * * * *") == ""

    def test_four_fields_rejected(self):
        err = _validate_custom_cron("0 3 * *")
        assert err
        assert "5 fields" in err

    def test_six_fields_rejected(self):
        err = _validate_custom_cron("0 3 * * * *")
        assert err
        assert "5 fields" in err

    def test_hour_out_of_range_rejected(self):
        err = _validate_custom_cron("0 25 * * *")
        assert err
        assert "hour" in err.lower()

    def test_minute_out_of_range_rejected(self):
        err = _validate_custom_cron("70 3 * * *")
        assert err
        assert "minute" in err.lower()


# ---------------------------------------------------------------------------
# build_script_content — pure bash-script generator
# ---------------------------------------------------------------------------

class TestBuildScriptContent:
    def test_starts_with_shebang(self):
        script = build_script_content("admin@example.com", "/var/log/bob")
        assert script.startswith("#!/bin/bash\n")

    def test_quotes_email(self):
        # shlex.quote should wrap simple addresses without modification.
        script = build_script_content("admin@example.com", "/var/log/bob")
        assert "NOTIFY_EMAILS=admin@example.com" in script

    def test_quotes_email_with_special_chars(self):
        # An address with a space would never be legal, but shlex should
        # nevertheless guarantee the assignment stays single-line.
        script = build_script_content("a b", "/var/log/bob")
        assert "NOTIFY_EMAILS='a b'" in script

    def test_includes_log_dir(self):
        script = build_script_content("admin@example.com", "/custom/path")
        assert "LOG_DIR=/custom/path" in script

    def test_quotes_log_dir_with_space(self):
        script = build_script_content("a@b.c", "/path with space")
        assert "LOG_DIR='/path with space'" in script

    def test_runs_bob_quiet_detailed(self):
        script = build_script_content("a@b.c", "/var/log/bob")
        assert "--quiet --detailed" in script

    def test_exports_audit_email_and_log(self):
        script = build_script_content("a@b.c", "/var/log/bob")
        assert 'export AUDIT_EMAIL=' in script
        assert 'export AUDIT_LOG=' in script


# ---------------------------------------------------------------------------
# apply_cron_schedule — patches the cron file in place
# ---------------------------------------------------------------------------

class TestApplyCronSchedule:
    """Pre-Phase-5 coverage for the file-mutation helper extracted in v0.4.8.

    The wizard refactor (#6, Phase 5) will reuse these helpers; these
    tests pin the contract.
    """

    @staticmethod
    def _make_entry(tmp_path: Path) -> CronEntry:
        cron_path = tmp_path / "bob-test"
        script_path = tmp_path / "bob-test.sh"
        cron_path.write_text(
            "# email: admin@example.com\n"
            "0 3 * * *  root  /usr/local/bin/bob-test.sh\n",
            encoding="utf-8",
        )
        script_path.write_text(
            "#!/bin/bash\n"
            "NOTIFY_EMAILS=admin@example.com\n"
            "echo hello\n",
            encoding="utf-8",
        )
        return CronEntry(
            name="test", schedule_expr="0 3 * * *", hour=3, minute=0,
            script_path=script_path, cron_path=cron_path,
        )

    def test_replaces_schedule(self, tmp_path):
        entry = self._make_entry(tmp_path)
        err = apply_cron_schedule(entry, "30 14 * * 1")
        assert err == ""
        content = entry.cron_path.read_text(encoding="utf-8")
        assert "30 14 * * 1  root  " in content

    def test_preserves_email_comment(self, tmp_path):
        entry = self._make_entry(tmp_path)
        apply_cron_schedule(entry, "0 4 * * *")
        content = entry.cron_path.read_text(encoding="utf-8")
        assert "# email: admin@example.com" in content

    def test_missing_file_returns_error(self, tmp_path):
        bogus = CronEntry(
            name="x", schedule_expr="* * * * *", hour=0, minute=0,
            script_path=tmp_path / "missing.sh",
            cron_path=tmp_path / "missing",
        )
        err = apply_cron_schedule(bogus, "0 3 * * *")
        assert err  # OSError string surfaced to caller

    def test_comment_line_with_root_token_not_modified(self, tmp_path):
        """v0.5.5 M-10: regex must not match commented-out cron lines.

        Pre-v0.5.5 the regex was `^\\S+\\s+...` which matched any non-
        whitespace start including `#`. A comment like
        `# 0 3 * * * root /usr/bin/legacy-bob` would be silently rewritten.
        """
        cron_path = tmp_path / "bob-test"
        script_path = tmp_path / "bob-test.sh"
        cron_path.write_text(
            "# email: admin@example.com\n"
            "# legacy entry: 0 3 * * * root /usr/bin/legacy-bob\n"
            "0 3 * * *  root  /usr/local/bin/bob-test.sh\n",
            encoding="utf-8",
        )
        script_path.write_text("#!/bin/bash\necho hi\n", encoding="utf-8")
        entry = CronEntry(
            name="test", schedule_expr="0 3 * * *", hour=3, minute=0,
            script_path=script_path, cron_path=cron_path,
        )
        err = apply_cron_schedule(entry, "30 14 * * 1")
        assert err == ""
        content = entry.cron_path.read_text(encoding="utf-8")
        # The comment line must survive intact (was being rewritten pre-fix)
        assert "# legacy entry: 0 3 * * * root /usr/bin/legacy-bob" in content
        # The real schedule line must be replaced
        assert "30 14 * * 1  root  " in content


# ---------------------------------------------------------------------------
# apply_cron_email — patches cron file + wrapper script
# ---------------------------------------------------------------------------

class TestApplyCronEmail:
    @staticmethod
    def _make_entry(tmp_path: Path, *, legacy_var: bool = False) -> CronEntry:
        cron_path = tmp_path / "bob-test"
        script_path = tmp_path / "bob-test.sh"
        cron_path.write_text(
            "# email: old@example.com\n"
            "0 3 * * *  root  /usr/local/bin/bob-test.sh\n",
            encoding="utf-8",
        )
        var_name = "NOTIFY_EMAIL" if legacy_var else "NOTIFY_EMAILS"
        script_path.write_text(
            "#!/bin/bash\n"
            f"{var_name}=old@example.com\n"
            "echo hello\n",
            encoding="utf-8",
        )
        return CronEntry(
            name="test", schedule_expr="0 3 * * *", hour=3, minute=0,
            script_path=script_path, cron_path=cron_path,
        )

    def test_updates_email_comment(self, tmp_path):
        entry = self._make_entry(tmp_path)
        err, count = apply_cron_email(entry, "new@example.com")
        assert err == ""
        assert count == 1
        assert "# email: new@example.com" in entry.cron_path.read_text(encoding="utf-8")

    def test_updates_script_notify_emails(self, tmp_path):
        entry = self._make_entry(tmp_path)
        err, count = apply_cron_email(entry, "new@example.com")
        assert err == ""
        assert count == 1
        assert "NOTIFY_EMAILS=new@example.com" in entry.script_path.read_text(encoding="utf-8")

    def test_legacy_notify_email_var_still_matched(self, tmp_path):
        """Legacy NOTIFY_EMAIL= (no S) form must also be replaced — pre-v0.3 parity."""
        entry = self._make_entry(tmp_path, legacy_var=True)
        err, count = apply_cron_email(entry, "new@example.com")
        assert err == ""
        assert count == 1
        # Replacement always writes the new NOTIFY_EMAILS form (plural).
        assert "NOTIFY_EMAILS=new@example.com" in entry.script_path.read_text(encoding="utf-8")

    def test_missing_script_returns_zero_substs(self, tmp_path):
        entry = self._make_entry(tmp_path)
        entry.script_path.unlink()
        err, count = apply_cron_email(entry, "new@example.com")
        assert err == ""
        assert count == 0

    def test_special_chars_quoted_via_shlex(self, tmp_path):
        entry = self._make_entry(tmp_path)
        err, count = apply_cron_email(entry, "a b@c")  # never legal, but shlex-safe
        assert err == ""
        # shlex.quote wraps with single quotes when needed
        assert "NOTIFY_EMAILS='a b@c'" in entry.script_path.read_text(encoding="utf-8")

    def test_preserves_script_executable_mode(self, tmp_path):
        """Regression for v0.5.5 C-1: apply_cron_email() must keep script 0o755.

        Pre-v0.5.5 the helper rewrote the script via _atomic_write() which
        forced mode 0o600 — cron could no longer exec the script and the
        scheduled audit silently never ran. Tests must pin the mode.
        """
        import stat as _stat
        entry = self._make_entry(tmp_path)
        # Set the initial modes that bob --install-cron produces.
        entry.cron_path.chmod(0o640)
        entry.script_path.chmod(0o755)
        err, count = apply_cron_email(entry, "new@example.com")
        assert err == ""
        assert count == 1
        assert _stat.S_IMODE(entry.cron_path.stat().st_mode) == 0o640
        assert _stat.S_IMODE(entry.script_path.stat().st_mode) == 0o755


# ---------------------------------------------------------------------------
# I-3 (v0.5.7): apply_cron_schedule must go through _atomic_write to prevent
# truncation between O_TRUNC and write under power-loss / SIGKILL.
# ---------------------------------------------------------------------------

class TestApplyCronScheduleAtomic:
    @staticmethod
    def _make_entry(tmp_path: Path) -> CronEntry:
        cron_path = tmp_path / "bob-test"
        script_path = tmp_path / "bob-test.sh"
        cron_path.write_text(
            "# email: admin@example.com\n"
            "0 3 * * *  root  /usr/local/bin/bob-test.sh\n",
            encoding="utf-8",
        )
        return CronEntry(
            name="test", schedule_expr="0 3 * * *", hour=3, minute=0,
            script_path=script_path, cron_path=cron_path,
        )

    def test_goes_through_atomic_write(self, tmp_path):
        """Spy on _atomic_write to confirm schedule edits no longer do raw
        os.open(O_TRUNC) + write — that pattern leaves the cron file empty
        if the process dies after open but before write completes."""
        from bob import cron as cron_mod
        entry = self._make_entry(tmp_path)
        original = cron_mod._atomic_write
        calls = []

        def spy(path, content, mode=0o600):
            calls.append((path, content, mode))
            return original(path, content, mode=mode)

        with patch.object(cron_mod, "_atomic_write", side_effect=spy):
            err = apply_cron_schedule(entry, "30 14 * * 1")
        assert err == ""
        assert len(calls) == 1
        path, content, mode = calls[0]
        assert path == entry.cron_path
        assert "30 14 * * 1  root  " in content
        assert mode == 0o640  # cron skips files with wrong mode

    def test_failed_write_does_not_truncate(self, tmp_path):
        """If _atomic_write fails, the on-disk file must still contain the
        original schedule — this is the whole point of the atomic-write
        contract. Pre-I-3 the raw O_TRUNC truncated before write could fail."""
        from bob import cron as cron_mod
        entry = self._make_entry(tmp_path)
        original_text = entry.cron_path.read_text(encoding="utf-8")

        def boom(*args, **kwargs):
            raise OSError("simulated disk full")

        with patch.object(cron_mod, "_atomic_write", side_effect=boom):
            err = apply_cron_schedule(entry, "30 14 * * 1")
        assert "simulated disk full" in err
        assert entry.cron_path.read_text(encoding="utf-8") == original_text


# ---------------------------------------------------------------------------
# I-1 (v0.5.7): _is_printable_input_char must reject curses KEY_* codes that
# previously leaked through chr(ch_i) as Greek/Unicode glyphs.
# ---------------------------------------------------------------------------

class TestIsPrintableInputChar:
    def test_accepts_printable_ascii(self):
        from bob.tui.cron import _is_printable_input_char
        for ch in "aZ0! @~":
            assert _is_printable_input_char(ord(ch)), f"rejected {ch!r}"

    def test_accepts_printable_latin1(self):
        from bob.tui.cron import _is_printable_input_char
        for ch in "éèàç€":
            # € is U+20AC > 256 so it gets rejected — that's accepted limitation
            expected = ord(ch) < 256 and ch.isprintable()
            assert _is_printable_input_char(ord(ch)) == expected

    def test_rejects_control_chars(self):
        from bob.tui.cron import _is_printable_input_char
        for code in (0, 1, 9, 10, 13, 27, 31):  # NUL, SOH, TAB, LF, CR, ESC, US
            assert not _is_printable_input_char(code)

    def test_rejects_curses_keypad_codes(self):
        """The whole point of I-1: KEY_UP=259, KEY_F1=265 etc. previously
        passed the `ch_i >= 32` gate and inserted Greek glyphs (Ι, Ε) into
        input buffers because chr(259)='Ι', chr(265)='Ω'."""
        import curses
        from bob.tui.cron import _is_printable_input_char
        for code in (
            curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT,
            curses.KEY_HOME, curses.KEY_END, curses.KEY_PPAGE, curses.KEY_NPAGE,
            curses.KEY_F1, curses.KEY_F12,
        ):
            assert code >= 256, f"sanity: {code} should be >= 256"
            assert not _is_printable_input_char(code)


# ---------------------------------------------------------------------------
# M-5 (v0.5.8): schedule wizard constants promoted from local tuple unpack
# to module-level IntEnum for explicit names + introspection.
# ---------------------------------------------------------------------------

class TestScheduleIntEnum:
    def test_enum_values_match_menu_indices(self):
        from bob.tui.cron import _Schedule
        assert _Schedule.DAILY == 1
        assert _Schedule.WEEKDAYS == 2
        assert _Schedule.MONTHDAYS == 3
        assert _Schedule.CUSTOM == 4

    def test_enum_supports_int_comparison(self):
        """The wizard does `choice == _Schedule.WEEKDAYS` where choice is a
        raw int derived from `sel + 1` or `ch_i - ord('0')`. IntEnum must
        compare equal to plain ints to preserve the existing call sites."""
        from bob.tui.cron import _Schedule
        for raw_choice, expected in (
            (1, _Schedule.DAILY),
            (2, _Schedule.WEEKDAYS),
            (3, _Schedule.MONTHDAYS),
            (4, _Schedule.CUSTOM),
        ):
            assert raw_choice == expected


# ---------------------------------------------------------------------------
# M-8 (v0.5.8): datetime imports lifted to module-level. Verify both modules
# expose `datetime` as a module attribute (no local import inside functions).
# ---------------------------------------------------------------------------

class TestDatetimeImportLifted:
    def test_bob_cron_has_module_level_datetime(self):
        import bob.cron
        from datetime import datetime as _dt_stdlib
        assert hasattr(bob.cron, "datetime")
        assert bob.cron.datetime is _dt_stdlib

    def test_bob_tui_cron_has_module_level_datetime(self):
        import bob.tui.cron
        from datetime import datetime as _dt_stdlib
        assert hasattr(bob.tui.cron, "datetime")
        assert bob.tui.cron.datetime is _dt_stdlib

    def test_build_script_content_still_stamps_date(self):
        """Smoke test: lifting the import must not break the existing
        date-stamping behaviour in build_script_content."""
        from bob.cron import build_script_content
        script = build_script_content("a@b.c", "/var/log/bob")
        # The stamp line uses today's date in YYYY-MM-DD
        from datetime import datetime
        today = datetime.now().strftime("%Y-%m-%d")
        assert today in script
