"""
Unit tests for bob.cli module.

Run with: python -m pytest tests/test_cli.py -v
"""

import pytest
from bob.cli import AuditConfig, CLIError, parse_args


class TestDefaults:
    def test_empty_argv_returns_defaults(self):
        config = parse_args([])
        assert config.lang == "en"
        assert not config.verbose
        assert not config.detailed
        assert not config.fix
        assert not config.yes
        assert not config.reconfigure
        assert not config.no_color
        assert not config.quiet
        assert not config.json_mode
        assert not config.json_full
        assert config.log_days == 7
        assert not config.manage_logs
        assert not config.install_cron
        assert not config.manage_cron
        assert not config.show_version
        assert not config.show_help
        assert not config.install_completion
        assert not config.offline
        assert config.profile == ""
        assert not config.reset_baseline
        assert config.explain_key == ""
        assert not config.diff_mode
        assert config.webhook_url == ""
        assert config.webhook_format == "auto"
        assert not config.apply
        assert config.target == 0


class TestFlags:
    @pytest.mark.parametrize("argv", [["-v"], ["--verbose"]])
    def test_verbose(self, argv):
        assert parse_args(argv).verbose

    @pytest.mark.parametrize("argv", [["-d"], ["--detailed"]])
    def test_detailed(self, argv):
        assert parse_args(argv).detailed

    def test_fix(self):
        assert parse_args(["--fix"]).fix

    @pytest.mark.parametrize("argv", [["-y", "--fix", "--apply"], ["--yes", "--fix", "--apply"]])
    def test_yes(self, argv):
        assert parse_args(argv).yes

    def test_reconfigure(self):
        assert parse_args(["--reconfigure"]).reconfigure

    def test_no_color(self):
        assert parse_args(["--no-color"]).no_color

    def test_json(self):
        config = parse_args(["--json"])
        assert config.json_mode
        assert not config.json_full

    def test_json_full_implies_json_mode(self):
        config = parse_args(["--json-full"])
        assert config.json_mode
        assert config.json_full

    def test_json_full_short(self):
        config = parse_args(["-J"])
        assert config.json_mode
        assert config.json_full

    def test_french(self):
        assert parse_args(["--french"]).lang == "fr"

    def test_french_overrides_system_locale(self, monkeypatch):
        # Even on a Japanese system, --french wins
        monkeypatch.setenv("LANG", "ja_JP.UTF-8")
        assert parse_args(["--french"]).lang == "fr"

    def test_lang_explicit_overrides_system_locale(self, monkeypatch):
        monkeypatch.setenv("LANG", "fr_FR.UTF-8")
        assert parse_args(["--lang=en"]).lang == "en"

    def test_default_uses_system_locale_when_fr(self, monkeypatch):
        monkeypatch.setenv("LANG", "fr_FR.UTF-8")
        monkeypatch.delenv("LC_ALL", raising=False)
        monkeypatch.delenv("LC_MESSAGES", raising=False)
        assert parse_args([]).lang == "fr"

    def test_default_uses_en_when_lang_c(self, monkeypatch):
        monkeypatch.setenv("LANG", "C")
        monkeypatch.delenv("LC_ALL", raising=False)
        monkeypatch.delenv("LC_MESSAGES", raising=False)
        assert parse_args([]).lang == "en"

    def test_version(self):
        assert parse_args(["--version"]).show_version

    @pytest.mark.parametrize("argv", [["-h"], ["--help"]])
    def test_help(self, argv):
        assert parse_args(argv).show_help

    @pytest.mark.parametrize("argv", [["-o"], ["--offline"]])
    def test_offline(self, argv):
        assert parse_args(argv).offline

    @pytest.mark.parametrize("argv", [["-q"], ["--quiet"]])
    def test_quiet(self, argv):
        assert parse_args(argv).quiet

    def test_diff(self):
        assert parse_args(["--diff"]).diff_mode

    def test_diff_short(self):
        assert parse_args(["-D"]).diff_mode

    def test_explain_with_equals(self):
        assert parse_args(["--explain=ssh.password_auth"]).explain_key == "ssh.password_auth"

    def test_explain_with_space(self):
        assert parse_args(["--explain", "ssh.password_auth"]).explain_key == "ssh.password_auth"

    def test_explain_short(self):
        assert parse_args(["-e", "ssh.password_auth"]).explain_key == "ssh.password_auth"

    def test_profile(self):
        assert parse_args(["--profile=server"]).profile == "server"

    def test_profile_short(self):
        assert parse_args(["-p", "desktop"]).profile == "desktop"

    def test_reset_baseline(self):
        assert parse_args(["--reset-baseline"]).reset_baseline

    def test_json_full_order_independent(self):
        """--json --json-full and --json-full --json must produce identical config."""
        c1 = parse_args(["--json", "--json-full"])
        c2 = parse_args(["--json-full", "--json"])
        assert c1.json_full and c1.json_mode
        assert c2.json_full and c2.json_mode


class TestLogDays:
    def test_log_days_valid(self):
        assert parse_args(["--log-days=30"]).log_days == 30

    def test_log_days_default(self):
        assert parse_args([]).log_days == 7

    def test_log_days_one(self):
        assert parse_args(["--log-days=1"]).log_days == 1

    def test_log_days_zero_raises(self):
        with pytest.raises(CLIError, match="positive integer"):
            parse_args(["--log-days=0"])

    def test_log_days_negative_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--log-days=-5"])

    def test_log_days_non_numeric_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--log-days=abc"])

    def test_log_days_large_valid(self):
        """A large but valid number must be accepted."""
        assert parse_args(["--log-days=365"]).log_days == 365

    def test_log_days_float_raises(self):
        """A float string is not a valid integer."""
        with pytest.raises(CLIError):
            parse_args(["--log-days=7.5"])


class TestCombinations:
    def test_multiple_flags(self):
        config = parse_args(["-v", "-d", "--french", "--fix", "--log-days=14"])
        assert config.verbose
        assert config.detailed
        assert config.lang == "fr"
        assert config.fix
        assert config.log_days == 14

    def test_unknown_option_raises(self):
        with pytest.raises(CLIError, match="Unknown option"):
            parse_args(["--unknown-flag"])

    def test_unknown_short_option_raises(self):
        with pytest.raises(CLIError):
            parse_args(["-z"])

    def test_duplicate_flags_idempotent(self):
        """Repeating a boolean flag must not crash or change the result."""
        config = parse_args(["--verbose", "--verbose"])
        assert config.verbose

    def test_config_isolation_between_calls(self):
        """Two separate parse_args calls must not share state."""
        c1 = parse_args(["--verbose"])
        c2 = parse_args([])
        assert not c2.verbose


class TestAuditConfigDirectInstantiation:
    def test_can_instantiate_directly(self):
        """AuditConfig can be built without parse_args — useful in tests."""
        config = AuditConfig(lang="fr", verbose=True, log_days=30)
        assert config.lang == "fr"
        assert config.verbose
        assert config.log_days == 30
        assert config.fix is False  # default preserved


class TestMutuallyExclusiveModes:
    def test_manage_logs_and_fix_raises(self):
        """--manage-logs and --fix cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-logs", "--fix"])

    def test_install_cron_and_fix_raises(self):
        """--install-cron and --fix cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--install-cron", "--fix"])

    def test_manage_cron_and_fix_raises(self):
        """--manage-cron and --fix cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-cron", "--fix"])

    def test_manage_logs_and_install_cron_raises(self):
        """--manage-logs and --install-cron cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-logs", "--install-cron"])

    def test_manage_logs_and_manage_cron_raises(self):
        """--manage-logs and --manage-cron cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--manage-logs", "--manage-cron"])

    def test_install_cron_and_manage_cron_raises(self):
        """--install-cron and --manage-cron cannot be combined."""
        with pytest.raises(CLIError):
            parse_args(["--install-cron", "--manage-cron"])

    def test_fix_alone_ok(self):
        """--fix alone is valid."""
        assert parse_args(["--fix"]).fix

    def test_manage_logs_alone_ok(self):
        """--manage-logs alone is valid."""
        assert parse_args(["--manage-logs"]).manage_logs

    def test_install_cron_alone_ok(self):
        """--install-cron alone is valid."""
        assert parse_args(["--install-cron"]).install_cron

    def test_manage_cron_alone_ok(self):
        """--manage-cron alone is valid."""
        assert parse_args(["--manage-cron"]).manage_cron

    def test_manage_cron_short(self):
        assert parse_args(["-C"]).manage_cron

    def test_yes_without_fix_raises(self):
        """--yes without --fix must raise CLIError."""
        with pytest.raises(CLIError, match="--yes requires --fix"):
            parse_args(["--yes"])

    def test_json_and_fix_apply_raises(self):
        """--json and --fix --apply are incompatible (fix mode is interactive)."""
        with pytest.raises(CLIError):
            parse_args(["--json", "--fix", "--apply"])

    def test_quiet_and_json_raises(self):
        """--quiet and --json are incompatible (JSON requires stdout)."""
        with pytest.raises(CLIError):
            parse_args(["--quiet", "--json"])

    def test_quiet_and_fix_apply_raises(self):
        """--quiet and --fix --apply are incompatible (fix mode requires prompts)."""
        with pytest.raises(CLIError):
            parse_args(["--quiet", "--fix", "--apply"])


class TestWebhook:
    def test_webhook_url_with_equals(self):
        config = parse_args(["--webhook=https://hooks.example.com/abc"])
        assert config.webhook_url == "https://hooks.example.com/abc"

    def test_webhook_url_with_space(self):
        config = parse_args(["--webhook", "https://hooks.example.com/abc"])
        assert config.webhook_url == "https://hooks.example.com/abc"

    def test_webhook_short(self):
        config = parse_args(["-w", "https://hooks.example.com/abc"])
        assert config.webhook_url == "https://hooks.example.com/abc"

    def test_webhook_format_generic(self):
        assert parse_args(["--webhook-format=generic"]).webhook_format == "generic"

    def test_webhook_format_slack(self):
        assert parse_args(["--webhook-format=slack"]).webhook_format == "slack"

    def test_webhook_format_auto(self):
        assert parse_args(["--webhook-format=auto"]).webhook_format == "auto"

    def test_webhook_format_invalid_raises(self):
        """An unrecognised format value must raise CLIError."""
        with pytest.raises(CLIError, match="webhook-format"):
            parse_args(["--webhook-format=discord"])

    def test_webhook_empty_value_raises(self):
        with pytest.raises(CLIError, match="URL"):
            parse_args(["--webhook="])


class TestEmptyValues:
    def test_explain_empty_value_raises(self):
        with pytest.raises(CLIError, match="--explain="):
            parse_args(["--explain="])

    def test_profile_empty_value_raises(self):
        with pytest.raises(CLIError, match="--profile="):
            parse_args(["--profile="])

    def test_lang_empty_value_raises(self):
        with pytest.raises(CLIError, match="--lang="):
            parse_args(["--lang="])

    def test_log_days_empty_value_raises(self):
        with pytest.raises(CLIError, match="--log-days"):
            parse_args(["--log-days="])

    def test_target_empty_value_raises(self):
        with pytest.raises(CLIError, match="--target"):
            parse_args(["--target="])


class TestExplain:
    def test_explain_key_default_empty(self):
        assert parse_args([]).explain_key == ""

    def test_explain_key_set(self):
        assert parse_args(["--explain=updates.security_pending"]).explain_key == "updates.security_pending"

    def test_explain_key_with_space_arg(self):
        assert parse_args(["--explain", "hardening.rp_filter_disabled"]).explain_key == "hardening.rp_filter_disabled"

    def test_explain_short_with_space(self):
        assert parse_args(["-e", "hardening.rp_filter_disabled"]).explain_key == "hardening.rp_filter_disabled"

    def test_explain_short_list(self):
        assert parse_args(["-e", "list"]).explain_key == "list"


class TestApplyFlag:
    def test_apply_default_false(self):
        assert not parse_args([]).apply

    def test_apply_without_fix_raises(self):
        with pytest.raises(CLIError, match="--apply requires --fix"):
            parse_args(["--apply"])

    def test_fix_alone_sets_dry_run(self):
        """--fix without --apply sets fix=True, apply=False (dry-run mode)."""
        config = parse_args(["--fix"])
        assert config.fix
        assert not config.apply

    def test_fix_apply_sets_both(self):
        config = parse_args(["--fix", "--apply"])
        assert config.fix
        assert config.apply

    def test_fix_apply_yes_sets_all(self):
        config = parse_args(["--fix", "--apply", "--yes"])
        assert config.fix
        assert config.apply
        assert config.yes

    def test_yes_without_apply_raises(self):
        with pytest.raises(CLIError, match="--yes requires --fix --apply"):
            parse_args(["--yes", "--fix"])

    def test_yes_without_fix_raises(self):
        with pytest.raises(CLIError, match="--yes requires --fix --apply"):
            parse_args(["--yes"])

    def test_json_fix_dry_run_ok(self):
        """--json --fix (dry run, no --apply) must NOT raise."""
        config = parse_args(["--json", "--fix"])
        assert config.json_mode
        assert config.fix
        assert not config.apply

    def test_quiet_fix_dry_run_ok(self):
        """--quiet --fix (dry run, no --apply) must NOT raise."""
        config = parse_args(["--quiet", "--fix"])
        assert config.quiet
        assert config.fix
        assert not config.apply

    def test_fix_apply_order_independent(self):
        """--apply --fix and --fix --apply produce the same config."""
        c1 = parse_args(["--apply", "--fix"])
        c2 = parse_args(["--fix", "--apply"])
        assert c1.fix and c1.apply
        assert c2.fix and c2.apply


class TestTargetFlag:
    def test_target_default_zero(self):
        assert parse_args([]).target == 0

    def test_target_with_equals(self):
        assert parse_args(["--target=8"]).target == 8

    def test_target_with_space(self):
        assert parse_args(["--target", "9"]).target == 9

    def test_target_one(self):
        assert parse_args(["--target=1"]).target == 1

    def test_target_ten(self):
        assert parse_args(["--target=10"]).target == 10

    def test_target_zero_raises(self):
        with pytest.raises(CLIError, match="1 and 10"):
            parse_args(["--target=0"])

    def test_target_eleven_raises(self):
        with pytest.raises(CLIError, match="1 and 10"):
            parse_args(["--target=11"])

    def test_target_non_numeric_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--target=high"])

    def test_target_float_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--target=7.5"])

    def test_target_combined_with_profile(self):
        config = parse_args(["--target=9", "--profile=server"])
        assert config.target == 9
        assert config.profile == "server"


class TestCheckSkipFlags:
    def test_check_only_single(self):
        config = parse_args(["--check=ssh"])
        assert config.check_only == frozenset({"ssh"})

    def test_check_only_multiple(self):
        config = parse_args(["--check=ssh,firewall,ports"])
        assert config.check_only == frozenset({"ssh", "firewall", "ports"})

    def test_check_with_equals(self):
        config = parse_args(["--check=ssl_certs"])
        assert "ssl_certs" in config.check_only

    def test_check_with_space(self):
        config = parse_args(["--check", "ssh,firewall"])
        assert config.check_only == frozenset({"ssh", "firewall"})

    def test_skip_single(self):
        config = parse_args(["--skip=clamav"])
        assert config.skip_checks == frozenset({"clamav"})

    def test_skip_multiple(self):
        config = parse_args(["--skip=clamav,rootkit,backup"])
        assert config.skip_checks == frozenset({"clamav", "rootkit", "backup"})

    def test_skip_with_space(self):
        config = parse_args(["--skip", "clamav,rootkit"])
        assert config.skip_checks == frozenset({"clamav", "rootkit"})

    def test_check_and_skip_mutually_exclusive(self):
        with pytest.raises(CLIError):
            parse_args(["--check=ssh", "--skip=clamav"])

    def test_check_empty_value_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--check="])

    def test_skip_empty_value_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--skip="])

    def test_check_defaults_empty(self):
        config = parse_args([])
        assert config.check_only == frozenset()

    def test_check_list_sets_list_checks(self):
        config = parse_args(["--check=list"])
        assert config.list_checks
        assert config.check_only == frozenset()

    def test_check_list_space_sets_list_checks(self):
        config = parse_args(["--check", "list"])
        assert config.list_checks
        assert config.check_only == frozenset()

    def test_check_list_case_insensitive(self):
        config = parse_args(["--check=LIST"])
        assert config.list_checks

    def test_check_list_default_false(self):
        config = parse_args([])
        assert not config.list_checks
        assert config.skip_checks == frozenset()

    def test_check_strips_spaces(self):
        config = parse_args(["--check=ssh, firewall , ports"])
        assert config.check_only == frozenset({"ssh", "firewall", "ports"})


class TestSectionEnabled:
    """Tests for _section_enabled helper in runner.py."""

    def test_no_filters_always_enabled(self):
        from bob.runner import _section_enabled
        config = AuditConfig()
        assert _section_enabled("ssh", config, None)

    def test_check_only_filters_out(self):
        from bob.runner import _section_enabled
        config = AuditConfig(check_only=frozenset({"ssh"}))
        assert _section_enabled("ssh", config, None)
        assert not _section_enabled("firewall", config, None)

    def test_skip_blocks_section(self):
        from bob.runner import _section_enabled
        config = AuditConfig(skip_checks=frozenset({"clamav"}))
        assert not _section_enabled("clamav", config, None)
        assert _section_enabled("ssh", config, None)

    def test_profile_skip_respected(self):
        from bob.runner import _section_enabled
        from unittest.mock import MagicMock
        config = AuditConfig()
        profile = MagicMock()
        profile.should_skip_section.return_value = True
        assert not _section_enabled("samba", config, profile)

    def test_check_only_overrides_profile_skip(self):
        from bob.runner import _section_enabled
        from unittest.mock import MagicMock
        config = AuditConfig(check_only=frozenset({"ssh"}))
        profile = MagicMock()
        profile.should_skip_section.return_value = False
        # "firewall" not in check_only → disabled regardless of profile
        assert not _section_enabled("firewall", config, profile)

    def test_prefix_check_matches_multiple(self):
        from bob.runner import _section_enabled
        config = AuditConfig(check_only=frozenset({"kernel"}))
        assert _section_enabled("kernel_hardening", config, None)
        assert _section_enabled("kernel_modules", config, None)
        assert not _section_enabled("ssh", config, None)

    def test_prefix_skip_blocks_multiple(self):
        from bob.runner import _section_enabled
        config = AuditConfig(skip_checks=frozenset({"kernel"}))
        assert not _section_enabled("kernel_hardening", config, None)
        assert not _section_enabled("kernel_modules", config, None)
        assert _section_enabled("ssh", config, None)

    def test_prefix_does_not_overmatch(self):
        from bob.runner import _section_enabled
        config = AuditConfig(check_only=frozenset({"ssh"}))
        # ssl_certs starts with 's' but not 'ssh'
        assert _section_enabled("ssh", config, None)
        assert not _section_enabled("ssl_certs", config, None)
        assert not _section_enabled("suid_audit", config, None)

    def test_prefix_file_matches_both(self):
        from bob.runner import _section_enabled
        config = AuditConfig(check_only=frozenset({"file"}))
        assert _section_enabled("file_perms", config, None)
        assert _section_enabled("file_integrity", config, None)


class TestValidateCheckFilters:
    """Tests for validate_check_filters in runner.py."""

    def test_valid_exact_check_returns_none(self):
        from bob.runner import validate_check_filters
        config = AuditConfig(check_only=frozenset({"ssh"}))
        assert validate_check_filters(config) is None

    def test_valid_prefix_check_returns_none(self):
        from bob.runner import validate_check_filters
        config = AuditConfig(check_only=frozenset({"kernel"}))
        assert validate_check_filters(config) is None

    def test_all_bad_tokens_returns_error(self):
        from bob.runner import validate_check_filters
        config = AuditConfig(check_only=frozenset({"sshh", "firewallx"}))
        result = validate_check_filters(config)
        assert result is not None
        assert "matched no known" in result

    def test_partial_bad_returns_none(self, capsys):
        from bob.runner import validate_check_filters
        config = AuditConfig(check_only=frozenset({"ssh", "zzz_nonexistent"}))
        result = validate_check_filters(config)
        # ssh matches → not fatal
        assert result is None
        # but a warning should be printed to stderr
        captured = capsys.readouterr()
        assert "zzz_nonexistent" in captured.err

    def test_bad_skip_prints_warning_not_error(self, capsys):
        from bob.runner import validate_check_filters
        config = AuditConfig(skip_checks=frozenset({"nonexistent_check"}))
        result = validate_check_filters(config)
        assert result is None
        captured = capsys.readouterr()
        assert "nonexistent_check" in captured.err

    def test_no_filters_returns_none(self):
        from bob.runner import validate_check_filters
        config = AuditConfig()
        assert validate_check_filters(config) is None

    def test_difflib_suggestion_included(self, capsys):
        from bob.runner import validate_check_filters
        config = AuditConfig(check_only=frozenset({"sshh"}))
        validate_check_filters(config)
        captured = capsys.readouterr()
        # difflib should suggest "ssh" for "sshh"
        assert "ssh" in captured.err


class TestOutputDirFlag:
    def test_output_dir_with_equals(self):
        config = parse_args(["--output-dir=/var/log/bob"])
        assert config.output_dir == "/var/log/bob"

    def test_output_dir_with_space(self):
        config = parse_args(["--output-dir", "/tmp/reports"])
        assert config.output_dir == "/tmp/reports"

    def test_output_dir_default_empty(self):
        config = parse_args([])
        assert config.output_dir == ""

    def test_output_dir_empty_value_raises(self):
        with pytest.raises(CLIError):
            parse_args(["--output-dir="])

    def test_output_dir_combined_with_detailed(self):
        config = parse_args(["-d", "--output-dir=/tmp/audit"])
        assert config.detailed
        assert config.output_dir == "/tmp/audit"


class TestFormatFlag:
    """--format=FORMAT canonical output flag."""

    @pytest.mark.parametrize("argv,expected", [
        (["--format=json"],      {"json_mode": True,  "json_full": False, "csv_mode": False, "markdown_mode": False, "html_mode": False}),
        (["--format=json-full"], {"json_mode": True,  "json_full": True,  "csv_mode": False, "markdown_mode": False, "html_mode": False}),
        (["--format=csv"],       {"json_mode": False, "json_full": False, "csv_mode": True,  "markdown_mode": False, "html_mode": False}),
        (["--format=markdown"],  {"json_mode": False, "json_full": False, "csv_mode": False, "markdown_mode": True,  "html_mode": False}),
        (["--format=html"],      {"json_mode": False, "json_full": False, "csv_mode": False, "markdown_mode": False, "html_mode": True}),
    ])
    def test_format_sets_correct_flags(self, argv, expected):
        config = parse_args(argv)
        for attr, val in expected.items():
            assert getattr(config, attr) == val

    @pytest.mark.parametrize("argv", [
        ["--format", "json"],
        ["--format", "json-full"],
        ["--format", "csv"],
        ["--format", "markdown"],
        ["--format", "html"],
    ])
    def test_format_space_separated(self, argv):
        config = parse_args(argv)
        assert any([config.json_mode, config.csv_mode, config.markdown_mode, config.html_mode])

    def test_format_invalid_raises(self):
        with pytest.raises(CLIError, match="--format requires"):
            parse_args(["--format=xml"])

    def test_format_invalid_space_raises(self):
        with pytest.raises(CLIError, match="--format requires"):
            parse_args(["--format", "pdf"])

    def test_format_combined_with_verbose(self):
        config = parse_args(["--format=json", "--verbose"])
        assert config.json_mode
        assert config.verbose

    def test_format_json_and_format_csv_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--format=json", "--format=csv"])

    def test_format_json_and_legacy_html_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--format=json", "--html"])

    def test_format_csv_and_quiet_raises(self):
        with pytest.raises(CLIError, match="--quiet"):
            parse_args(["--format=csv", "--quiet"])

    def test_format_json_and_watch_raises(self):
        with pytest.raises(CLIError, match="[Ii]ncompatible"):
            parse_args(["--format=json", "--watch"])

    def test_legacy_json_flag_still_works(self):
        config = parse_args(["-j"])
        assert config.json_mode
        assert not config.json_full

    def test_legacy_json_full_flag_still_works(self):
        config = parse_args(["-J"])
        assert config.json_mode
        assert config.json_full

    def test_legacy_output_csv_still_works(self):
        config = parse_args(["--output=csv"])
        assert config.csv_mode

    def test_legacy_output_markdown_still_works(self):
        config = parse_args(["--output=markdown"])
        assert config.markdown_mode

    def test_legacy_html_flag_still_works(self):
        config = parse_args(["--html"])
        assert config.html_mode
