"""
Tests for checks/log_rotation.py — CHECK 39.

Covers:
  - logrotate not installed: WARN + deduction
  - logrotate installed, no rules: INFO
  - logrotate installed, rules present: OK
  - journald volatile/none: WARN + deduction
  - journald persistent: OK
  - journald no disk limit: INFO
  - journald disk limit set: OK
  - remote syslog configured: OK
  - remote syslog absent: INFO
  - no syslog daemon: no finding
  - combined scenarios + deduction invariants
  - LogRotationSnapshot defaults
"""

from __future__ import annotations

import pytest

from bob.checks.log_rotation import LogRotationSnapshot, check_log_rotation
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(**kwargs) -> LogRotationSnapshot:
    """Build a snapshot with all-good defaults, overriding with kwargs."""
    defaults = dict(
        logrotate_installed=True,
        logrotate_rule_count=10,
        journald_active=True,
        journald_storage="persistent",
        journald_max_use="500M",
        journald_keep_free="",
        journal_persistent=True,
        remote_syslog_configured=False,
        syslog_daemon="rsyslog",
    )
    defaults.update(kwargs)
    return LogRotationSnapshot(**defaults)


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


def _deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def _deduction_keys(result) -> set[str]:
    return {d.key for d in result.deductions}


def _level(result, key: str) -> FindingLevel:
    for f in result.findings:
        if f.key == key:
            return f.level
    raise KeyError(key)


def _finding(result, key: str):
    for f in result.findings:
        if f.key == key:
            return f
    raise KeyError(key)


def _t_format(key: str, **kwargs) -> str:
    parts = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    return f"{key}: {parts}" if parts else key


# ---------------------------------------------------------------------------
# logrotate not installed
# ---------------------------------------------------------------------------

class TestLogrotateNotInstalled:
    def test_missing_is_warn(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        assert _level(result, "log_rotation.logrotate_missing") == FindingLevel.WARN

    def test_missing_deducts_1(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        assert _deductions(result) == 1

    def test_missing_deduction_key(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        assert "log_rotation.logrotate_missing" in _deduction_keys(result)

    def test_missing_has_fix_cmd(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        f = _finding(result, "log_rotation.logrotate_missing")
        assert f.cmd is not None
        assert "apt" in (f.cmd or "")

    def test_missing_cmd_type_fix(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        f = _finding(result, "log_rotation.logrotate_missing")
        assert f.cmd_type == "fix"

    def test_missing_has_detail(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        f = _finding(result, "log_rotation.logrotate_missing")
        assert f.detail is not None

    def test_no_ok_when_missing(self):
        result = check_log_rotation(_snap(logrotate_installed=False))
        assert "log_rotation.logrotate_ok" not in _keys(result)


# ---------------------------------------------------------------------------
# logrotate installed, no rules
# ---------------------------------------------------------------------------

class TestLogrotateNoRules:
    def test_no_rules_is_info(self):
        result = check_log_rotation(_snap(logrotate_rule_count=0))
        assert _level(result, "log_rotation.logrotate_no_rules") == FindingLevel.INFO

    def test_no_rules_no_deduction(self):
        result = check_log_rotation(_snap(logrotate_rule_count=0))
        assert _deductions(result) == 0

    def test_no_rules_has_cmd(self):
        result = check_log_rotation(_snap(logrotate_rule_count=0))
        f = _finding(result, "log_rotation.logrotate_no_rules")
        assert f.cmd is not None

    def test_no_ok_when_no_rules(self):
        result = check_log_rotation(_snap(logrotate_rule_count=0))
        assert "log_rotation.logrotate_ok" not in _keys(result)


# ---------------------------------------------------------------------------
# logrotate installed with rules
# ---------------------------------------------------------------------------

class TestLogrotateOk:
    def test_ok_finding(self):
        result = check_log_rotation(_snap(logrotate_rule_count=15))
        assert _level(result, "log_rotation.logrotate_ok") == FindingLevel.OK

    def test_ok_no_deduction(self):
        result = check_log_rotation(_snap(logrotate_rule_count=15))
        assert _deductions(result) == 0

    def test_ok_message_contains_count(self):
        result = check_log_rotation(_snap(logrotate_rule_count=15), t=_t_format)
        f = _finding(result, "log_rotation.logrotate_ok")
        assert "count=15" in (f.message or "")

    def test_ok_with_1_rule(self):
        result = check_log_rotation(_snap(logrotate_rule_count=1))
        assert _level(result, "log_rotation.logrotate_ok") == FindingLevel.OK


# ---------------------------------------------------------------------------
# journald volatile / none
# ---------------------------------------------------------------------------

class TestJournaldVolatile:
    @pytest.mark.parametrize("storage", ["volatile", "none"])
    def test_volatile_is_warn(self, storage):
        result = check_log_rotation(_snap(
            journald_storage=storage,
            journal_persistent=False,
        ))
        assert _level(result, "log_rotation.journald_volatile") == FindingLevel.WARN

    @pytest.mark.parametrize("storage", ["volatile", "none"])
    def test_volatile_deducts_1(self, storage):
        result = check_log_rotation(_snap(
            journald_storage=storage,
            journal_persistent=False,
        ))
        assert "log_rotation.journald_volatile" in _deduction_keys(result)

    def test_volatile_has_fix_cmd(self):
        result = check_log_rotation(_snap(
            journald_storage="volatile",
            journal_persistent=False,
        ))
        f = _finding(result, "log_rotation.journald_volatile")
        assert f.cmd is not None
        assert f.cmd_type == "fix"

    def test_volatile_has_detail(self):
        result = check_log_rotation(_snap(
            journald_storage="volatile",
            journal_persistent=False,
        ))
        f = _finding(result, "log_rotation.journald_volatile")
        assert f.detail is not None

    def test_volatile_no_persistent_ok(self):
        result = check_log_rotation(_snap(
            journald_storage="volatile",
            journal_persistent=False,
        ))
        assert "log_rotation.journald_persistent" not in _keys(result)


# ---------------------------------------------------------------------------
# journald persistent
# ---------------------------------------------------------------------------

class TestJournaldPersistent:
    def test_explicit_persistent_is_ok(self):
        result = check_log_rotation(_snap(
            journald_storage="persistent",
            journal_persistent=True,
        ))
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK

    def test_auto_with_journal_dir_is_ok(self):
        """Storage=auto + /var/log/journal exists → persistent."""
        result = check_log_rotation(_snap(
            journald_storage="auto",
            journal_persistent=True,
        ))
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK

    def test_empty_storage_with_journal_dir_is_ok(self):
        """Storage= not set + /var/log/journal exists → persistent."""
        result = check_log_rotation(_snap(
            journald_storage="",
            journal_persistent=True,
        ))
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK

    def test_auto_without_journal_dir_is_volatile(self):
        """Storage=auto but /var/log/journal missing → warn."""
        result = check_log_rotation(_snap(
            journald_storage="auto",
            journal_persistent=False,
        ))
        assert _level(result, "log_rotation.journald_volatile") == FindingLevel.WARN

    def test_persistent_no_deduction(self):
        result = check_log_rotation(_snap(journald_storage="persistent"))
        assert "log_rotation.journald_volatile" not in _deduction_keys(result)


# ---------------------------------------------------------------------------
# journald disk limits
# ---------------------------------------------------------------------------

class TestJournaldLimits:
    def test_no_limit_is_info(self):
        result = check_log_rotation(_snap(journald_max_use="", journald_keep_free=""))
        assert _level(result, "log_rotation.journald_no_limit") == FindingLevel.INFO

    def test_no_limit_no_deduction(self):
        result = check_log_rotation(_snap(journald_max_use="", journald_keep_free=""))
        assert _deductions(result) == 0

    def test_no_limit_has_detail(self):
        result = check_log_rotation(_snap(journald_max_use="", journald_keep_free=""))
        f = _finding(result, "log_rotation.journald_no_limit")
        assert f.detail is not None

    def test_max_use_set_is_ok(self):
        result = check_log_rotation(_snap(journald_max_use="500M", journald_keep_free=""))
        assert _level(result, "log_rotation.journald_limit_ok") == FindingLevel.OK

    def test_keep_free_set_is_ok(self):
        result = check_log_rotation(_snap(journald_max_use="", journald_keep_free="1G"))
        assert _level(result, "log_rotation.journald_limit_ok") == FindingLevel.OK

    def test_both_set_is_ok(self):
        result = check_log_rotation(_snap(journald_max_use="500M", journald_keep_free="1G"))
        assert _level(result, "log_rotation.journald_limit_ok") == FindingLevel.OK

    def test_limit_ok_message_contains_setting(self):
        result = check_log_rotation(_snap(journald_max_use="500M", journald_keep_free=""), t=_t_format)
        f = _finding(result, "log_rotation.journald_limit_ok")
        assert "500M" in (f.message or "")

    def test_both_limits_in_message(self):
        result = check_log_rotation(_snap(journald_max_use="500M", journald_keep_free="1G"), t=_t_format)
        f = _finding(result, "log_rotation.journald_limit_ok")
        assert "500M" in (f.message or "")
        assert "1G" in (f.message or "")


# ---------------------------------------------------------------------------
# Remote syslog
# ---------------------------------------------------------------------------

class TestRemoteSyslog:
    def test_remote_configured_is_ok(self):
        result = check_log_rotation(_snap(
            syslog_daemon="rsyslog",
            remote_syslog_configured=True,
        ))
        assert _level(result, "log_rotation.remote_syslog_ok") == FindingLevel.OK

    def test_remote_configured_no_deduction(self):
        result = check_log_rotation(_snap(
            syslog_daemon="rsyslog",
            remote_syslog_configured=True,
        ))
        assert _deductions(result) == 0

    def test_remote_configured_message_contains_daemon(self):
        result = check_log_rotation(_snap(
            syslog_daemon="rsyslog",
            remote_syslog_configured=True,
        ), t=_t_format)
        f = _finding(result, "log_rotation.remote_syslog_ok")
        assert "rsyslog" in (f.message or "")

    def test_no_remote_is_info(self):
        result = check_log_rotation(_snap(
            syslog_daemon="rsyslog",
            remote_syslog_configured=False,
        ))
        assert _level(result, "log_rotation.remote_syslog_none") == FindingLevel.INFO

    def test_no_remote_no_deduction(self):
        result = check_log_rotation(_snap(
            syslog_daemon="rsyslog",
            remote_syslog_configured=False,
        ))
        assert _deductions(result) == 0

    def test_no_remote_has_detail(self):
        result = check_log_rotation(_snap(
            syslog_daemon="rsyslog",
            remote_syslog_configured=False,
        ))
        f = _finding(result, "log_rotation.remote_syslog_none")
        assert f.detail is not None

    def test_no_remote_message_contains_daemon(self):
        result = check_log_rotation(_snap(
            syslog_daemon="syslog-ng",
            remote_syslog_configured=False,
        ), t=_t_format)
        f = _finding(result, "log_rotation.remote_syslog_none")
        assert "syslog-ng" in (f.message or "")

    def test_no_syslog_daemon_no_finding(self):
        result = check_log_rotation(_snap(syslog_daemon=""))
        assert "log_rotation.remote_syslog_none" not in _keys(result)
        assert "log_rotation.remote_syslog_ok" not in _keys(result)

    def test_syslogng_remote_is_ok(self):
        result = check_log_rotation(_snap(
            syslog_daemon="syslog-ng",
            remote_syslog_configured=True,
        ))
        assert _level(result, "log_rotation.remote_syslog_ok") == FindingLevel.OK


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_max_deduction_2(self):
        """logrotate missing + journald volatile → −2 pts."""
        result = check_log_rotation(_snap(
            logrotate_installed=False,
            journald_storage="volatile",
            journal_persistent=False,
        ))
        assert _deductions(result) == 2

    def test_both_deduction_keys_present(self):
        result = check_log_rotation(_snap(
            logrotate_installed=False,
            journald_storage="volatile",
            journal_persistent=False,
        ))
        assert "log_rotation.logrotate_missing" in _deduction_keys(result)
        assert "log_rotation.journald_volatile" in _deduction_keys(result)

    def test_info_findings_no_deduction(self):
        """No rules + no limit + no remote → 0 deductions."""
        result = check_log_rotation(_snap(
            logrotate_rule_count=0,
            journald_max_use="",
            journald_keep_free="",
            remote_syslog_configured=False,
        ))
        assert _deductions(result) == 0

    def test_all_ok(self):
        result = check_log_rotation(_snap(
            logrotate_rule_count=20,
            journald_storage="persistent",
            journal_persistent=True,
            journald_max_use="500M",
            remote_syslog_configured=True,
        ))
        assert _deductions(result) == 0
        assert _level(result, "log_rotation.logrotate_ok") == FindingLevel.OK
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK
        assert _level(result, "log_rotation.journald_limit_ok") == FindingLevel.OK
        assert _level(result, "log_rotation.remote_syslog_ok") == FindingLevel.OK

    def test_journald_inactive_no_journald_findings(self):
        """If journald is not active, no journald findings are emitted."""
        result = check_log_rotation(_snap(journald_active=False))
        assert "log_rotation.journald_persistent" not in _keys(result)
        assert "log_rotation.journald_volatile" not in _keys(result)
        assert "log_rotation.journald_no_limit" not in _keys(result)
        assert "log_rotation.journald_limit_ok" not in _keys(result)


# ---------------------------------------------------------------------------
# LogRotationSnapshot defaults
# ---------------------------------------------------------------------------

class TestSnapshotDefaults:
    def test_default_logrotate_installed_false(self):
        assert not LogRotationSnapshot().logrotate_installed

    def test_default_rule_count_zero(self):
        assert LogRotationSnapshot().logrotate_rule_count == 0

    def test_default_journald_active_false(self):
        assert not LogRotationSnapshot().journald_active

    def test_default_journald_storage_empty(self):
        assert LogRotationSnapshot().journald_storage == ""

    def test_default_journald_max_use_empty(self):
        assert LogRotationSnapshot().journald_max_use == ""

    def test_default_journald_keep_free_empty(self):
        assert LogRotationSnapshot().journald_keep_free == ""

    def test_default_journal_persistent_false(self):
        assert not LogRotationSnapshot().journal_persistent

    def test_default_remote_syslog_false(self):
        assert not LogRotationSnapshot().remote_syslog_configured

    def test_default_syslog_daemon_empty(self):
        assert LogRotationSnapshot().syslog_daemon == ""


# ---------------------------------------------------------------------------
# journald_storage: normalization (strip + lower)
# ---------------------------------------------------------------------------

class TestJournaldStorageNormalization:
    def test_storage_with_leading_trailing_spaces(self):
        """`' persistent '` must be treated identically to `'persistent'`."""
        result = check_log_rotation(_snap(
            journald_storage=" persistent ",
            journal_persistent=True,
        ))
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK

    def test_storage_uppercase_persistent(self):
        result = check_log_rotation(_snap(journald_storage="PERSISTENT"))
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK

    def test_storage_mixed_case_volatile(self):
        result = check_log_rotation(_snap(journald_storage="Volatile"))
        assert _level(result, "log_rotation.journald_volatile") == FindingLevel.WARN

    def test_storage_uppercase_none(self):
        result = check_log_rotation(_snap(
            journald_storage="None",
            journal_persistent=False,
        ))
        assert _level(result, "log_rotation.journald_volatile") == FindingLevel.WARN

    def test_storage_auto_with_spaces(self):
        result = check_log_rotation(_snap(
            journald_storage="  auto  ",
            journal_persistent=True,
        ))
        assert _level(result, "log_rotation.journald_persistent") == FindingLevel.OK

    def test_unknown_storage_value_treated_as_volatile(self):
        """Unrecognised Storage= value → worst-case assumption (WARN + deduction)."""
        result = check_log_rotation(_snap(
            journald_storage="unknown-value",
            journal_persistent=False,
        ))
        assert _level(result, "log_rotation.journald_volatile") == FindingLevel.WARN
        assert _deductions(result) == 1


# ---------------------------------------------------------------------------
# logrotate_rule_count: negative and zero treated identically
# ---------------------------------------------------------------------------

class TestLogrotateRuleCountEdge:
    def test_negative_rule_count_treated_as_no_rules(self):
        """`logrotate_rule_count=-1` must produce INFO, not OK."""
        result = check_log_rotation(_snap(logrotate_rule_count=-1))
        assert _level(result, "log_rotation.logrotate_no_rules") == FindingLevel.INFO

    def test_negative_large_treated_as_no_rules(self):
        result = check_log_rotation(_snap(logrotate_rule_count=-999))
        assert _level(result, "log_rotation.logrotate_no_rules") == FindingLevel.INFO

    def test_negative_no_deduction(self):
        """No deduction for rule_count<0 — logrotate IS installed."""
        result = check_log_rotation(_snap(logrotate_rule_count=-1))
        assert _deductions(result) == 0

    def test_zero_still_info(self):
        """Regression: zero must still produce INFO, not OK."""
        result = check_log_rotation(_snap(logrotate_rule_count=0))
        assert _level(result, "log_rotation.logrotate_no_rules") == FindingLevel.INFO


# ---------------------------------------------------------------------------
# journald limits: whitespace-only values are not valid settings
# ---------------------------------------------------------------------------

class TestJournaldLimitWhitespace:
    def test_whitespace_only_keep_free_is_not_configured(self):
        """`'   '` is truthy but not a real setting — INFO expected."""
        result = check_log_rotation(_snap(
            journald_max_use="",
            journald_keep_free="   ",
        ))
        assert _level(result, "log_rotation.journald_no_limit") == FindingLevel.INFO

    def test_whitespace_only_max_use_is_not_configured(self):
        result = check_log_rotation(_snap(
            journald_max_use="   ",
            journald_keep_free="",
        ))
        assert _level(result, "log_rotation.journald_no_limit") == FindingLevel.INFO

    def test_both_whitespace_is_not_configured(self):
        result = check_log_rotation(_snap(
            journald_max_use="  ",
            journald_keep_free="  ",
        ))
        assert _level(result, "log_rotation.journald_no_limit") == FindingLevel.INFO

    def test_real_value_with_trailing_space_is_ok(self):
        """A value like `'500M '` stripped → `'500M'` → still a valid setting."""
        result = check_log_rotation(_snap(
            journald_max_use="500M ",
            journald_keep_free="",
        ))
        assert _level(result, "log_rotation.journald_limit_ok") == FindingLevel.OK


# ---------------------------------------------------------------------------
# _count_logrotate_rules: hidden files excluded
# ---------------------------------------------------------------------------

class TestCountLogrotateRules:
    def test_hidden_files_not_counted(self, tmp_path, monkeypatch):
        import bob.checks.log_rotation as lr_mod
        d = tmp_path / "logrotate.d"
        d.mkdir()
        (d / "nginx").write_text("# rule")
        (d / "rsyslog").write_text("# rule")
        (d / ".hidden").write_text("# hidden")
        monkeypatch.setattr(lr_mod, "_LOGROTATE_D", d)
        assert lr_mod._count_logrotate_rules()[0] == 2

    def test_directories_not_counted(self, tmp_path, monkeypatch):
        import bob.checks.log_rotation as lr_mod
        d = tmp_path / "logrotate.d"
        d.mkdir()
        (d / "nginx").write_text("# rule")
        (d / "subdir").mkdir()
        monkeypatch.setattr(lr_mod, "_LOGROTATE_D", d)
        assert lr_mod._count_logrotate_rules()[0] == 1

    def test_empty_dir_returns_zero(self, tmp_path, monkeypatch):
        import bob.checks.log_rotation as lr_mod
        d = tmp_path / "logrotate.d"
        d.mkdir()
        monkeypatch.setattr(lr_mod, "_LOGROTATE_D", d)
        assert lr_mod._count_logrotate_rules()[0] == 0

    def test_only_hidden_files_returns_zero(self, tmp_path, monkeypatch):
        import bob.checks.log_rotation as lr_mod
        d = tmp_path / "logrotate.d"
        d.mkdir()
        (d / ".keep").write_text("")
        (d / ".hidden").write_text("")
        monkeypatch.setattr(lr_mod, "_LOGROTATE_D", d)
        assert lr_mod._count_logrotate_rules()[0] == 0

    def test_missing_dir_returns_zero(self, tmp_path, monkeypatch):
        import bob.checks.log_rotation as lr_mod
        monkeypatch.setattr(lr_mod, "_LOGROTATE_D", tmp_path / "nonexistent")
        assert lr_mod._count_logrotate_rules()[0] == 0
