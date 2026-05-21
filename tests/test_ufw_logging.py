"""Tests for UFW logging level check (CHECK 40)."""

from __future__ import annotations

import pytest
from bob.checks.firewall import FirewallStatus, check_ufw_logging, _read_logging_level
from bob.scoring import FindingLevel


def _status(logging_level: str = "low", active: bool = True) -> FirewallStatus:
    return FirewallStatus(
        installed=True, active=active,
        incoming_policy="deny",
        ufw_output="", numbered_output="",
        logging_level=logging_level,
    )


class TestCheckUfwLogging:
    # --- off: ALERT -2 ---

    def test_logging_off_alerts(self):
        result = check_ufw_logging(_status("off"))
        levels = [f.level for f in result.findings]
        assert FindingLevel.ALERT in levels

    def test_logging_off_deducts_2(self):
        result = check_ufw_logging(_status("off"))
        assert sum(d.points for d in result.deductions) == 2

    def test_logging_off_key(self):
        result = check_ufw_logging(_status("off"))
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert alert.key == "firewall.logging_off"

    def test_logging_off_cmd(self):
        result = check_ufw_logging(_status("off"))
        alert = next(f for f in result.findings if f.level == FindingLevel.ALERT)
        assert "ufw logging low" in alert.cmd

    # --- low / medium: OK ---

    def test_logging_low_ok(self):
        result = check_ufw_logging(_status("low"))
        assert result.findings[0].level == FindingLevel.OK

    def test_logging_medium_ok(self):
        result = check_ufw_logging(_status("medium"))
        assert result.findings[0].level == FindingLevel.OK

    def test_logging_ok_key(self):
        result = check_ufw_logging(_status("low"))
        assert result.findings[0].key == "firewall.logging_ok"

    def test_logging_low_no_deduction(self):
        result = check_ufw_logging(_status("low"))
        assert not result.deductions

    # --- high / full: INFO (too verbose) ---

    def test_logging_high_is_info(self):
        result = check_ufw_logging(_status("high"))
        assert result.findings[0].level == FindingLevel.INFO

    def test_logging_full_is_info(self):
        result = check_ufw_logging(_status("full"))
        assert result.findings[0].level == FindingLevel.INFO

    def test_logging_verbose_key_high(self):
        result = check_ufw_logging(_status("high"))
        assert result.findings[0].key == "firewall.logging_verbose"

    def test_logging_verbose_key_full(self):
        result = check_ufw_logging(_status("full"))
        assert result.findings[0].key == "firewall.logging_verbose"

    def test_logging_high_no_deduction(self):
        result = check_ufw_logging(_status("high"))
        assert not result.deductions

    def test_logging_full_no_deduction(self):
        result = check_ufw_logging(_status("full"))
        assert not result.deductions

    # --- unknown: INFO ---

    def test_logging_unknown_is_info(self):
        result = check_ufw_logging(_status("unknown"))
        assert result.findings[0].level == FindingLevel.INFO

    # --- inactive firewall ---

    def test_inactive_firewall_returns_empty(self):
        result = check_ufw_logging(_status("off", active=False))
        assert not result.findings


class TestReadLoggingLevel:
    # --- standard formats ---

    def test_parses_logging_on_low(self):
        output = "Status: active\nLogging: on (low)\nDefault: deny\n"
        assert _read_logging_level(output) == "low"

    def test_parses_logging_on_medium(self):
        output = "Status: active\nLogging: on (medium)\n"
        assert _read_logging_level(output) == "medium"

    def test_parses_logging_on_high(self):
        output = "Logging: on (high)\n"
        assert _read_logging_level(output) == "high"

    def test_parses_logging_on_full(self):
        output = "Logging: on (full)\n"
        assert _read_logging_level(output) == "full"

    def test_parses_logging_off(self):
        output = "Status: active\nLogging: off\n"
        assert _read_logging_level(output) == "off"

    # --- case-insensitive parsing ---

    def test_parses_lowercase_logging_line(self):
        output = "logging: on (low)\n"
        assert _read_logging_level(output) == "low"

    def test_parses_uppercase_logging_off(self):
        output = "LOGGING: OFF\n"
        assert _read_logging_level(output) == "off"

    def test_parses_mixed_case_level(self):
        output = "Logging: ON (MEDIUM)\n"
        assert _read_logging_level(output) == "medium"

    # --- missing / unknown ---

    def test_empty_output_returns_unknown(self, tmp_path):
        no_conf = tmp_path / "ufw.conf"
        assert _read_logging_level("", ufw_conf=no_conf) == "unknown"

    def test_no_logging_line_returns_unknown(self, tmp_path):
        no_conf = tmp_path / "ufw.conf"
        assert _read_logging_level("Status: active\nDefault: deny\n", ufw_conf=no_conf) == "unknown"

    def test_unrecognised_level_falls_through(self, tmp_path):
        no_conf = tmp_path / "ufw.conf"
        output = "Logging: on (exotic)\n"
        assert _read_logging_level(output, ufw_conf=no_conf) == "unknown"

    # --- fallback to conf file ---

    def test_fallback_to_conf_file(self, tmp_path):
        conf = tmp_path / "ufw.conf"
        conf.write_text("LOGLEVEL=medium\n")
        assert _read_logging_level("", ufw_conf=conf) == "medium"

    def test_fallback_conf_quoted_value(self, tmp_path):
        conf = tmp_path / "ufw.conf"
        conf.write_text('LOGLEVEL="low"\n')
        assert _read_logging_level("", ufw_conf=conf) == "low"

    def test_fallback_conf_uppercase_key(self, tmp_path):
        conf = tmp_path / "ufw.conf"
        conf.write_text("loglevel=high\n")
        assert _read_logging_level("", ufw_conf=conf) == "high"

    def test_output_takes_precedence_over_conf(self, tmp_path):
        # If verbose output has a level, conf file must be ignored
        conf = tmp_path / "ufw.conf"
        conf.write_text("LOGLEVEL=high\n")
        output = "Logging: on (low)\n"
        assert _read_logging_level(output, ufw_conf=conf) == "low"

    def test_fallback_conf_unreadable_returns_unknown(self, tmp_path):
        conf = tmp_path / "ufw.conf"
        conf.write_text("LOGLEVEL=low\n")
        conf.chmod(0o000)
        result = _read_logging_level("", ufw_conf=conf)
        conf.chmod(0o644)
        assert result == "unknown"
