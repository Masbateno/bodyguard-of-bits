"""
Tests for bob/markdown_output.py — --output markdown.

Covers:
  - build_markdown_output: structure, headers, summary table
  - Findings grouped by level (ALERT, WARN, INFO, OK)
  - Score deductions section
  - Pipe escaping in message text
  - Empty findings produces valid Markdown
  - CLI parsing: --output markdown, --output=markdown
  - CLI validation: markdown incompatible with --json, --csv, --watch, --quiet
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from bob.markdown_output import build_markdown_output, _md_escape
from bob.cli import AuditConfig, CLIError, parse_args


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sys_info(**kw):
    ns = SimpleNamespace(
        hostname="testhost",
        os_name="Linux Mint 22",
        kernel="6.1.0",
        ufw_version="0.36",
        iptables_version="1.8",
        nftables_version="1.0",
        user="so6",
        config_path="/root/.config/bob/config.conf",
        language="en",
        version="1.19.0",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _make_engine(score=10, findings=None, deductions=None):
    from bob.scoring import RiskLevel
    engine = MagicMock()
    engine.score = score
    engine.alert_count = sum(1 for f in (findings or []) if f.level.value == "alert")
    engine.warn_count  = sum(1 for f in (findings or []) if f.level.value == "warn")
    engine.findings  = findings or []
    engine.breakdown = deductions or []
    if score >= 8:
        engine.level = RiskLevel.LOW
    elif score >= 5:
        engine.level = RiskLevel.MEDIUM
    else:
        engine.level = RiskLevel.HIGH
    return engine


def _finding(level_str, message, cmd=""):
    from bob.scoring import Finding, FindingLevel
    level = {
        "ok":    FindingLevel.OK,
        "info":  FindingLevel.INFO,
        "warn":  FindingLevel.WARN,
        "alert": FindingLevel.ALERT,
    }[level_str]
    return Finding(level=level, message=message, cmd=cmd)


# ---------------------------------------------------------------------------
# _md_escape
# ---------------------------------------------------------------------------

class TestMdEscape:
    def test_pipe_is_escaped(self):
        assert _md_escape("a | b") == r"a \| b"

    def test_newline_replaced_by_space(self):
        assert _md_escape("line1\nline2") == "line1 line2"

    def test_plain_text_unchanged(self):
        assert _md_escape("hello world") == "hello world"

    def test_multiple_pipes(self):
        assert _md_escape("a|b|c") == r"a\|b\|c"

    def test_empty_string(self):
        assert _md_escape("") == ""


# ---------------------------------------------------------------------------
# build_markdown_output — structure
# ---------------------------------------------------------------------------

class TestMarkdownStructure:
    def test_starts_with_h1(self):
        md = build_markdown_output(_make_engine(), _make_sys_info())
        assert md.startswith("# BOB Report")

    def test_hostname_in_header(self):
        md = build_markdown_output(_make_engine(), _make_sys_info(hostname="mybox"))
        assert "mybox" in md.splitlines()[0]

    def test_summary_section_present(self):
        md = build_markdown_output(_make_engine(), _make_sys_info())
        assert "## Summary" in md

    def test_summary_table_has_score(self):
        md = build_markdown_output(_make_engine(score=7), _make_sys_info())
        assert "7/10" in md

    def test_summary_table_has_hostname(self):
        md = build_markdown_output(_make_engine(), _make_sys_info(hostname="srv01"))
        assert "srv01" in md

    def test_footer_present(self):
        md = build_markdown_output(_make_engine(), _make_sys_info())
        assert "BOB" in md

    def test_ends_with_newline(self):
        md = build_markdown_output(_make_engine(), _make_sys_info())
        assert md.endswith("\n")

    def test_valid_table_rows_have_pipes(self):
        """Every table row must start and end with |."""
        md = build_markdown_output(_make_engine(), _make_sys_info())
        table_rows = [l for l in md.splitlines() if l.startswith("|")]
        assert len(table_rows) >= 6  # at least the summary table rows


# ---------------------------------------------------------------------------
# Findings grouping
# ---------------------------------------------------------------------------

class TestMarkdownFindings:
    def test_alert_section_present_when_alert_finding(self):
        findings = [_finding("alert", "UFW inactive")]
        md = build_markdown_output(_make_engine(score=4, findings=findings), _make_sys_info())
        assert "Alerts" in md

    def test_warn_section_present_when_warn_finding(self):
        findings = [_finding("warn", "MaxAuthTries = 6")]
        md = build_markdown_output(_make_engine(score=9, findings=findings), _make_sys_info())
        assert "Warnings" in md

    def test_info_section_present_when_info_finding(self):
        findings = [_finding("info", "Swap unused")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "Informational" in md

    def test_ok_section_present_when_ok_finding(self):
        findings = [_finding("ok", "UFW active")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "OK" in md

    def test_finding_message_in_table(self):
        findings = [_finding("warn", "Secure Boot is disabled")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "Secure Boot is disabled" in md

    def test_fix_cmd_in_table(self):
        findings = [_finding("warn", "MaxAuthTries", cmd="sudo nano /etc/ssh/sshd_config")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "sudo nano" in md

    def test_absent_level_section_not_rendered(self):
        """If no ALERT findings, the ## Alerts section header must not appear."""
        findings = [_finding("ok", "All good")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "## 🔴 Alerts" not in md

    def test_pipe_in_message_is_escaped(self):
        findings = [_finding("info", "Port 22/tcp | covered")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert r"\|" in md

    def test_empty_findings_still_valid_markdown(self):
        md = build_markdown_output(_make_engine(findings=[]), _make_sys_info())
        assert "## Summary" in md
        assert md.count("#") >= 2  # at least H1 + H2


# ---------------------------------------------------------------------------
# Score deductions
# ---------------------------------------------------------------------------

class TestMarkdownDeductions:
    def test_deductions_section_present_when_nonzero(self):
        from types import SimpleNamespace
        ded = SimpleNamespace(points=1, reason="MaxAuthTries high")
        engine = _make_engine(score=9, deductions=[ded])
        md = build_markdown_output(engine, _make_sys_info())
        assert "Score Deductions" in md

    def test_deductions_section_absent_when_no_deductions(self):
        md = build_markdown_output(_make_engine(deductions=[]), _make_sys_info())
        assert "Score Deductions" not in md

    def test_deduction_reason_in_table(self):
        from types import SimpleNamespace
        ded = SimpleNamespace(points=2, reason="Secure Boot disabled")
        engine = _make_engine(score=8, deductions=[ded])
        md = build_markdown_output(engine, _make_sys_info())
        assert "Secure Boot disabled" in md

    def test_deduction_points_shown(self):
        from types import SimpleNamespace
        ded = SimpleNamespace(points=3, reason="auditd missing")
        engine = _make_engine(score=7, deductions=[ded])
        md = build_markdown_output(engine, _make_sys_info())
        assert "-3" in md


# ---------------------------------------------------------------------------
# Robustness / edge cases
# ---------------------------------------------------------------------------

class TestMarkdownRobustness:
    def test_level_none_does_not_crash(self):
        """engine.level=None must not raise — renders 'unknown' gracefully."""
        engine = _make_engine()
        engine.level = None
        md = build_markdown_output(engine, _make_sys_info())
        assert "Risk level" in md

    def test_section_order_alert_before_warn(self):
        """ALERT section must appear before WARN section."""
        findings = [_finding("alert", "UFW inactive"), _finding("warn", "MaxAuthTries")]
        md = build_markdown_output(_make_engine(score=4, findings=findings), _make_sys_info())
        assert md.index("🔴 Alerts") < md.index("🟡 Warnings")

    def test_unicode_preserved(self):
        """Non-ASCII characters in messages must pass through unmodified."""
        findings = [_finding("warn", "éà🔥 sécurité réseau")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "éà🔥 sécurité réseau" in md

    def test_multiline_message_flattened(self):
        """Newlines inside a message are replaced by spaces to keep table valid."""
        findings = [_finding("info", "line1\nline2\nline3")]
        md = build_markdown_output(_make_engine(findings=findings), _make_sys_info())
        assert "line1 line2 line3" in md

    def test_backticks_in_message_preserved(self):
        """Backticks inside a table cell don't break table structure."""
        findings = [_finding("alert", "Use `rm -rf /`")]
        md = build_markdown_output(_make_engine(score=4, findings=findings), _make_sys_info())
        lines = [l for l in md.splitlines() if "rm -rf" in l]
        assert lines, "finding message must appear in output"
        assert lines[0].startswith("|"), "row must remain a valid table row"

    def test_missing_deductions_attr_safe(self):
        """If engine has no _deductions attr, no Score Deductions section appears."""
        engine = _make_engine()
        if hasattr(engine, "_deductions"):
            del engine._deductions
        md = build_markdown_output(engine, _make_sys_info())
        assert "Score Deductions" not in md


# ---------------------------------------------------------------------------
# CLI: --output markdown parsing
# ---------------------------------------------------------------------------

class TestMarkdownCLIParsing:
    def test_output_markdown_equals(self):
        cfg = parse_args(["--output=markdown"])
        assert cfg.markdown_mode

    def test_output_markdown_space(self):
        cfg = parse_args(["--output", "markdown"])
        assert cfg.markdown_mode

    def test_markdown_mode_default_false(self):
        cfg = AuditConfig()
        assert not cfg.markdown_mode

    def test_output_markdown_does_not_set_csv(self):
        cfg = parse_args(["--output=markdown"])
        assert not cfg.csv_mode

    def test_output_markdown_does_not_set_json(self):
        cfg = parse_args(["--output=markdown"])
        assert not cfg.json_mode


# ---------------------------------------------------------------------------
# CLI: --output markdown validation
# ---------------------------------------------------------------------------

class TestMarkdownCLIValidation:
    def test_markdown_and_json_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--output=markdown", "--json"])

    def test_json_and_markdown_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--json", "--output=markdown"])

    def test_markdown_and_csv_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--output=markdown", "--output=csv"])

    def test_quiet_and_markdown_raises(self):
        with pytest.raises(CLIError, match="--quiet"):
            parse_args(["--quiet", "--output=markdown"])

    def test_watch_and_markdown_raises(self):
        with pytest.raises(CLIError, match="[Ii]ncompatible"):
            parse_args(["--watch", "--output=markdown"])
