"""
Tests for bob/csv_output.py — CSV export.

Covers:
  - build_csv_output: headers, one row per finding, metadata columns, empty findings
  - CLI parsing: --output csv, --output=csv, --output json alias, unknown value
  - CLI validation: --output csv + --quiet, + --json, missing value
  - AuditConfig default csv_mode=False
"""

from __future__ import annotations

import csv
import io

import pytest

from bob.cli import AuditConfig, CLIError, parse_args


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(score: int = 7, alerts: int = 1, warnings: int = 2):
    """Build a minimal ScoreEngine with the given counters and a few findings.

    score is applied via deductions from MAX_SCORE (10) so that engine.score
    returns the expected value.  alert_count / warn_count are derived from
    the actual findings list, so we populate it accordingly.
    """
    from bob.scoring import MAX_SCORE, Deduction, FindingLevel, ScoreEngine, Finding
    engine = ScoreEngine()
    # Apply deductions to reach the requested score
    deduct = MAX_SCORE - score
    if deduct > 0:
        engine._apply_deduction(Deduction(reason="test deduction", points=deduct))
    if alerts:
        engine.findings.append(Finding(
            level=FindingLevel.ALERT,
            message="SSH PasswordAuthentication enabled",
            nature="ssh_audit",
            cmd="sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
            note="Restart sshd after applying.",
        ))
    if warnings:
        engine.findings.append(Finding(
            level=FindingLevel.WARN,
            message="UFW log level is low",
            nature="firewall",
            cmd="sudo ufw logging medium",
            note="",
        ))
    return engine


def _make_sys_info(hostname: str = "testhost"):
    from bob.report import SystemInfo
    return SystemInfo(
        hostname=hostname,
        os_name="Ubuntu 22.04",
        kernel="5.15",
        ufw_version="0.36",
        iptables_version="1.8.7",
        nftables_version=None,
        user="root",
        config_path="",
        language="en",
        version="1.19.0",
    )


def _parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


# ---------------------------------------------------------------------------
# build_csv_output: headers
# ---------------------------------------------------------------------------

class TestCSVHeaders:
    def test_header_present(self):
        from bob.csv_output import build_csv_output, _HEADERS
        engine = _make_engine()
        out = build_csv_output(engine, _make_sys_info())
        first_line = out.splitlines()[0]
        for col in _HEADERS:
            assert col in first_line

    def test_all_expected_columns(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert set(rows[0].keys()) >= {
            "host", "timestamp", "score", "risk", "alerts", "warnings",
            "level", "section", "message", "fix_cmd", "note",
        }


# ---------------------------------------------------------------------------
# build_csv_output: one row per finding
# ---------------------------------------------------------------------------

class TestCSVRows:
    def test_row_count_matches_findings(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=2)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        # 2 findings (1 alert appended, 1 warn appended in helper, but warnings=2 counter
        # only appended 1 WARN in helper) → 2 Finding objects
        assert len(rows) == 2

    def test_alert_level_correct(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=0)
        # _make_engine(alerts=1, warnings=0) produces exactly one ALERT finding
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["level"] == "alert"

    def test_message_preserved(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=0)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert "PasswordAuthentication" in rows[0]["message"]

    def test_fix_cmd_preserved(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=0)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert "sshd_config" in rows[0]["fix_cmd"]

    def test_note_preserved(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=0)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["note"] == "Restart sshd after applying."

    def test_section_preserved(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=0)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["section"] == "ssh_audit"

    def test_empty_note_is_empty_string(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=0, warnings=1)
        # _make_engine(alerts=0, warnings=1) produces exactly one WARN finding (no note)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["note"] == ""


# ---------------------------------------------------------------------------
# build_csv_output: metadata repeated on each row
# ---------------------------------------------------------------------------

class TestCSVMetadata:
    def test_host_repeated(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info("myserver")))
        for row in rows:
            assert row["host"] == "myserver"

    def test_score_repeated(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine(score=8)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        for row in rows:
            assert row["score"] == "8"

    def test_risk_repeated(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        risks = {row["risk"] for row in rows}
        assert len(risks) == 1  # all rows have same risk

    def test_timestamp_is_iso(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        ts = rows[0]["timestamp"]
        assert "T" in ts
        assert "+00:00" in ts or "Z" in ts

    def test_alerts_count(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        engine.findings.append(Finding(level=FindingLevel.ALERT, message="a1", nature="s"))
        engine.findings.append(Finding(level=FindingLevel.ALERT, message="a2", nature="s"))
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        for row in rows:
            assert row["alerts"] == "2"

    def test_warnings_count(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        for i in range(3):
            engine.findings.append(Finding(level=FindingLevel.WARN, message=f"w{i}", nature="s"))
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        for row in rows:
            assert row["warnings"] == "3"


# ---------------------------------------------------------------------------
# build_csv_output: empty findings (perfect score)
# ---------------------------------------------------------------------------

class TestCSVEmptyFindings:
    def test_single_row_when_no_findings(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()  # score=10, no findings
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert len(rows) == 1

    def test_empty_level_when_no_findings(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["level"] == ""

    def test_empty_message_when_no_findings(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["message"] == ""

    def test_metadata_present_when_no_findings(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info("clean-host")))
        assert rows[0]["host"] == "clean-host"
        assert rows[0]["score"] == "10"


# ---------------------------------------------------------------------------
# build_csv_output: output is valid CSV
# ---------------------------------------------------------------------------

class TestCSVFormat:
    def test_parseable_by_csv_module(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        out = build_csv_output(engine, _make_sys_info())
        rows = _parse_csv(out)
        assert len(rows) > 0

    def test_comma_in_message_escaped(self):
        """Messages containing commas must not break CSV parsing."""
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        engine._score = 7
        engine.findings.append(Finding(
            level=FindingLevel.WARN,
            message="Open ports: 22, 80, 443",
            nature="ports",
        ))
        out = build_csv_output(engine, _make_sys_info())
        rows = _parse_csv(out)
        assert "Open ports: 22, 80, 443" in rows[0]["message"]

    def test_newline_in_cmd_roundtrip_exact(self):
        """Newlines inside a field must survive CSV quoting — exact round-trip."""
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        engine.findings.append(Finding(
            level=FindingLevel.ALERT,
            message="test",
            nature="s",
            cmd="line1\nline2",
        ))
        out = build_csv_output(engine, _make_sys_info())
        rows = _parse_csv(out)
        assert rows[0]["fix_cmd"] == "line1\nline2"

    def test_output_ends_with_newline(self):
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        out = build_csv_output(engine, _make_sys_info())
        assert out.endswith("\n")


# ---------------------------------------------------------------------------
# CLI: --output parsing
# ---------------------------------------------------------------------------

class TestOutputCLIParsing:
    def test_output_csv_equals(self):
        cfg = parse_args(["--output=csv"])
        assert cfg.csv_mode

    def test_output_csv_space(self):
        cfg = parse_args(["--output", "csv"])
        assert cfg.csv_mode

    def test_output_json_sets_json_mode(self):
        cfg = parse_args(["--output=json"])
        assert cfg.json_mode
        assert not cfg.csv_mode

    def test_output_json_space(self):
        cfg = parse_args(["--output", "json"])
        assert cfg.json_mode

    def test_unknown_format_raises(self):
        with pytest.raises(CLIError, match="--output requires"):
            parse_args(["--output=xml"])

    def test_unknown_format_space_raises(self):
        with pytest.raises(CLIError, match="--output requires"):
            parse_args(["--output", "text"])

    def test_csv_mode_default_false(self):
        cfg = AuditConfig()
        assert not cfg.csv_mode

    def test_output_csv_does_not_set_json(self):
        cfg = parse_args(["--output=csv"])
        assert not cfg.json_mode

    def test_output_compatible_with_verbose(self):
        cfg = parse_args(["--output=csv", "--verbose"])
        assert cfg.csv_mode
        assert cfg.verbose

    def test_output_compatible_with_profile(self):
        cfg = parse_args(["--output=csv", "--profile=desktop"])
        assert cfg.csv_mode
        assert cfg.profile == "desktop"


# ---------------------------------------------------------------------------
# CLI: --output csv validation errors
# ---------------------------------------------------------------------------

class TestOutputCLIValidation:
    def test_csv_and_quiet_raises(self):
        with pytest.raises(CLIError, match="--quiet"):
            parse_args(["--output=csv", "--quiet"])

    def test_quiet_and_csv_raises(self):
        with pytest.raises(CLIError, match="--quiet"):
            parse_args(["--quiet", "--output=csv"])

    def test_csv_and_json_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--output=csv", "--json"])

    def test_json_and_csv_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--json", "--output=csv"])

    def test_csv_and_json_full_raises(self):
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--output=csv", "--json-full"])


# ---------------------------------------------------------------------------
# Hardening / edge cases
# ---------------------------------------------------------------------------

class TestCSVHardening:
    """Tests targeting probable bugs: None fields, header order, quotes, UTC."""

    def test_header_order_is_strict(self):
        """Headers must appear in exactly the order defined by _HEADERS."""
        from bob.csv_output import build_csv_output, _HEADERS
        engine = _make_engine()
        out = build_csv_output(engine, _make_sys_info())
        first_line = out.splitlines()[0]
        assert first_line == ",".join(_HEADERS)

    def test_none_cmd_is_empty_string(self):
        """If cmd is None (type annotation violated), CSV must not contain 'None'."""
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        f = Finding(level=FindingLevel.WARN, message="x", nature="s")
        f.cmd = None  # force None despite type hint
        engine.findings.append(f)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["fix_cmd"] == ""

    def test_none_note_is_empty_string(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        f = Finding(level=FindingLevel.WARN, message="x", nature="s")
        f.note = None
        engine.findings.append(f)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["note"] == ""

    def test_none_section_is_empty_string(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        f = Finding(level=FindingLevel.WARN, message="x", nature="s")
        f.nature = None
        engine.findings.append(f)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["section"] == ""

    def test_none_message_is_empty_string(self):
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        f = Finding(level=FindingLevel.WARN, message="x", nature="s")
        f.message = None
        engine.findings.append(f)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["message"] == ""

    def test_quotes_in_message_are_escaped(self):
        """Double quotes inside a field must round-trip correctly through CSV."""
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        engine.findings.append(Finding(
            level=FindingLevel.WARN,
            message='He said "hello, world"',
            nature="test",
        ))
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["message"] == 'He said "hello, world"'

    def test_level_value_is_lowercase_enum_string(self):
        """level column must be the enum value string, not repr/uppercase."""
        from bob.csv_output import build_csv_output
        engine = _make_engine(alerts=1, warnings=0)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["level"] == "alert"
        assert "FindingLevel" not in rows[0]["level"]
        assert rows[0]["level"] == rows[0]["level"].lower()

    def test_timestamp_is_utc(self):
        """Timestamp must be ISO 8601 with UTC timezone."""
        from datetime import datetime, timezone
        from bob.csv_output import build_csv_output
        engine = _make_engine()
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        ts = rows[0]["timestamp"]
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo == timezone.utc

    def test_output_equals_empty_value_raises(self):
        with pytest.raises(CLIError, match="--output"):
            parse_args(["--output="])

    def test_output_csv_uppercase_raises(self):
        """CLI is case-sensitive — 'CSV' is not a valid format."""
        with pytest.raises(CLIError, match="--output requires"):
            parse_args(["--output=CSV"])

    def test_output_csv_then_json_raises(self):
        """Two --output flags conflict."""
        with pytest.raises(CLIError, match="cannot be combined"):
            parse_args(["--output=csv", "--output=json"])


# ---------------------------------------------------------------------------
# Unicode, volume, score type
# ---------------------------------------------------------------------------

class TestCSVRobustness:
    def test_unicode_characters_preserved(self):
        """UTF-8 messages round-trip exactly through StringIO + csv module."""
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        engine.findings.append(Finding(
            level=FindingLevel.WARN,
            message="éàü — sécurité 🔥",
            nature="réseau",
        ))
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert rows[0]["message"] == "éàü — sécurité 🔥"
        assert rows[0]["section"] == "réseau"

    def test_score_value_is_string_in_parsed_csv(self):
        """csv.DictReader always returns strings — score must be parseable as int."""
        from bob.csv_output import build_csv_output
        engine = _make_engine(score=8)
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert isinstance(rows[0]["score"], str)
        assert int(rows[0]["score"]) == 8

    def test_large_number_of_findings(self):
        """5 000 findings must all appear as rows — no truncation or OOM."""
        from bob.csv_output import build_csv_output
        from bob.scoring import Finding, FindingLevel, ScoreEngine
        engine = ScoreEngine()
        for i in range(5000):
            engine.findings.append(Finding(
                level=FindingLevel.WARN,
                message=f"finding {i}",
                nature="test",
            ))
        rows = _parse_csv(build_csv_output(engine, _make_sys_info()))
        assert len(rows) == 5000
        assert rows[0]["message"] == "finding 0"
        assert rows[4999]["message"] == "finding 4999"
