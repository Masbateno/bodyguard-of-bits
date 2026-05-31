"""
Unit tests for bob.report module.

Run with: python -m pytest tests/test_report.py -v
"""

import pytest
from pathlib import Path
from bob.report import AuditReport, NullReport, SystemInfo
from bob.scoring import Deduction


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def system_info():
    return SystemInfo(
        os_name="Linux Mint 22.3",
        hostname="testhost",
        kernel="6.8.0",
        ufw_version="0.36.2",
        iptables_version="1.8.9",
        nftables_version="",
        user="testuser",
        config_path="/home/testuser/.config/bob/config.conf",
        language="en",
        version="0.9.0",
    )


@pytest.fixture
def report(tmp_path):
    r = AuditReport.open(directory=tmp_path, version="0.9.0")
    yield r
    r.close()


def read_report(report: AuditReport) -> str:
    report.close()
    return report.path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# AuditReport.open
# ---------------------------------------------------------------------------

class TestOpen:
    def test_creates_file(self, tmp_path):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.close()
        assert r.path.exists()

    def test_filename_format(self, tmp_path):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.close()
        assert r.path.name.startswith("bob_")
        assert r.path.suffix == ".log"

    def test_enabled_is_true(self, tmp_path):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.close()
        assert r.enabled

    def test_path_in_given_directory(self, tmp_path):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.close()
        assert r.path.parent == tmp_path


# ---------------------------------------------------------------------------
# write_header
# ---------------------------------------------------------------------------

class TestWriteHeader:
    def test_contains_version(self, tmp_path, system_info):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.write_header(system_info)
        content = read_report(r)
        assert "0.9.0" in content

    def test_contains_hostname(self, tmp_path, system_info):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.write_header(system_info)
        content = read_report(r)
        assert "testhost" in content

    def test_contains_os(self, tmp_path, system_info):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.write_header(system_info)
        content = read_report(r)
        assert "Linux Mint 22.3" in content

    def test_contains_separator(self, tmp_path, system_info):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.write_header(system_info)
        content = read_report(r)
        assert "=" * 10 in content

    def test_contains_language(self, tmp_path, system_info):
        r = AuditReport.open(directory=tmp_path, version="0.9.0")
        r.write_header(system_info)
        content = read_report(r)
        assert "en" in content


# ---------------------------------------------------------------------------
# write_section
# ---------------------------------------------------------------------------

class TestWriteSection:
    def test_contains_title(self, report):
        report.write_section("UFW RULES ANALYSIS")
        content = read_report(report)
        assert "UFW RULES ANALYSIS" in content

    def test_section_format(self, report):
        report.write_section("MY SECTION")
        content = read_report(report)
        assert "=== MY SECTION ===" in content


# ---------------------------------------------------------------------------
# write_finding
# ---------------------------------------------------------------------------

class TestWriteFinding:
    def test_contains_level_and_message(self, report):
        report.write_finding("OK", "UFW is active")
        content = read_report(report)
        assert "[OK]" in content
        assert "UFW is active" in content

    def test_contains_timestamp(self, report):
        report.write_finding("OK", "message")
        content = read_report(report)
        assert "2026" in content  # year in timestamp

    def test_detail_appended(self, report):
        report.write_finding("WARN", "main message", "extra detail")
        content = read_report(report)
        assert "main message" in content
        assert "extra detail" in content

    def test_no_detail_no_extra_line(self, report):
        report.write_finding("OK", "message")
        content = read_report(report)
        lines = [l for l in content.splitlines() if l.strip()]
        assert len(lines) == 1


# ---------------------------------------------------------------------------
# write_raw / write_indented / write_separator
# ---------------------------------------------------------------------------

class TestWriteRaw:
    def test_raw_text(self, report):
        report.write_raw("plain text line")
        content = read_report(report)
        assert "plain text line" in content

    def test_indented(self, report):
        report.write_indented("indented line", indent=4)
        content = read_report(report)
        assert "    indented line" in content

    def test_separator(self, report):
        report.write_separator()
        content = read_report(report)
        assert "=" * 10 in content

    def test_thin_separator(self, report):
        report.write_separator(thin=True)
        content = read_report(report)
        assert "-" * 10 in content


# ---------------------------------------------------------------------------
# write_summary
# ---------------------------------------------------------------------------

class TestWriteSummary:
    def test_contains_score(self, report):
        report.write_summary(
            score=8, risk_level="LOW", network_context="local",
            public_ip="", ok_count=5, warn_count=1, alert_count=0,
            breakdown=[], labels={},
        )
        content = read_report(report)
        assert "8/10" in content

    def test_contains_risk(self, report):
        report.write_summary(
            score=8, risk_level="LOW", network_context="local",
            public_ip="", ok_count=5, warn_count=1, alert_count=0,
            breakdown=[], labels={},
        )
        content = read_report(report)
        assert "LOW" in content

    def test_public_ip_appended(self, report):
        report.write_summary(
            score=8, risk_level="LOW", network_context="public",
            public_ip="1.2.3.4", ok_count=5, warn_count=0, alert_count=0,
            breakdown=[], labels={},
        )
        content = read_report(report)
        assert "1.2.3.4" in content

    def test_breakdown_written(self, report):
        deductions = [Deduction(reason="Open port 22", points=2, context="public")]
        report.write_summary(
            score=8, risk_level="LOW", network_context="local",
            public_ip="", ok_count=5, warn_count=1, alert_count=0,
            breakdown=deductions, labels={},
        )
        content = read_report(report)
        assert "Open port 22" in content
        assert "-2" in content

    def test_empty_breakdown_no_section(self, report):
        report.write_summary(
            score=10, risk_level="LOW", network_context="local",
            public_ip="", ok_count=5, warn_count=0, alert_count=0,
            breakdown=[], labels={"breakdown": "SCORE BREAKDOWN"},
        )
        content = read_report(report)
        assert "SCORE BREAKDOWN" not in content


class TestWriteSummaryPostureAnnotation:
    """M-3 (v0.7.0 Phase 2.1): the on-disk .txt report must surface the
    same posture annotation as the terminal summary box so the two stay
    in sync. Before the fix, the .txt said ``Risk : HIGH`` with no
    explanation while the terminal said ``Niveau de risque : HIGH
    (majoré par posture : pare-feu inactif)``."""

    def test_posture_annotation_omitted_when_empty(self, report):
        """Default behaviour preserved when no escalation occurred."""
        report.write_summary(
            score=10, risk_level="LOW", network_context="local",
            public_ip="", ok_count=5, warn_count=0, alert_count=0,
            breakdown=[], labels={},
        )
        content = read_report(report)
        assert "Risk    : LOW" in content
        # No parens after the level
        assert "Risk    : LOW (" not in content

    def test_posture_annotation_appended_when_provided(self, report):
        """When the caller passes ``posture_annotation``, it appears
        parenthetically next to the level."""
        report.write_summary(
            score=10, risk_level="HIGH", network_context="local",
            public_ip="", ok_count=5, warn_count=0, alert_count=0,
            breakdown=[], labels={},
            posture_annotation="raised by posture: firewall inactive",
        )
        content = read_report(report)
        assert "Risk    : HIGH" in content
        assert "(raised by posture: firewall inactive)" in content

    def test_posture_annotation_kwarg_is_optional(self, report):
        """Backward compat: existing 9-positional-arg callers still work."""
        report.write_summary(
            score=8, risk_level="MEDIUM", network_context="local",
            public_ip="", ok_count=5, warn_count=1, alert_count=0,
            breakdown=[], labels={},
        )
        content = read_report(report)
        assert "Risk    : MEDIUM" in content


# ---------------------------------------------------------------------------
# write_risk_context_section
# ---------------------------------------------------------------------------

class TestWriteRiskContext:
    def test_contains_service_label(self, report):
        entries = [{
            "label": "Redis",
            "level": "CRITICAL",
            "exposure_label": "Exposure",
            "exposure": "No auth by default",
            "threat_label": "Threat",
            "threat": "RCE possible",
        }]
        report.write_risk_context_section("RISK CONTEXT", entries)
        content = read_report(report)
        assert "Redis" in content
        assert "CRITICAL" in content
        assert "No auth by default" in content

    def test_empty_entries_writes_nothing(self, report):
        report.write_risk_context_section("RISK CONTEXT", [])
        content = read_report(report)
        assert "RISK CONTEXT" not in content


# ---------------------------------------------------------------------------
# write_next_steps
# ---------------------------------------------------------------------------

class TestWriteNextSteps:
    def test_contains_steps(self, report):
        report.write_next_steps(["Fix alerts first.", "Review warnings."])
        content = read_report(report)
        assert "Fix alerts first." in content
        assert "Review warnings." in content

    def test_numbered(self, report):
        report.write_next_steps(["Step one"])
        content = read_report(report)
        assert "1. Step one" in content


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_context_manager_closes_file(self, tmp_path):
        with AuditReport.open(directory=tmp_path, version="0.9.0") as r:
            r.write_raw("test line")
            path = r.path
        assert path.exists()
        content = path.read_text()
        assert "test line" in content


# ---------------------------------------------------------------------------
# NullReport
# ---------------------------------------------------------------------------

class TestNullReport:
    def test_null_report_enabled_false(self):
        r = AuditReport.null()
        assert not r.enabled

    def test_null_report_path_is_none(self):
        r = AuditReport.null()
        assert r.path is None

    def test_null_report_discards_writes(self):
        r = AuditReport.null()
        r.write_raw("this should not crash")
        r.write_section("SECTION")
        r.write_finding("OK", "message")
        r.close()  # no-op, no crash

    def test_null_report_isinstance_of_audit_report(self):
        r = AuditReport.null()
        assert isinstance(r, AuditReport)
