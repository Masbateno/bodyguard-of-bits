"""
Unit tests for bob.output module.

Focuses on logic correctness (colour state, strip_ansi, no crashes)
rather than visual rendering — terminal output is hard to assert pixel-perfectly.

Run with: python -m pytest tests/test_output.py -v
"""

import io
import sys
import pytest
from bob import output
from bob.output import (
    _strip_ansi,
    _COLOURS_ON,
    _COLOURS_OFF,
    print_ok,
    print_warn,
    print_alert,
    print_info,
    print_section,
    print_service_header,
    print_port_detail,
    print_recommendation,
    print_dim,
    print_risk_context,
    print_summary_box,
)


@pytest.fixture(autouse=True)
def reset_output():
    """Reset output state and capture stdout between tests."""
    output.init(no_color=True)  # default to no-color in tests
    yield
    output.init(no_color=True)


def capture(fn, *args, **kwargs) -> str:
    """Capture stdout output from a print_* call."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        fn(*args, **kwargs)
    finally:
        sys.stdout = old
    return buf.getvalue()


class TestInit:
    def test_init_no_color_disables_ansi(self):
        output.init(no_color=True)
        assert output._c.reset == ""
        assert output._c.green == ""

    def test_init_color_enables_ansi(self):
        output.init(no_color=False)
        assert output._c.reset != ""
        assert output._c.green != ""

    def test_init_default_is_color(self):
        output.init()
        assert output._c.reset != ""


class TestStripAnsi:
    def test_strips_colour_codes(self):
        assert _strip_ansi("\033[32mhello\033[0m") == "hello"

    def test_strips_bold(self):
        assert _strip_ansi("\033[1mbold\033[0m") == "bold"

    def test_plain_string_unchanged(self):
        assert _strip_ansi("plain text") == "plain text"

    def test_empty_string(self):
        assert _strip_ansi("") == ""

    def test_complex_sequence(self):
        assert _strip_ansi("\033[1;31mred bold\033[0m text") == "red bold text"


class TestStatusLines:
    def test_print_ok_contains_message(self):
        out = capture(print_ok, "All good")
        assert "All good" in out

    def test_print_ok_contains_ok_label(self):
        out = capture(print_ok, "All good")
        assert "OK" in out

    def test_print_warn_contains_message(self):
        out = capture(print_warn, "Be careful")
        assert "Be careful" in out

    def test_print_alert_contains_message(self):
        out = capture(print_alert, "Critical issue")
        assert "Critical issue" in out

    def test_print_info_contains_message(self):
        out = capture(print_info, "Just so you know")
        assert "Just so you know" in out

    def test_print_ok_with_detail(self):
        out = capture(print_ok, "Main message", "Extra detail")
        assert "Main message" in out
        assert "Extra detail" in out

    def test_print_ok_no_detail_no_extra_line(self):
        out = capture(print_ok, "Main message")
        lines = [l for l in out.splitlines() if l.strip()]
        assert len(lines) == 1


class TestSection:
    def test_section_contains_title(self):
        out = capture(print_section, "MY SECTION")
        assert "MY SECTION" in out

    def test_section_has_border_chars(self):
        out = capture(print_section, "TITLE")
        assert "┌" in out
        assert "└" in out
        assert "│" in out


class TestServiceHeader:
    def test_contains_label(self):
        out = capture(print_service_header, "SSH Server")
        assert "SSH Server" in out

    def test_contains_arrow(self):
        out = capture(print_service_header, "Redis")
        assert "▶" in out


class TestPortDetail:
    def test_contains_message(self):
        out = capture(print_port_detail, "22/tcp: exposure = open_world")
        assert "22/tcp" in out

    def test_contains_arrow(self):
        out = capture(print_port_detail, "22/tcp")
        assert "↳" in out


class TestRecommendation:
    def test_single_string(self):
        out = capture(print_recommendation, "sudo ufw deny 22/tcp")
        assert "sudo ufw deny 22/tcp" in out
        assert "→" in out

    def test_list_of_strings(self):
        out = capture(print_recommendation, ["line one", "line two"])
        assert "line one" in out
        assert "line two" in out

    def test_multiline_string(self):
        out = capture(print_recommendation, "line one\nline two")
        assert "line one" in out
        assert "line two" in out


class TestDim:
    def test_contains_message(self):
        out = capture(print_dim, "subtle note")
        assert "subtle note" in out


class TestRiskContext:
    def test_contains_all_fields(self):
        out = capture(
            print_risk_context,
            title="Risk context",
            level="CRITICAL",
            exposure_label="Exposure",
            exposure="Heavily targeted",
            threat_label="Threat",
            threat="Full shell access",
            is_critical=True,
        )
        assert "Risk context" in out
        assert "CRITICAL" in out
        assert "Heavily targeted" in out
        assert "Full shell access" in out

    def test_high_risk_non_critical(self):
        out = capture(
            print_risk_context,
            title="Risk context",
            level="HIGH",
            exposure_label="Exposure",
            exposure="Some exposure",
            threat_label="Threat",
            threat="Some threat",
            is_critical=False,
        )
        assert "HIGH" in out


class TestSummaryBox:
    def test_contains_values(self):
        out = capture(print_summary_box, [
            ("Score", "10/10"),
            ("Risk",  "LOW"),
        ])
        assert "10/10" in out
        assert "LOW" in out

    def test_separator_row(self):
        out = capture(print_summary_box, [
            ("Score", "10/10"),
            ("---", ""),
            ("Risk", "LOW"),
        ])
        assert "═" in out

    def test_box_borders(self):
        out = capture(print_summary_box, [("Score", "10/10")])
        assert "╔" in out
        assert "╚" in out
        assert "║" in out
