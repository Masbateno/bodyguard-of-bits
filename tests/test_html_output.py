"""Tests for bob/html_output.py — --html export."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup

from bob.html_output import build_html_output, _h, _score_color
from bob.cli import CLIError, parse_args


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
        version="1.21.0",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class FakeEngine:
    """Minimal engine stub — tests the actual interface, not a MagicMock."""
    def __init__(self, score=10, findings=None, deductions=None):
        from bob.scoring import RiskLevel
        self.score     = score
        self.findings  = findings or []
        self.breakdown = deductions or []
        self.alert_count = sum(1 for f in self.findings if f.level.value == "alert")
        self.warn_count  = sum(1 for f in self.findings if f.level.value == "warn")
        if score >= 8:
            self.level = RiskLevel.LOW
        elif score >= 5:
            self.level = RiskLevel.MEDIUM
        else:
            self.level = RiskLevel.HIGH


def _finding(level_str, message, cmd=""):
    from bob.scoring import Finding, FindingLevel
    level = {
        "ok":    FindingLevel.OK,
        "info":  FindingLevel.INFO,
        "warn":  FindingLevel.WARN,
        "alert": FindingLevel.ALERT,
    }[level_str]
    return Finding(level=level, message=message, cmd=cmd)


def _deduction(points, reason):
    return SimpleNamespace(points=points, reason=reason)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


# ---------------------------------------------------------------------------
# _h — HTML escaping
# ---------------------------------------------------------------------------

class TestHtmlEscape:
    def test_ampersand_escaped(self):
        assert "&amp;" in _h("a & b")

    def test_angle_brackets_escaped(self):
        assert "&lt;" in _h("<script>")
        assert "&gt;" in _h("</script>")

    def test_single_quote_escaped(self):
        result = _h("it's")
        assert "'" not in result or "&#x27;" in result or "&apos;" in result

    def test_double_quote_escaped(self):
        result = _h('say "hello"')
        assert '"' not in result

    def test_plain_text_unchanged(self):
        assert _h("hello world") == "hello world"

    def test_empty_string(self):
        assert _h("") == ""

    def test_combined_escape(self):
        s = '<a href="x">foo & bar</a>'
        escaped = _h(s)
        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped
        assert "&amp;" in escaped

    def test_numeric_value_coerced(self):
        assert _h(42) == "42"


# ---------------------------------------------------------------------------
# _score_color
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (10, "#198754"),
    (8,  "#198754"),
    (7,  "#fd7e14"),
    (5,  "#fd7e14"),
    (4,  "#dc3545"),
    (0,  "#dc3545"),
    (-1, "#dc3545"),   # below range → red
    (42, "#198754"),   # above range → green
])
def test_score_color_parametrized(score, expected):
    assert _score_color(score) == expected


# ---------------------------------------------------------------------------
# HTML structure (DOM-based)
# ---------------------------------------------------------------------------

class TestHtmlStructure:
    def test_starts_with_doctype(self):
        html = build_html_output(FakeEngine(), _make_sys_info())
        assert html.startswith("<!DOCTYPE html>")

    def test_has_head_and_body(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info()))
        assert soup.head is not None
        assert soup.body is not None

    def test_charset_utf8(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info()))
        meta = soup.find("meta", attrs={"charset": True})
        assert meta is not None
        assert meta["charset"].lower() == "utf-8"

    def test_contains_embedded_css(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info()))
        assert soup.find("style") is not None

    def test_hostname_in_title(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info(hostname="mybox")))
        assert "mybox" in soup.title.string

    def test_hostname_in_h1(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info(hostname="srv42")))
        h1 = soup.find("h1")
        assert h1 is not None and "srv42" in h1.text

    def test_score_present_in_circle(self):
        soup = _soup(build_html_output(FakeEngine(score=7), _make_sys_info()))
        circle = soup.find(class_="score-circle")
        assert circle is not None
        assert "7" in circle.text

    def test_at_most_one_external_link(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info()))
        links = soup.find_all("a")
        assert len(links) <= 1

    def test_footer_present(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info()))
        footer = soup.find("footer")
        assert footer is not None
        assert "BOB" in footer.text

    def test_no_script_tags(self):
        html = build_html_output(FakeEngine(), _make_sys_info())
        assert "<script" not in html

    def test_no_inline_event_handlers(self):
        html = build_html_output(FakeEngine(), _make_sys_info())
        assert "onerror=" not in html
        assert "onclick=" not in html
        assert "onload=" not in html

    def test_no_javascript_urls(self):
        html = build_html_output(FakeEngine(), _make_sys_info())
        assert "javascript:" not in html


# ---------------------------------------------------------------------------
# Findings rendering
# ---------------------------------------------------------------------------

class TestHtmlFindings:
    def test_alert_finding_included(self):
        f = _finding("alert", "SSH password auth enabled")
        html = build_html_output(FakeEngine(findings=[f], score=8), _make_sys_info())
        assert "SSH password auth enabled" in html

    def test_warn_finding_included(self):
        f = _finding("warn", "No backup solution found")
        html = build_html_output(FakeEngine(findings=[f], score=9), _make_sys_info())
        assert "No backup solution found" in html

    def test_ok_finding_included(self):
        f = _finding("ok", "UFW is active and enabled")
        html = build_html_output(FakeEngine(findings=[f]), _make_sys_info())
        assert "UFW is active and enabled" in html

    def test_fix_command_in_code_tag(self):
        f = _finding("alert", "Password auth", "sudo nano /etc/ssh/sshd_config")
        soup = _soup(build_html_output(FakeEngine(findings=[f], score=8), _make_sys_info()))
        code_tags = soup.find_all("code")
        assert any("sudo nano" in c.text for c in code_tags)

    def test_alert_badge_present(self):
        f = _finding("alert", "Something bad")
        soup = _soup(build_html_output(FakeEngine(findings=[f], score=8), _make_sys_info()))
        badges = soup.find_all(class_="badge")
        assert any("ALERT" in b.text for b in badges)

    def test_no_findings_still_valid_html(self):
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info()))
        assert soup.find("html") is not None

    def test_empty_cmd_produces_no_code_tag_for_that_finding(self):
        f = _finding("warn", "Some warning")  # cmd=""
        html = build_html_output(FakeEngine(findings=[f]), _make_sys_info())
        # Empty cmd → no <code> wrapping empty string
        assert "<code></code>" not in html


# ---------------------------------------------------------------------------
# XSS resistance
# ---------------------------------------------------------------------------

class TestXssResistance:
    def test_script_tag_in_message_escaped(self):
        f = _finding("alert", "<script>alert('xss')</script>")
        html = build_html_output(FakeEngine(findings=[f], score=8), _make_sys_info())
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_script_tag_in_cmd_escaped(self):
        f = _finding("alert", "bad", "<script>evil()</script>")
        html = build_html_output(FakeEngine(findings=[f], score=8), _make_sys_info())
        assert "<script>evil" not in html

    def test_img_onerror_payload_not_rendered(self):
        """img tag injected via message must not appear as a real DOM element."""
        payload = '"><img src=x onerror=alert(1)>'
        f = _finding("warn", payload)
        soup = _soup(build_html_output(FakeEngine(findings=[f]), _make_sys_info()))
        assert soup.find("img") is None

    def test_javascript_url_in_cmd_not_in_href(self):
        """javascript: in cmd is shown in <code>, never in a href attribute."""
        f = _finding("warn", "msg", "javascript:alert(1)")
        soup = _soup(build_html_output(FakeEngine(findings=[f]), _make_sys_info()))
        for link in soup.find_all("a"):
            assert not link.get("href", "").startswith("javascript:")

    def test_xss_in_hostname_not_rendered(self):
        """Script tag in hostname must not appear as a real DOM element."""
        soup = _soup(build_html_output(FakeEngine(), _make_sys_info(hostname="<script>pwned</script>")))
        assert soup.find("script") is None

    def test_xss_in_deduction_reason_not_rendered(self):
        """img tag in deduction reason must not appear as a real DOM element."""
        d = _deduction(1, '<img src=x onerror=alert(1)>')
        soup = _soup(build_html_output(FakeEngine(deductions=[d]), _make_sys_info()))
        assert soup.find("img") is None

    def test_combined_xss_payload_not_rendered(self):
        """SVG injected via finding message must not appear as a real DOM element."""
        payload = '\'";><svg onload=alert(document.domain)>'
        f = _finding("alert", payload)
        soup = _soup(build_html_output(FakeEngine(findings=[f], score=8), _make_sys_info()))
        assert soup.find("svg") is None


# ---------------------------------------------------------------------------
# Deductions
# ---------------------------------------------------------------------------

class TestHtmlDeductions:
    def test_deductions_section_when_present(self):
        d = _deduction(2, "SSH password auth enabled")
        soup = _soup(build_html_output(FakeEngine(deductions=[d], score=8), _make_sys_info()))
        assert any("Deduction" in h.text for h in soup.find_all("h2"))

    def test_deduction_points_shown(self):
        d = _deduction(2, "test reason")
        html = build_html_output(FakeEngine(deductions=[d], score=8), _make_sys_info())
        assert "2" in html

    def test_no_deductions_section_when_empty(self):
        html = build_html_output(FakeEngine(deductions=[], score=10), _make_sys_info())
        assert "Score Deductions" not in html

    def test_zero_point_deductions_omitted(self):
        """Deductions with points=0 must not appear in the deductions table."""
        d = _deduction(0, "phantom deduction")
        html = build_html_output(FakeEngine(deductions=[d], score=10), _make_sys_info())
        assert "phantom deduction" not in html


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestHtmlPerformance:
    def test_large_number_of_findings(self):
        """500 findings must render without error and include last entry."""
        findings = [_finding("warn", f"finding {i}") for i in range(500)]
        html = build_html_output(FakeEngine(findings=findings, score=5), _make_sys_info())
        assert "finding 499" in html

    def test_large_deductions_list(self):
        deductions = [_deduction(1, f"reason {i}") for i in range(200)]
        html = build_html_output(FakeEngine(deductions=deductions, score=0), _make_sys_info())
        assert "reason 199" in html


# ---------------------------------------------------------------------------
# CLI — --html flag
# ---------------------------------------------------------------------------

class TestHtmlCli:
    def test_html_flag(self):
        assert parse_args(["--html"]).html_mode

    def test_html_false_by_default(self):
        assert not parse_args([]).html_mode

    def test_html_incompatible_with_json(self):
        with pytest.raises(CLIError):
            parse_args(["--html", "--json"])

    def test_html_incompatible_with_csv(self):
        with pytest.raises(CLIError):
            parse_args(["--html", "--output", "csv"])

    def test_html_incompatible_with_markdown(self):
        with pytest.raises(CLIError):
            parse_args(["--html", "--output", "markdown"])

    def test_html_incompatible_with_quiet(self):
        with pytest.raises(CLIError):
            parse_args(["--html", "--quiet"])

    def test_html_incompatible_with_watch(self):
        with pytest.raises(CLIError):
            parse_args(["--html", "--watch"])

    def test_html_compatible_with_verbose(self):
        config = parse_args(["--html", "--verbose"])
        assert config.html_mode and config.verbose


class TestHtmlEffectiveLevel:
    """I-1 (v0.7.0 Phase 2.1): HTML must render the posture-aware effective_level,
    matching display/JSON/CSV/webhook contracts. Before the fix, a host with
    UFW inactive saw 'LOW' in the HTML report despite 'HIGH' in the terminal."""

    def test_clean_engine_renders_score_only_level(self):
        from bob.scoring import ScoreEngine
        eng = ScoreEngine()
        eng.finalize()
        # No posture issue → effective_level == level → LOW
        html = build_html_output(eng, _make_sys_info())
        assert "LOW" in html.upper()
        assert "HIGH" not in html.upper()

    def test_firewall_inactive_renders_effective_high(self):
        """The Ubuntu VM scenario: score 10 (LOW score-only) + UFW inactive
        → posture lifts to HIGH. HTML must reflect HIGH, not LOW."""
        from bob.scoring import ScoreEngine
        eng = ScoreEngine()
        eng.finalize()
        eng.set_posture(firewall_inactive=True)
        # Sanity: engine surfaces diverge as expected
        assert eng.level.value == "low"
        assert eng.effective_level.value == "high"
        # Output must reflect effective, not score-only
        html = build_html_output(eng, _make_sys_info())
        assert "HIGH" in html.upper()


# ---------------------------------------------------------------------------
# M-4 (v0.7.2): translation function ``t`` + ``lang`` routes through
# ---------------------------------------------------------------------------

class TestHtmlT18nExtraction:
    """M-4 (v0.7.2): user-facing strings + the <html lang="..."> attr go
    through the optional ``t`` translation function + ``lang`` kwarg."""

    def test_default_lang_is_en(self):
        """Backwards-compat: omitted lang kwarg produces ``<html lang="en">``."""
        from bob.scoring import ScoreEngine
        eng = ScoreEngine()
        eng.finalize()
        html = build_html_output(eng, _make_sys_info())
        assert '<html lang="en">' in html

    def test_custom_lang_is_emitted(self):
        from bob.scoring import ScoreEngine
        eng = ScoreEngine()
        eng.finalize()
        html = build_html_output(eng, _make_sys_info(), lang="fr")
        assert '<html lang="fr">' in html

    def test_custom_t_routes_through_to_output(self):
        from bob.scoring import ScoreEngine
        eng = ScoreEngine()
        eng.finalize()

        def fake_t(key, **kw):
            # Sentinel without HTML-unsafe chars so it survives _h() escaping
            # verbatim. Underscores + the (escaped) period in keys are both
            # passed through unchanged.
            return f"SENTINEL_{key.replace('.', '_DOT_')}"

        html = build_html_output(eng, _make_sys_info(), t=fake_t)
        assert "SENTINEL_html_output_DOT_field_score" in html
        assert "SENTINEL_html_output_DOT_field_host" in html
        assert "SENTINEL_html_output_DOT_report_title" in html

    def test_t_fallback_supplies_all_documented_keys(self):
        from bob.html_output import _FALLBACK_LABELS
        from bob.scoring import ScoreEngine
        eng = ScoreEngine()
        eng.finalize()
        html = build_html_output(eng, _make_sys_info())
        for key in _FALLBACK_LABELS:
            assert key not in html, (
                f"Translation key {key!r} surfaced in HTML output — "
                f"_FALLBACK_LABELS is incomplete or the fallback was not used."
            )
