"""Tests for bob/report_markdown.py XSS / HTML-safety helpers.

The full markdown→HTML pipeline is exercised end-to-end by integration
tests; this module pins the security primitives in isolation so a
regression is caught at PR time.
"""
from __future__ import annotations

from bob.report_markdown import _safe_url, _inline_format


class TestSafeUrl:
    """v0.5.5 I-3 regression: _safe_url must re-escape attribute context."""

    def test_http_url_passes_through(self):
        assert _safe_url("http://example.com/foo") == "http://example.com/foo"

    def test_https_url_passes_through(self):
        assert _safe_url("https://example.com/foo") == "https://example.com/foo"

    def test_unknown_scheme_replaced(self):
        assert _safe_url("javascript:alert(1)") == "#"
        assert _safe_url("data:text/html,<script>") == "#"
        assert _safe_url("file:///etc/passwd") == "#"
        assert _safe_url("") == "#"

    def test_double_quote_in_url_is_escaped(self):
        """A URL containing `"` would break out of href="..." in HTML.
        After html.escape(quote=True), `"` becomes `&quot;`.
        """
        url = 'https://x.com" onclick="alert(1)'
        out = _safe_url(url)
        assert '"' not in out, "raw double quote leaked into attribute context"
        assert "&quot;" in out

    def test_single_quote_in_url_is_escaped(self):
        url = "https://x.com' onclick='alert(1)"
        out = _safe_url(url)
        assert "'" not in out
        assert "&#x27;" in out

    def test_angle_brackets_in_url_are_escaped(self):
        url = "https://x.com/<script>"
        out = _safe_url(url)
        assert "<" not in out
        assert "&lt;" in out


class TestInlineFormat:
    """End-to-end inline format on user-controlled text."""

    def test_plain_text_html_escaped(self):
        assert _inline_format("hello <world>") == "hello &lt;world&gt;"

    def test_link_renders_anchor(self):
        out = _inline_format("[BOB](https://example.com)")
        assert '<a href="https://example.com">BOB</a>' == out

    def test_crafted_link_double_quote_attack(self):
        """Full pipeline regression for I-3.

        Source contains a crafted markdown link with a `"` inside the URL
        that would try to escape the href attribute. After the I-3 fix,
        `_safe_url` re-escapes the URL with quote=True, double-encoding
        any pre-escaped `&quot;` to `&amp;quot;`. Browsers decode once
        when rendering attribute values, so the final href value is the
        text `&quot;` (a broken URL) — no attribute-breakout.
        """
        out = _inline_format('[label](https://x.com" onclick="alert(1))')
        # Anchor tag must have exactly one href attribute opening (no
        # injected attribute mid-tag).
        assert out.count("<a ") == 1
        # The opening `<a href="` is followed by exactly one closing `">`
        # for the URL — no second `"` slipping in to break out.
        assert out.startswith('<a href="')
        href_open = out.index('<a href="') + len('<a href="')
        href_close = out.index('">', href_open)
        href_value = out[href_open:href_close]
        # Inside the href, there must be no raw `"` (otherwise the
        # attribute closes early); we asserted href_close exists but
        # check no stray `"` was emitted within href_value itself.
        assert '"' not in href_value
