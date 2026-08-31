"""
v0.15.0 — the Markdown report rendered whatever the audited host put in a name.

Finding messages carry system-derived values: process names, cron commands,
file paths, service and jail names. `_md_escape` escaped `|` so the table would
not break, and stopped there. A Markdown cell renders inline HTML, links and
images, so anything else went through intact:

    <img src=x onerror=alert(1)>      executes in any renderer that passes HTML
    [click](javascript:alert(1))      renders as a live link
    ![x](https://evil.invalid/t.png)  fetches a remote image when the report is
                                      opened — the auditor's own machine calling
                                      out because of a string on the audited one

The HTML writer escaped all of this from the start (`html.escape`, `quote=True`),
and `report_markdown.py` — the `-d` detailed report — was hardened in v0.7.3 with
a documented `_safe_url`. `markdown_output.py` was the third writer and the only
one left. The same invariant, honoured in two output formats out of three.

The `cmd` field is deliberately *not* entity-escaped: it is rendered inside a
code span, where Markdown treats content literally, and `&lt;` there would show
the operator five characters instead of a `<` in a command they are meant to
copy. What a code span needs instead is a fence longer than the longest backtick
run inside it, which is what `_md_code` does.
"""

from __future__ import annotations

import re

import pytest

from bob import i18n
from bob.cli import parse_args
from bob.markdown_output import _md_code, _md_escape, build_markdown_output
from bob.profiles import load_profile
from bob.scoring import Finding, FindingLevel, ScoreEngine
from bob.sysinfo import collect_system_info


class TestEscapingProse:
    @pytest.mark.parametrize("raw,forbidden", [
        ("<script>alert(1)</script>", "<script>"),
        ("<img src=x onerror=alert(1)>", "<img"),
        ("<iframe src=//evil>", "<iframe"),
    ])
    def test_inline_html_is_neutralised(self, raw, forbidden):
        assert forbidden not in _md_escape(raw)
        assert "&lt;" in _md_escape(raw)

    def test_a_link_is_not_rendered(self):
        out = _md_escape("[click](javascript:alert(1))")
        assert "\\[click\\]" in out

    def test_an_image_is_not_rendered(self):
        """An image is a link with a `!` in front, so escaping `[` covers both —
        and this is the one that reaches out to the network on open."""
        out = _md_escape("![x](https://evil.invalid/t.png)")
        assert "\\[x\\]" in out

    def test_the_pipe_escape_still_works(self):
        assert _md_escape("a | b") == "a \\| b"

    def test_newlines_still_collapse(self):
        assert "\n" not in _md_escape("a\nb")

    def test_ordinary_text_is_untouched(self):
        assert _md_escape("plain text 42") == "plain text 42"


class TestCodeSpans:
    def test_a_plain_command_gets_single_backticks(self):
        assert _md_code("systemctl status ssh") == "`systemctl status ssh`"

    def test_a_command_containing_backticks_gets_a_longer_fence(self):
        out = _md_code("echo `date`")
        assert out.startswith("`` ") and out.endswith(" ``")
        assert "echo `date`" in out

    @pytest.mark.parametrize("raw", ["`start", "end`", "`both`"])
    def test_leading_or_trailing_backticks_are_padded(self, raw):
        out = _md_code(raw)
        assert out.startswith("`` ") and out.endswith(" ``")

    def test_a_command_is_not_entity_escaped(self):
        """`&lt;` inside a code span displays as five characters, corrupting a
        command the operator is meant to copy."""
        assert "&lt;" not in _md_code("grep <pattern> file")

    def test_a_pipe_is_still_escaped_inside_a_cell(self):
        assert "\\|" in _md_code("ps aux | grep sshd")


class TestEndToEnd:
    _HOSTILE = ('<script>alert(1)</script> [c](javascript:alert(3)) '
                '![i](https://evil.invalid/t.png)')

    def _render(self, **kw):
        i18n.init("en")
        eng = ScoreEngine()
        eng.findings.append(Finding(level=FindingLevel.WARN, key="ssh.x", **kw))
        return build_markdown_output(
            eng, collect_system_info("0.0.0-test", "en"), i18n.t,
            load_profile("server"), parse_args(["--offline"]))

    def _prose_cells(self, out: str) -> str:
        """Everything outside code spans — where rendering actually happens."""
        return re.sub(r"`+[^`]*`+", "", out)

    @pytest.mark.parametrize("field", ["message", "detail", "note"])
    def test_no_field_reaches_the_report_renderable(self, field):
        out = self._prose_cells(self._render(**{"message": "x", field: self._HOSTILE}))
        assert "<script>" not in out
        assert "<img" not in out
        assert not re.search(r"(?<!\\)\[c\]\(javascript", out)
        assert not re.search(r"!(?<!\\)\[i\]\(https", out)

    def test_the_command_is_preserved_verbatim_in_its_code_span(self):
        out = self._render(message="x", cmd="grep <pattern> /etc/passwd")
        assert "grep <pattern> /etc/passwd" in out
        assert "&lt;pattern&gt;" not in out

    def test_the_table_still_has_its_own_line_breaks(self):
        """`<br>` is emitted by the writer itself, outside the escaper."""
        out = self._render(message="m", detail="d")
        assert "<br>" in out
