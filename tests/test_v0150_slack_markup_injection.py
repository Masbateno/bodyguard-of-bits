"""
v0.15.0 — a string on the audited host could ping a whole Slack workspace.

Finding messages carry system-derived values, and `build_slack_payload` sent
them verbatim. Slack's mrkdwn parser reserves three characters and interprets
two constructs that matter here:

    <!channel>                              notifies everyone in the channel
    <http://elsewhere|looks legitimate>     a link whose visible text is under
                                            the same control as its destination

So a process name, a cron command or a service name on the audited machine
reached the security channel with control over what it rendered as. Slack's own
formatting rules require `&`, `<` and `>` to be sent escaped; BOB did not.

Same family as the Markdown report fixed alongside it: content from the audited
host arriving somewhere that renders markup. The generic (non-Slack) payload
needs no equivalent — it is consumed as JSON, not as markup — and was verified
to serialise cleanly with the hostname it is documented to carry.
"""

from __future__ import annotations

import json

import pytest

from bob import i18n
from bob.scoring import Finding, FindingLevel, ScoreEngine
from bob.sysinfo import collect_system_info
from bob.webhook import _slack_escape, build_generic_payload, build_slack_payload


def _payload_text(**finding_kw) -> str:
    i18n.init("en")
    eng = ScoreEngine()
    eng.findings.append(Finding(level=FindingLevel.ALERT, key="ssh.root_login",
                                **finding_kw))
    return json.dumps(build_slack_payload(
        eng, collect_system_info("0.0.0-test", "en"), "0.0.0-test"))


class TestSlackEscape:
    @pytest.mark.parametrize("raw,expected", [
        ("a & b", "a &amp; b"),
        ("<tag>", "&lt;tag&gt;"),
        ("<!channel>", "&lt;!channel&gt;"),
        ("<http://x|y>", "&lt;http://x|y&gt;"),
        ("plain text", "plain text"),
        ("", ""),
    ])
    def test_the_three_reserved_characters(self, raw, expected):
        assert _slack_escape(raw) == expected

    def test_ampersand_is_escaped_first(self):
        """Otherwise the `&` introduced by escaping `<` would be escaped again
        and the reader would see `&amp;lt;`."""
        assert _slack_escape("<") == "&lt;"
        assert "&amp;lt;" not in _slack_escape("<")


class TestNothingRenderableReachesSlack:
    @pytest.mark.parametrize("field", ["message", "detail"])
    @pytest.mark.parametrize("payload", ["<!channel>", "<!here>", "<!everyone>",
                                         "<http://evil.invalid|click here>"])
    def test_a_finding_cannot_carry_slack_markup(self, field, payload):
        kw = {"message": "benign"}
        kw[field] = payload
        out = _payload_text(**kw)
        assert payload not in out
        assert "&lt;" in out

    def test_the_hostname_is_escaped_too(self, monkeypatch):
        """It appears in both the fallback text and the summary line."""
        assert _slack_escape("<!channel>.local") == "&lt;!channel&gt;.local"


class TestWhatMustSurvive:
    def test_bobs_own_markup_is_untouched(self):
        """The summary's `*bold*` and backticks are added outside the escaper."""
        out = _payload_text(message="benign")
        assert "*BOB*" in out
        assert "Score: *" in out

    def test_an_ordinary_finding_reads_normally(self):
        out = _payload_text(message="SSH root login permitted")
        assert "SSH root login permitted" in out

    def test_the_alert_prefix_is_still_there(self):
        assert "\\ud83d\\udea8" in _payload_text(message="x") or "🚨" in _payload_text(message="x")


class TestGenericPayload:
    def test_it_serialises_and_carries_the_documented_fields(self):
        i18n.init("en")
        eng = ScoreEngine()
        eng.findings.append(Finding(level=FindingLevel.ALERT, message="m",
                                    key="ssh.root_login"))
        p = build_generic_payload(eng, collect_system_info("0.0.0-test", "en"),
                                  "0.0.0-test", profile="server",
                                  degraded_sections=())
        assert json.loads(json.dumps(p)) == p
        for key in ("source", "version", "host", "score", "risk", "findings",
                    "profile", "degraded_sections"):
            assert key in p

    def test_it_is_not_markup_escaped(self):
        """It is consumed as JSON, so escaping would corrupt the values."""
        i18n.init("en")
        eng = ScoreEngine()
        eng.findings.append(Finding(level=FindingLevel.ALERT, message="a & b",
                                    key="ssh.root_login"))
        p = build_generic_payload(eng, collect_system_info("0.0.0-test", "en"),
                                  "0.0.0-test")
        assert "&amp;" not in json.dumps(p)
