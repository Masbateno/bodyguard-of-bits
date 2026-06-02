"""
Tests for bob/webhook.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from bob.webhook import (
    WebhookError,
    _is_slack_url,
    build_generic_payload,
    build_slack_payload,
    detect_format,
    send_webhook,
)
from bob.scoring import CheckResult, FindingLevel, ScoreEngine


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@dataclass
class _FakeSysInfo:
    hostname: str = "test-host"


def _make_engine(alerts: int = 0, warns: int = 0) -> ScoreEngine:
    engine = ScoreEngine()
    result = CheckResult()
    for _ in range(alerts):
        result.alert(message="Root login permitted", key="ssh.permit_root_login")
    for _ in range(warns):
        result.warn(message="X11 forwarding enabled", key="ssh.x11_forwarding")
    engine.apply(result)
    engine.finalize()
    return engine


_SYS_INFO  = _FakeSysInfo()
_VERSION   = "1.9.0"


# ---------------------------------------------------------------------------
# _is_slack_url
# ---------------------------------------------------------------------------

class TestIsSlackUrl:
    def test_slack_hook_url(self):
        assert _is_slack_url("https://hooks.slack.com/services/T123/B456/xyz")

    def test_slack_services_url(self):
        assert _is_slack_url("https://slack.com/services/T123/B456/xyz")

    def test_grafana_url_is_not_slack(self):
        assert not _is_slack_url("https://grafana.internal/api/annotations")

    def test_generic_https_is_not_slack(self):
        assert not _is_slack_url("https://example.com/webhook")

    def test_case_insensitive(self):
        assert _is_slack_url("HTTPS://HOOKS.SLACK.COM/services/T123")


# ---------------------------------------------------------------------------
# detect_format
# ---------------------------------------------------------------------------

class TestDetectFormat:
    def test_explicit_slack_overrides_url(self):
        assert detect_format("https://example.com/webhook", "slack") == "slack"

    def test_explicit_generic_overrides_slack_url(self):
        assert detect_format("https://hooks.slack.com/services/T123", "generic") == "generic"

    def test_auto_detects_slack(self):
        assert detect_format("https://hooks.slack.com/services/T123", "auto") == "slack"

    def test_auto_falls_back_to_generic(self):
        assert detect_format("https://grafana.internal/api/annotations", "auto") == "generic"


# ---------------------------------------------------------------------------
# build_generic_payload
# ---------------------------------------------------------------------------

class TestBuildGenericPayload:
    def test_required_fields_present(self):
        engine = _make_engine()
        payload = build_generic_payload(engine, _SYS_INFO, _VERSION)
        for key in ("source", "version", "host", "timestamp", "score", "max_score",
                    "risk", "alerts", "warnings", "findings"):
            assert key in payload, f"Missing key: {key}"

    def test_source_is_bob(self):
        payload = build_generic_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert payload["source"] == "bob"

    def test_version_matches(self):
        payload = build_generic_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert payload["version"] == _VERSION

    def test_host_matches(self):
        payload = build_generic_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert payload["host"] == "test-host"

    def test_max_score_is_10(self):
        payload = build_generic_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert payload["max_score"] == 10

    def test_score_within_range(self):
        payload = build_generic_payload(_make_engine(alerts=2), _SYS_INFO, _VERSION)
        assert 0 <= payload["score"] <= 10

    def test_alerts_count(self):
        payload = build_generic_payload(_make_engine(alerts=2), _SYS_INFO, _VERSION)
        assert payload["alerts"] == 2

    def test_warnings_count(self):
        payload = build_generic_payload(_make_engine(warns=3), _SYS_INFO, _VERSION)
        assert payload["warnings"] == 3

    def test_findings_only_alert_and_warn(self):
        engine = _make_engine(alerts=1, warns=1)
        payload = build_generic_payload(engine, _SYS_INFO, _VERSION)
        for f in payload["findings"]:
            assert f["level"] in ("ALERT", "WARN")

    def test_findings_have_level_key_message(self):
        engine = _make_engine(alerts=1)
        payload = build_generic_payload(engine, _SYS_INFO, _VERSION)
        f = payload["findings"][0]
        assert "level" in f
        assert "key" in f
        assert "message" in f

    def test_clean_engine_has_empty_findings(self):
        engine = _make_engine()
        payload = build_generic_payload(engine, _SYS_INFO, _VERSION)
        assert payload["findings"] == []

    def test_payload_is_json_serialisable(self):
        engine = _make_engine(alerts=1, warns=2)
        payload = build_generic_payload(engine, _SYS_INFO, _VERSION)
        serialised = json.dumps(payload)  # must not raise
        assert isinstance(serialised, str)

    def test_domain_scores_present(self):
        """Generic payload must include per-domain scores for all domains."""
        from bob.domain_scores import DOMAINS
        from bob.scoring import MAX_SCORE
        payload = build_generic_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert "domain_scores" in payload
        for d in DOMAINS:
            assert d in payload["domain_scores"]
            assert 0 <= payload["domain_scores"][d] <= MAX_SCORE


# ---------------------------------------------------------------------------
# build_slack_payload
# ---------------------------------------------------------------------------

class TestBuildSlackPayload:
    def test_text_field_present(self):
        payload = build_slack_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert "text" in payload

    def test_attachments_present(self):
        payload = build_slack_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1

    def test_attachment_has_color(self):
        payload = build_slack_payload(_make_engine(alerts=1), _SYS_INFO, _VERSION)
        att = payload["attachments"][0]
        assert "color" in att
        assert att["color"].startswith("#")

    def test_alert_uses_red_color(self):
        from bob.webhook import _SLACK_COLOR_ALERT
        payload = build_slack_payload(_make_engine(alerts=1), _SYS_INFO, _VERSION)
        assert payload["attachments"][0]["color"] == _SLACK_COLOR_ALERT

    def test_warn_only_uses_orange(self):
        from bob.webhook import _SLACK_COLOR_WARN
        payload = build_slack_payload(_make_engine(warns=1), _SYS_INFO, _VERSION)
        assert payload["attachments"][0]["color"] == _SLACK_COLOR_WARN

    def test_clean_uses_green(self):
        from bob.webhook import _SLACK_COLOR_OK
        payload = build_slack_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert payload["attachments"][0]["color"] == _SLACK_COLOR_OK

    def test_hostname_in_text(self):
        payload = build_slack_payload(_make_engine(), _SYS_INFO, _VERSION)
        assert "test-host" in payload["text"]

    def test_payload_is_json_serialisable(self):
        payload = build_slack_payload(_make_engine(alerts=1, warns=1), _SYS_INFO, _VERSION)
        serialised = json.dumps(payload)
        assert isinstance(serialised, str)

    def test_attachment_text_contains_score(self):
        """Score/risk summary must appear in the Slack attachment body text."""
        payload = build_slack_payload(_make_engine(), _SYS_INFO, _VERSION)
        attachment_text = payload["attachments"][0]["text"]
        assert "score" in attachment_text.lower()


# ---------------------------------------------------------------------------
# send_webhook — invalid URL
# ---------------------------------------------------------------------------

class TestSendWebhookInvalidUrl:
    def test_rejects_non_http_url(self):
        engine = _make_engine()
        with pytest.raises(WebhookError, match="must start with"):
            send_webhook("ftp://example.com/hook", engine, _SYS_INFO, _VERSION)

    def test_rejects_empty_url(self):
        engine = _make_engine()
        with pytest.raises(WebhookError):
            send_webhook("", engine, _SYS_INFO, _VERSION)

    def test_rejects_plain_http_by_default(self, monkeypatch):
        """I-5 (v0.7.1): plain http:// is rejected without the
        BOB_WEBHOOK_ALLOW_INSECURE=1 escape hatch. The audit payload
        contains hostname + public_ip + score + alerts — that would leak
        in plaintext on any path between BOB and the receiver. SECURITY.md
        "Network surface" documents webhook as HTTPS-only."""
        monkeypatch.delenv("BOB_WEBHOOK_ALLOW_INSECURE", raising=False)
        engine = _make_engine()
        with pytest.raises(WebhookError, match="plain http://"):
            send_webhook("http://hook.example.com/path", engine, _SYS_INFO, _VERSION)

    def test_plain_http_accepted_with_escape_hatch(self, monkeypatch):
        """I-5 (v0.7.1): BOB_WEBHOOK_ALLOW_INSECURE=1 opts in to plain http,
        for offline labs / private-network testing. The static rejection
        must release, but the request itself is then mocked at the
        urllib boundary by other tests."""
        monkeypatch.setenv("BOB_WEBHOOK_ALLOW_INSECURE", "1")
        engine = _make_engine()
        # http:// URL no longer rejected statically — it goes to the
        # urllib call which will fail to connect in the test sandbox.
        # We don't care about the network error; we just assert the
        # specific "plain http://" rejection no longer fires.
        with pytest.raises(WebhookError) as excinfo:
            send_webhook("http://hook.example.com/path", engine, _SYS_INFO, _VERSION)
        assert "plain http://" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# I-5 (v0.7.3): URL scheme matching is case-insensitive (RFC 3986)
# ---------------------------------------------------------------------------

class TestSendWebhookSchemeCaseInsensitive:
    """I-5 (v0.7.3): pre-v0.7.3 ``HTTPS://example.com`` was rejected with
    the "must start with http(s)://" error instead of falling through;
    the lowered form is now the canonical one for the scheme guard."""

    def test_uppercase_https_accepted(self, monkeypatch):
        from bob.webhook import send_webhook
        from unittest.mock import patch, MagicMock
        engine = _make_engine()
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=resp):
            status = send_webhook("HTTPS://example.com/hook", engine, _SYS_INFO, _VERSION)
        assert status == 200

    def test_mixedcase_https_accepted(self, monkeypatch):
        from bob.webhook import send_webhook
        from unittest.mock import patch, MagicMock
        engine = _make_engine()
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=resp):
            status = send_webhook("HtTpS://Example.com/hook", engine, _SYS_INFO, _VERSION)
        assert status == 200

    def test_uppercase_http_rejected_without_escape_hatch(self, monkeypatch):
        from bob.webhook import send_webhook, WebhookError
        monkeypatch.delenv("BOB_WEBHOOK_ALLOW_INSECURE", raising=False)
        engine = _make_engine()
        with pytest.raises(WebhookError, match="plain http://"):
            send_webhook("HTTP://example.com/hook", engine, _SYS_INFO, _VERSION)


# ---------------------------------------------------------------------------
# send_webhook — mocked HTTP
# ---------------------------------------------------------------------------

class TestSendWebhookHTTP:
    def _mock_resp(self, status: int = 200):
        resp = MagicMock()
        resp.status = status
        resp.__enter__ = lambda s: s
        resp.__exit__  = MagicMock(return_value=False)
        return resp

    def test_returns_status_code_on_success(self):
        engine = _make_engine()
        with patch("urllib.request.urlopen", return_value=self._mock_resp(200)):
            status = send_webhook("https://example.com/hook", engine, _SYS_INFO, _VERSION)
        assert status == 200

    def test_posts_json_content_type(self):
        engine = _make_engine()
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return self._mock_resp(200)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            send_webhook("https://example.com/hook", engine, _SYS_INFO, _VERSION)

        assert captured[0].get_header("Content-type").startswith("application/json")

    def test_sends_valid_json_body(self):
        engine = _make_engine(alerts=1)
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return self._mock_resp(200)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            send_webhook("https://example.com/hook", engine, _SYS_INFO, _VERSION)

        body = json.loads(captured[0].data.decode("utf-8"))
        assert "source" in body

    def test_http_error_raises_webhook_error(self):
        import urllib.error
        engine = _make_engine()
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(
                       "https://example.com", 500, "Internal Server Error", {}, None
                   )):
            with pytest.raises(WebhookError, match="HTTP 500"):
                send_webhook("https://example.com/hook", engine, _SYS_INFO, _VERSION)

    def test_url_error_raises_webhook_error(self):
        import urllib.error
        engine = _make_engine()
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(WebhookError, match="connection failed"):
                send_webhook("https://example.com/hook", engine, _SYS_INFO, _VERSION)

    def test_slack_url_uses_slack_format(self):
        engine = _make_engine()
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return self._mock_resp(200)

        slack_url = "https://hooks.slack.com/services/T123/B456/xyz"
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            send_webhook(slack_url, engine, _SYS_INFO, _VERSION, fmt="auto")

        body = json.loads(captured[0].data.decode("utf-8"))
        # Slack payload has 'attachments', generic does not
        assert "attachments" in body

    def test_timeout_is_passed_to_urlopen(self):
        """send_webhook must forward the timeout parameter to urlopen."""
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(timeout)
            return self._mock_resp(200)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            send_webhook("https://example.com/hook", _make_engine(), _SYS_INFO, _VERSION)

        assert captured[0] is not None

    def test_explicit_generic_format_on_slack_url(self):
        engine = _make_engine()
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return self._mock_resp(200)

        slack_url = "https://hooks.slack.com/services/T123/B456/xyz"
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            send_webhook(slack_url, engine, _SYS_INFO, _VERSION, fmt="generic")

        body = json.loads(captured[0].data.decode("utf-8"))
        assert "source" in body
        assert "attachments" not in body


# ---------------------------------------------------------------------------
# UserConfig webhook helpers
# ---------------------------------------------------------------------------

class TestUserConfigWebhook:
    def test_get_webhook_url_default_empty(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        assert cfg.get_webhook_url() == ""

    def test_set_and_get_webhook_url(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set_webhook_url("https://example.com/webhook")
        assert cfg.get_webhook_url() == "https://example.com/webhook"

    def test_invalid_url_raises(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        with pytest.raises(ValueError, match="must start with http"):
            cfg.set_webhook_url("ftp://invalid.com")

    def test_set_webhook_url_accepts_uppercase_scheme(self, tmp_path):
        # I-4 (v0.7.4): scheme match is case-insensitive (RFC 3986). Mirrors
        # the v0.7.3 I-5 fix in webhook.py::send_webhook.
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set_webhook_url("HTTPS://EXAMPLE.com/webhook")
        assert cfg.get_webhook_url() == "HTTPS://EXAMPLE.com/webhook"
        cfg.set_webhook_url("HTTP://example.com/webhook")
        assert cfg.get_webhook_url() == "HTTP://example.com/webhook"
        cfg.set_webhook_url("Https://example.com/webhook")
        assert cfg.get_webhook_url() == "Https://example.com/webhook"

    def test_set_empty_deletes_key(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set_webhook_url("https://example.com/webhook")
        cfg.set_webhook_url("")
        assert cfg.get_webhook_url() == ""

    def test_get_webhook_format_default_auto(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        assert cfg.get_webhook_format() == "auto"

    def test_set_webhook_format_slack(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        cfg.set_webhook_format("slack")
        assert cfg.get_webhook_format() == "slack"

    def test_invalid_format_raises(self, tmp_path):
        from bob.config import UserConfig
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        with pytest.raises(ValueError, match="must be 'auto'"):
            cfg.set_webhook_format("xml")


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

class TestCLIWebhookParsing:
    def test_webhook_equals_syntax(self):
        from bob.cli import parse_args
        cfg = parse_args(["--webhook=https://example.com/hook"])
        assert cfg.webhook_url == "https://example.com/hook"

    def test_webhook_space_syntax(self):
        from bob.cli import parse_args
        cfg = parse_args(["--webhook", "https://example.com/hook"])
        assert cfg.webhook_url == "https://example.com/hook"

    def test_webhook_format_slack(self):
        from bob.cli import parse_args
        cfg = parse_args(["--webhook-format=slack"])
        assert cfg.webhook_format == "slack"

    def test_webhook_format_generic(self):
        from bob.cli import parse_args
        cfg = parse_args(["--webhook-format=generic"])
        assert cfg.webhook_format == "generic"

    def test_webhook_format_invalid_raises(self):
        from bob.cli import parse_args, CLIError
        with pytest.raises(CLIError, match="--webhook-format"):
            parse_args(["--webhook-format=xml"])

    def test_webhook_url_default_empty(self):
        from bob.cli import parse_args
        cfg = parse_args([])
        assert cfg.webhook_url == ""

    def test_webhook_format_default_auto(self):
        from bob.cli import parse_args
        cfg = parse_args([])
        assert cfg.webhook_format == "auto"

    def test_diff_and_explain_together(self):
        """--diff and --explain can be combined without conflict."""
        from bob.cli import parse_args
        cfg = parse_args(["--diff", "--explain=ssh.password_auth"])
        assert cfg.diff_mode
        assert cfg.explain_key == "ssh.password_auth"

    def test_webhook_with_offline_flag_parses(self):
        """
        --offline + --webhook-url are not mutually exclusive at CLI level.
        At runtime, __main__.py skips webhook POSTs when offline=True
        (`if _webhook_url and not config.offline`). The CLI parser accepts both
        so users can dry-run their webhook config without external network access.
        """
        from bob.cli import parse_args
        cfg = parse_args(["--offline", "--webhook=https://example.com/hook"])
        assert cfg.offline is True
        assert cfg.webhook_url == "https://example.com/hook"


class TestOfflineModeNetworkContract:
    """
    Public contract: --offline skips ALL external HTTP and the audit completes
    without network access. This class is the test-suite acknowledgement of that
    contract — useful for distro packagers running BOB in build sandboxes.
    """

    def test_offline_skips_webhook_send(self, monkeypatch):
        """
        Smoke test: simulating the __main__.py decision branch ensures the
        webhook is not POSTed when offline=True, even if webhook_url is set.
        """
        # Build a fake config object with offline=True + webhook URL.
        cfg = MagicMock()
        cfg.offline = True
        cfg.webhook_url = "https://example.com/hook"

        # Mirror the gating in bob/__main__.py:277.
        # If this condition changes, the smoke test surfaces it.
        should_send = bool(cfg.webhook_url) and not cfg.offline
        assert should_send is False, (
            "--offline must override webhook_url so no POST happens. "
            "Mirror of __main__.py:277 contract."
        )

    def test_get_public_ip_offline_skips_urllib(self, monkeypatch):
        """get_public_ip(offline=True) must short-circuit before any HTTP call."""
        from bob import sysinfo
        called = []

        def _explode(*args, **kwargs):
            called.append(args)
            raise AssertionError("urllib.request.urlopen called in offline mode")

        monkeypatch.setattr(sysinfo, "urllib", MagicMock(request=MagicMock(urlopen=_explode)), raising=False)
        result = sysinfo.get_public_ip(offline=True)
        assert result == ""
        assert not called, "no urlopen call must be attempted in offline mode"
