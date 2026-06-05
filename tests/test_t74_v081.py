"""
T74 (v0.8.1) — webhook URL credential redaction regression pin.

Pre-T74 the operator's webhook URL was printed in cleartext on two paths:

  1. ``bob/__main__.py`` ``print_info(f"Webhook: POST → {url} [{status}]")``
     — terminal stdout + on-disk ``.log`` audit report.
  2. ``bob/webhook.py`` ``WebhookError(t("webhook.error.scheme_invalid",
     url=repr(url)))`` — terminal stderr on URL-validation failure.

URLs with embedded ``user:pass@`` credentials (a common pattern for
Slack / Discord / Mattermost / HMAC-signed custom endpoints) leaked the
credential through every channel above plus any monitoring pipe consuming
the audit output (cron + journalctl, log shippers, etc.).

v0.8.1 adds ``redact_url_credentials()`` in ``bob/webhook.py`` and wires
it at every display site so the original URL is still used for the actual
POST while the operator-facing form is sanitised to ``[REDACTED]@host``.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest


# ===========================================================================
# Helper: redact_url_credentials
# ===========================================================================

class TestRedactUrlCredentials:

    @pytest.mark.parametrize("url,expected", [
        # Basic Slack-style pattern
        ("https://user:secret@hooks.slack.com/services/T123",
         "https://[REDACTED]@hooks.slack.com/services/T123"),
        # Bare user (no password) still redacted
        ("https://just_user@host/path",
         "https://[REDACTED]@host/path"),
        # No credentials — pass-through
        ("https://hooks.slack.com/services/T123",
         "https://hooks.slack.com/services/T123"),
        # Plain http
        ("http://user:secret@host",
         "http://[REDACTED]@host"),
        # Non-canonical scheme
        ("ftp://u:p@h",
         "ftp://[REDACTED]@h"),
        # Empty string
        ("", ""),
        # Garbage input — must not crash
        ("not-a-url", "not-a-url"),
        # URL with port
        ("https://user:pass@host.example.com:8443/webhook",
         "https://[REDACTED]@host.example.com:8443/webhook"),
        # URL with query string that contains @ but no userinfo segment
        # (the regex anchors on ``://`` to ``@`` *before the first /*, so a
        # query-string ``@`` shouldn't be touched)
        ("https://host/path?token=foo@bar.com",
         "https://host/path?token=foo@bar.com"),
    ])
    def test_redaction_known_cases(self, url, expected):
        from bob.webhook import redact_url_credentials
        assert redact_url_credentials(url) == expected

    def test_redaction_does_not_leak_secret(self):
        from bob.webhook import redact_url_credentials
        url = "https://api_user:s3cr3t_t0k3n@hooks.slack.com/services/T123/B456/abc"
        out = redact_url_credentials(url)
        assert "s3cr3t_t0k3n" not in out
        assert "api_user" not in out
        # But host + path preserved
        assert "hooks.slack.com" in out
        assert "T123" in out

    def test_redaction_idempotent(self):
        """Redacting a redacted URL returns the same string — useful when
        the URL has already been sanitised by a caller."""
        from bob.webhook import redact_url_credentials
        once  = redact_url_credentials("https://user:pass@host/path")
        twice = redact_url_credentials(once)
        assert once == twice


# ===========================================================================
# Integration: WebhookError messages no longer leak credentials
# ===========================================================================

class TestWebhookErrorRedaction:

    def setup_method(self):
        os.environ.pop("BOB_WEBHOOK_ALLOW_INSECURE", None)

    def test_scheme_invalid_redacts(self):
        from bob.webhook import send_webhook, WebhookError
        url = "ftp://user:supersecret@host.example.com/webhook"
        with pytest.raises(WebhookError) as exc_info:
            send_webhook(url, MagicMock(), MagicMock(), "0.8.1")
        msg = str(exc_info.value)
        assert "supersecret" not in msg, \
            "WebhookError leaked the password through the scheme-invalid path"
        assert "[REDACTED]" in msg

    def test_plain_http_insecure_redacts(self):
        from bob.webhook import send_webhook, WebhookError
        url = "http://api_user:s3cr3t@hooks.example.com/path"
        with pytest.raises(WebhookError) as exc_info:
            send_webhook(url, MagicMock(), MagicMock(), "0.8.1")
        msg = str(exc_info.value)
        assert "s3cr3t" not in msg, \
            "WebhookError leaked the password through the plain-http path"
        assert "api_user" not in msg
        assert "[REDACTED]" in msg

    def test_clean_url_unchanged_in_error(self):
        """URLs without embedded credentials must NOT have anything
        replaced — the host/path part is what the operator needs to
        diagnose the issue."""
        from bob.webhook import send_webhook, WebhookError
        url = "ftp://hooks.example.com/path"
        with pytest.raises(WebhookError) as exc_info:
            send_webhook(url, MagicMock(), MagicMock(), "0.8.1")
        msg = str(exc_info.value)
        assert "hooks.example.com" in msg
        # No spurious "[REDACTED]" injection when there's nothing to redact
        assert "[REDACTED]" not in msg


# ===========================================================================
# Integration: success-path stdout/log no longer leaks credentials
# ===========================================================================

class TestSuccessPathRedaction:
    """The success-path display is in ``bob/__main__.py``; we can't easily
    invoke the full audit pipeline in a unit test, but we CAN pin the
    invariant that ``redact_url_credentials`` is imported and called at the
    expected site."""

    def test_main_py_imports_and_uses_redact_helper(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "from bob.webhook import" in src and "redact_url_credentials" in src, (
            "bob/__main__.py must import redact_url_credentials so the "
            "Webhook: POST → URL line doesn't leak credentials to stdout/log."
        )
        # The display URL must use the redact helper
        assert "redact_url_credentials(_webhook_url)" in src, (
            "bob/__main__.py must call redact_url_credentials on the webhook "
            "URL before passing it to output.print_info — the line is what "
            "leaks credentials to stdout and the on-disk .log report."
        )
