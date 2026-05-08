"""
Webhook notification module for BOB.

Sends a POST request carrying the audit result as JSON after a completed audit.
Supports two payload formats:

  generic  — structured JSON for Grafana, custom endpoints, or any HTTP receiver
  slack    — Slack Incoming Webhook format (attachment with colour coding)
  auto     — detects Slack by URL; falls back to generic (default)

Webhook failures are non-fatal: a warning is printed to stderr but the audit
exit code is not affected.

Usage:
    from bob.webhook import send_webhook

    try:
        send_webhook(url, engine, sys_info, version=VERSION)
    except WebhookError as exc:
        print(f"Webhook failed: {exc}", file=sys.stderr)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bob.scoring import ScoreEngine
    from bob.sysinfo import SystemInfo

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMEOUT_SECONDS = 10

# ALERT → red, WARN → orange, clean → green
_SLACK_COLOR_ALERT = "#d00000"
_SLACK_COLOR_WARN  = "#ff8800"
_SLACK_COLOR_OK    = "#36a64f"

# Slack attachment text is capped at 3000 chars; leave margin for other fields
_SLACK_FINDINGS_MAX = 2500


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class WebhookError(RuntimeError):
    """Raised when the HTTP POST fails or returns a non-2xx status."""


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _is_slack_url(url: str) -> bool:
    """Return True if the URL looks like a Slack Incoming Webhook endpoint."""
    lower = url.lower()
    return "hooks.slack.com" in lower or ("slack.com" in lower and "/services/t" in lower)


def detect_format(url: str, requested: str) -> str:
    """
    Return the effective format string ('generic' or 'slack').

    Args:
        url:       The webhook URL.
        requested: Value of --webhook-format ('auto', 'generic', 'slack').
    """
    if requested in ("generic", "slack"):
        return requested
    # auto
    return "slack" if _is_slack_url(url) else "generic"


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def build_generic_payload(engine: "ScoreEngine", sys_info: "SystemInfo",
                          version: str) -> dict:
    """
    Build a generic JSON payload suitable for Grafana annotations,
    custom HTTP receivers, and automation pipelines.
    """
    from bob.scoring import FindingLevel

    from bob.domain_scores import compute_domain_scores, DOMAINS
    _ds, _ = compute_domain_scores(engine)

    return {
        "source":    "bob",
        "version":   version,
        "host":      sys_info.hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score":     engine.score,
        "max_score": 10,
        "risk":      engine.level.value,
        "alerts":    engine.alert_count,
        "warnings":  engine.warn_count,
        "domain_scores": {
            domain: _ds[domain]["score"] for domain in DOMAINS
        },
        "findings": [
            {
                "level":   f.level.name,
                "key":     f.key,
                "message": f.message,
            }
            for f in engine.findings
            if f.level in (FindingLevel.ALERT, FindingLevel.WARN)
        ],
    }


def build_slack_payload(engine: "ScoreEngine", sys_info: "SystemInfo",
                        version: str) -> dict:
    """
    Build a Slack Incoming Webhook payload with colour-coded attachment.
    """
    from bob.scoring import FindingLevel

    score_display = f"{engine.score}/10"

    if engine.alert_count > 0:
        color = _SLACK_COLOR_ALERT
    elif engine.warn_count > 0:
        color = _SLACK_COLOR_WARN
    else:
        color = _SLACK_COLOR_OK

    summary = (
        f"*BOB* v{version} — `{sys_info.hostname}`\n"
        f"Score: *{score_display}* | "
        f"Risk: *{engine.level.value.upper()}* | "
        f"{engine.alert_count} alert(s), {engine.warn_count} warning(s)"
    )

    finding_lines = [
        ("🚨 " if f.level == FindingLevel.ALERT else "⚠️  ") + f.message
        for f in engine.findings
        if f.level in (FindingLevel.ALERT, FindingLevel.WARN)
    ]
    findings_text = "\n".join(finding_lines)
    if len(findings_text) > _SLACK_FINDINGS_MAX:
        findings_text = findings_text[:_SLACK_FINDINGS_MAX] + "\n…"

    fields = []
    if findings_text:
        fields.append({"title": "Findings", "value": findings_text, "short": False})

    return {
        "text": f"BOB report — {sys_info.hostname}",
        "attachments": [
            {
                "color":  color,
                "text":   summary,
                "fields": fields,
            }
        ],
    }


# ---------------------------------------------------------------------------
# HTTP sender
# ---------------------------------------------------------------------------

def send_webhook(
    url:      str,
    engine:   "ScoreEngine",
    sys_info: "SystemInfo",
    version:  str,
    fmt:      str = "auto",
    timeout:  int = _TIMEOUT_SECONDS,
) -> int:
    """
    POST the audit result as JSON to *url*.

    Args:
        url:     Destination webhook URL (must start with http or https).
        engine:  Finalised ScoreEngine with audit results.
        sys_info: System information object (provides hostname).
        version: BOB version string.
        fmt:     Payload format: 'auto' (default), 'generic', or 'slack'.
        timeout: HTTP request timeout in seconds.

    Returns:
        HTTP status code returned by the server.

    Raises:
        WebhookError: If the URL is invalid, the connection fails, or the
                      server returns a non-2xx status code.
    """
    if not url.startswith(("http://", "https://")):
        raise WebhookError(f"Webhook URL must start with http:// or https://: {url!r}")

    effective_fmt = detect_format(url, fmt)
    if effective_fmt == "slack":
        payload = build_slack_payload(engine, sys_info, version)
    else:
        payload = build_generic_payload(engine, sys_info, version)

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status: int = resp.status
    except urllib.error.HTTPError as exc:
        raise WebhookError(f"HTTP {exc.code} from webhook: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise WebhookError(f"Webhook connection failed: {exc.reason}") from exc
    except OSError as exc:
        raise WebhookError(f"Webhook request error: {exc}") from exc

    if not (200 <= status < 300):
        raise WebhookError(f"Webhook returned non-2xx status: {status}")

    return status
