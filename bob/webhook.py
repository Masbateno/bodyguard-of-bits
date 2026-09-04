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
import os
import re
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

# T74 (v0.8.1): regex that captures the ``user[:pass]@`` segment of an
# absolute URL. Used by ``redact_url_credentials`` to scrub embedded
# credentials before the URL is printed to stdout / written to the on-disk
# log report / surfaced inside a WebhookError message. Anchored on the
# ``://`` boundary so query-string values containing ``@`` (e.g. an email
# in a token=foo@bar.com fragment) are NOT touched.
_URL_USERINFO_RE = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)[^/@]+@")

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
# URL credential redaction (T74 v0.8.1)
# ---------------------------------------------------------------------------

def redact_url_credentials(url: str) -> str:
    """Replace ``user:pass@`` credentials in *url* with ``[REDACTED]@``.

    Used to scrub embedded credentials before the URL is printed to stdout
    (operator terminal), written to the on-disk ``.log`` audit report,
    surfaced inside a ``WebhookError`` message, piped to a monitoring
    pipeline, or recorded in cron's ``journalctl`` trail. The original URL
    is still used for the actual HTTPS POST — only the displayed form is
    sanitised, so authentication still works.

    Pre-T74 (v0.8.1), an operator who stored a webhook with embedded
    credentials (a common pattern for Slack / Discord / Mattermost /
    custom HMAC-signed endpoints) leaked the credential in cleartext on
    every successful POST line and on every URL-validation error message.

    Examples:
        ``https://user:secret@hooks.slack.com/services/T123``
                                → ``https://[REDACTED]@hooks.slack.com/services/T123``
        ``https://hooks.slack.com/services/T123``  (no credentials)
                                → ``https://hooks.slack.com/services/T123``
        ``not-a-url``                → ``not-a-url`` (no change)
    """
    return _URL_USERINFO_RE.sub(r"\g<scheme>[REDACTED]@", url, count=1)


# ---------------------------------------------------------------------------
# T10 (v0.8.1): i18n fallback for exception messages
#
# Mirrors the v0.7.2 M-4 pattern used in ``markdown_output.py`` /
# ``html_output.py`` — an optional ``t`` callable can be threaded into
# ``send_webhook``; when absent, ``_fallback_t`` substitutes the English
# strings below so legacy callers (CLI tests, ad-hoc scripts) keep working
# without an i18n wiring. The production caller in ``bob/__main__.py``
# passes the audit's bound ``t`` so the WebhookError messages match the
# locale chosen by the operator.
# ---------------------------------------------------------------------------

_FALLBACK_LABELS = {
    "webhook.error.scheme_invalid":
        "Webhook URL must start with https:// (or http:// with BOB_WEBHOOK_ALLOW_INSECURE=1): {url}",
    "webhook.error.plain_http_insecure":
        "Webhook URL is plain http:// — audit payload would be sent unencrypted. "
        "Use https:// or set BOB_WEBHOOK_ALLOW_INSECURE=1 to override: {url}",
    "webhook.error.http_status":      "HTTP {code} from webhook: {reason}",
    "webhook.error.connection_failed": "Webhook connection failed: {reason}",
    "webhook.error.request_error":     "Webhook request error: {exc}",
    "webhook.error.non_2xx_status":    "Webhook returned non-2xx status: {status}",
}


# v0.8.2: hand-rolled ``_fallback_t`` body replaced by the shared factory
# in ``bob._i18n_safe``. Behaviour preserved verbatim — same format-or-
# return-template-on-error semantics, same kwarg contract.
from bob._i18n_safe import make_fallback_t
_fallback_t = make_fallback_t(_FALLBACK_LABELS)


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
                          version: str, *,
                          profile: str = "server",
                          degraded_sections: "tuple[str, ...] | list[str]" = ()) -> dict:
    """
    Build a generic JSON payload suitable for Grafana annotations,
    custom HTTP receivers, and automation pipelines.

    v0.14.1 adds ``profile`` and ``degraded_sections``, closing the same
    format-parity gap T27 (v0.8.1) closed for ``detail``/``note``. The webhook
    is the sink built for machines — nobody reads a terminal in a monitoring
    stack — so it is precisely where "this audit was incomplete" and "these
    numbers came from the desktop profile" have to be legible. Without them a
    receiver seeing ``score: 9, alerts: 0`` cannot tell a clean host from one
    where two sections never ran, nor compare two hosts audited under
    different profiles. Additive keys: existing receivers are unaffected.
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
        # Additive, like the JSON sink: a monitoring rule on `score` keeps
        # working, and this says whether the number is a measurement or a
        # ceiling.
        "score_is_upper_bound": engine.score_is_upper_bound,
        "score_low":  engine.score_span[0],       # v0.16.2, additive
        "score_high": engine.score_span[1],
        "unscored_domains": sorted(getattr(engine, "blinded_domains", []) or []),
        "unverified": sorted(engine.unverified),
        "max_score": 10,
        "risk":      engine.effective_level.value,
        "alerts":    engine.alert_count,
        "warnings":  engine.warn_count,
        "profile":   profile or "server",
        "degraded_sections": list(degraded_sections),
        "domain_scores": {
            domain: _ds[domain]["score"] for domain in DOMAINS
        },
        "findings": [
            {
                "level":   f.level.name,
                "key":     f.key,
                "message": f.message,
                # Additive, same reason as the JSON sink: a monitoring stack
                # alerting on keys must be able to see that the audit qualified
                # one of them.
                "qualified_by": list(f.qualified_by),
                # T27 (v0.8.1): close the format-parity pattern around
                # ``Finding.detail`` + ``Finding.note``. v0.8.0 T9 closed
                # Markdown + HTML; v0.8.1 T11 closed CSV + JSON v1/v2;
                # this entry closes the last sink — the webhook payload
                # consumed by monitoring stacks (Grafana, Loki, custom
                # endpoints). Empty strings ride through cleanly for
                # findings without secondary context.
                "detail":  f.detail or "",
                "note":    f.note   or "",
            }
            for f in engine.findings
            if f.level in (FindingLevel.ALERT, FindingLevel.WARN)
        ],
    }


def _slack_escape(text: str) -> str:
    """Escape the three characters Slack's mrkdwn parser reserves.

    Slack's own formatting rules require ``&``, ``<`` and ``>`` to be sent as
    ``&amp;``, ``&lt;`` and ``&gt;`` in message text. Until v0.15.0 finding
    messages went out verbatim, and they carry system-derived values — process
    names, cron commands, service names. Two constructs mattered:

    * ``<!channel>`` (also ``<!here>``, ``<!everyone>``) notifies everyone in
      the channel, so a string on the audited host could ping a whole
      workspace from the security report.
    * ``<http://elsewhere|looks legitimate>`` renders as a link whose visible
      text is under the same control as its destination.

    BOB's own markup — the ``*bold*`` and backticks in the summary line — is
    added by the builder outside this function and is unaffected.

    ``&`` is escaped first, or the ampersands introduced by the other two
    substitutions would be escaped in turn.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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
        f"*BOB* v{_slack_escape(version)} — `{_slack_escape(sys_info.hostname)}`\n"
        f"Score: *{score_display}* | "
        f"Risk: *{engine.effective_level.value.upper()}* | "
        f"{engine.alert_count} alert(s), {engine.warn_count} warning(s)"
    )

    # T27 (v0.8.1): include Finding.detail inline so Slack readers see the
    # full context, not just the headline. The detail is concatenated on the
    # same line with a separator so the existing _SLACK_FINDINGS_MAX
    # truncation logic still works. Findings without a detail render
    # unchanged (no trailing separator).
    finding_lines = []
    for f in engine.findings:
        if f.level not in (FindingLevel.ALERT, FindingLevel.WARN):
            continue
        prefix = "🚨 " if f.level == FindingLevel.ALERT else "⚠️  "
        line   = prefix + _slack_escape(f.message)
        if f.detail:
            line += f" — {_slack_escape(f.detail)}"
        finding_lines.append(line)
    findings_text = "\n".join(finding_lines)
    if len(findings_text) > _SLACK_FINDINGS_MAX:
        findings_text = findings_text[:_SLACK_FINDINGS_MAX] + "\n…"

    fields = []
    if findings_text:
        fields.append({"title": "Findings", "value": findings_text, "short": False})

    return {
        "text": f"BOB report — {_slack_escape(sys_info.hostname)}",
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
    t=None,
    profile:  str = "server",
    degraded_sections: "tuple[str, ...] | list[str]" = (),
) -> int:
    """
    POST the audit result as JSON to *url*.

    Args:
        url:     Destination webhook URL (must start with http or https).
        engine:  Finalised ScoreEngine with audit results.
        sys_info: System information object (provides hostname).
        version: BOB version string.
        fmt:     Payload format: 'auto' (default), 'generic', or 'slack'.
        profile: Active audit profile name — v0.14.1, generic payload only.
        degraded_sections: Sections degraded by the runner's fault barrier —
                 v0.14.1, generic payload only. Lets a monitoring stack tell a
                 clean audit from an incomplete one.
        timeout: HTTP request timeout in seconds.
        t:       Optional translation function ``t(key, **kwargs) -> str``
                 used to format WebhookError messages. When ``None`` (legacy
                 callers / tests), an English fallback dict is used.

    Returns:
        HTTP status code returned by the server.

    Raises:
        WebhookError: If the URL is invalid, the connection fails, or the
                      server returns a non-2xx status code.
    """
    if t is None:
        t = _fallback_t
    # I-5 (v0.7.1): reject plain http:// by default — the BOB payload contains
    # hostname + public_ip + score + alerts which leaks audit posture in
    # plaintext over the network. SECURITY.md "Network surface" documents
    # webhook as HTTPS-only. The escape hatch ``BOB_WEBHOOK_ALLOW_INSECURE=1``
    # is for offline labs / private network testing only.
    # I-5 (v0.7.3): URL scheme matching is now case-insensitive (RFC 3986).
    # Pre-v0.7.3 ``HTTPS://example.com`` was rejected with the bogus "must
    # start with http(s)://" error instead of falling through; the lowered
    # form is what gets normalised below.
    url_lower = url.lower()
    # T74 (v0.8.1): scrub any embedded ``user:pass@`` segment before the URL
    # appears in the exception message. The original (unredacted) URL is
    # still used for the HTTPS POST below — only the operator-facing form
    # is sanitised. ``repr()`` wraps the redacted URL in quotes so it stays
    # visually distinguishable from surrounding prose.
    _safe_url = repr(redact_url_credentials(url))
    if not url_lower.startswith(("http://", "https://")):
        raise WebhookError(t("webhook.error.scheme_invalid", url=_safe_url))
    if url_lower.startswith("http://") and os.environ.get("BOB_WEBHOOK_ALLOW_INSECURE") != "1":
        raise WebhookError(t("webhook.error.plain_http_insecure", url=_safe_url))

    effective_fmt = detect_format(url, fmt)
    if effective_fmt == "slack":
        payload = build_slack_payload(engine, sys_info, version)
    else:
        payload = build_generic_payload(
            engine, sys_info, version,
            profile=profile, degraded_sections=degraded_sections)

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
        raise WebhookError(t("webhook.error.http_status", code=exc.code, reason=exc.reason)) from exc
    except urllib.error.URLError as exc:
        raise WebhookError(t("webhook.error.connection_failed", reason=exc.reason)) from exc
    except OSError as exc:
        raise WebhookError(t("webhook.error.request_error", exc=exc)) from exc

    if not (200 <= status < 300):
        raise WebhookError(t("webhook.error.non_2xx_status", status=status))

    return status


def test_webhook(url: str, fmt: str = "auto", timeout: int = _TIMEOUT_SECONDS,
                 t=None) -> int:
    """v0.8.2 — POST a minimal smoke payload to *url* and return the HTTP status.

    Reuses every URL-validation guard from :func:`send_webhook` (scheme + the
    plain-http guard + ``BOB_WEBHOOK_ALLOW_INSECURE`` escape hatch) and goes
    through the same urllib request path, so a passing smoke test proves the
    real audit-time POST will reach the receiver. The payload is deliberately
    tiny + clearly tagged as a smoke message so receivers can filter or
    suppress it.

    Used by ``bob --test-webhook`` to validate a fresh webhook configuration
    without running a full audit (which is ~30s + needs sudo).

    Args:
        url:     Destination webhook URL.
        fmt:     Payload format hint (mirrors ``send_webhook(fmt=)``).
        timeout: HTTP request timeout in seconds.
        t:       Optional translation function.

    Returns:
        HTTP status code returned by the server (200..299 on success).

    Raises:
        WebhookError: same conditions as :func:`send_webhook` (scheme invalid,
                      plain http without escape hatch, connection failure,
                      non-2xx response).
    """
    if t is None:
        t = _fallback_t
    url_lower = url.lower()
    _safe_url = repr(redact_url_credentials(url))
    if not url_lower.startswith(("http://", "https://")):
        raise WebhookError(t("webhook.error.scheme_invalid", url=_safe_url))
    if url_lower.startswith("http://") and os.environ.get("BOB_WEBHOOK_ALLOW_INSECURE") != "1":
        raise WebhookError(t("webhook.error.plain_http_insecure", url=_safe_url))

    # Minimal payload. Generic and Slack receivers handle a plain ``text`` /
    # message dict well; the explicit ``test`` flag + ``bob_smoke_test`` tag
    # lets receivers filter or dashboard them separately from real audit
    # POSTs.
    effective_fmt = detect_format(url, fmt)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if effective_fmt == "slack":
        payload = {
            "text": (
                ":wave: BOB webhook smoke test — "
                "if you see this, the URL is reachable and the receiver "
                "accepts POSTs."
            ),
            "attachments": [{
                "color":  _SLACK_COLOR_OK,
                "fields": [
                    {"title": "Tag",       "value": "bob_smoke_test",  "short": True},
                    {"title": "Timestamp", "value": timestamp,         "short": True},
                ],
            }],
        }
    else:
        payload = {
            "test":      True,
            "tag":       "bob_smoke_test",
            "timestamp": timestamp,
            "message":   (
                "BOB webhook smoke test — if you see this, the URL is "
                "reachable and the receiver accepts POSTs."
            ),
        }

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status: int = resp.status
    except urllib.error.HTTPError as exc:
        raise WebhookError(t("webhook.error.http_status", code=exc.code, reason=exc.reason)) from exc
    except urllib.error.URLError as exc:
        raise WebhookError(t("webhook.error.connection_failed", reason=exc.reason)) from exc
    except OSError as exc:
        raise WebhookError(t("webhook.error.request_error", exc=exc)) from exc

    if not (200 <= status < 300):
        raise WebhookError(t("webhook.error.non_2xx_status", status=status))

    return status
