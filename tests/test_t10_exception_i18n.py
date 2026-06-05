"""
T10 (v0.8.1): i18n exception messages in webhook.py + config.py.

The v0.7.4 audit identified 9 hardcoded English exception messages across
``bob/webhook.py`` (5) and ``bob/config.py`` (4) that surfaced to French
audit users in mixed-language form. v0.8.1 routes each through an optional
``t`` callable with an English fallback dict (pattern from v0.7.2 M-4
``markdown_output.py`` / ``html_output.py``).

These tests pin:

  1. Each translated key resolves in both locales (EN + FR).
  2. The English fallback dict ``_FALLBACK_LABELS`` matches the EN locale
     entry verbatim so a developer translating doesn't drift.
  3. When ``t=None`` (legacy callers, tests), the fallback substitutes
     the English template with kwargs interpolation.
  4. When a custom ``t`` is passed, the WebhookError / ValueError message
     reflects the caller's locale.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from bob.config import EmailStore, UserConfig, _FALLBACK_LABELS as _CONFIG_FALLBACK
from bob.webhook import WebhookError, _FALLBACK_LABELS as _WEBHOOK_FALLBACK, send_webhook


_REPO_ROOT = Path(__file__).resolve().parent.parent
_LOCALES_DIR = _REPO_ROOT / "bob" / "locales"


def _load_locale(lang: str) -> dict:
    return json.loads((_LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def _resolve_dotted(data: dict, dotted_key: str):
    """Walk a dotted key path into a nested dict; None if any hop misses."""
    node = data
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


# ---------------------------------------------------------------------------
# 1. Locale parity: every fallback key must exist in EN and FR
# ---------------------------------------------------------------------------

_ALL_FALLBACK_KEYS = sorted(set(_CONFIG_FALLBACK.keys()) | set(_WEBHOOK_FALLBACK.keys()))


@pytest.mark.parametrize("dotted_key", _ALL_FALLBACK_KEYS)
@pytest.mark.parametrize("lang", ["en", "fr"])
def test_t10_locale_keys_resolve(dotted_key: str, lang: str):
    """Each T10 fallback key must resolve in both locale files."""
    locale = _load_locale(lang)
    value = _resolve_dotted(locale, dotted_key)
    assert value is not None, (
        f"T10 key {dotted_key!r} missing from {lang}.json — "
        f"add an entry under the appropriate nested namespace."
    )
    assert isinstance(value, str), f"{dotted_key!r} in {lang} should be a str, got {type(value).__name__}"


# ---------------------------------------------------------------------------
# 2. Fallback dict is the EN locale verbatim
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dotted_key,fallback_template", sorted({
    **_WEBHOOK_FALLBACK,
    **_CONFIG_FALLBACK,
}.items()))
def test_t10_en_fallback_matches_en_locale(dotted_key: str, fallback_template: str):
    """The ``_FALLBACK_LABELS`` template must match en.json verbatim.

    A drift means a developer changed the EN locale without updating the
    fallback dict, or vice versa — translators copying the fallback into
    fr.json would see a stale baseline.
    """
    en = _load_locale("en")
    en_value = _resolve_dotted(en, dotted_key)
    assert en_value == fallback_template, (
        f"Drift between fallback dict and en.json for {dotted_key!r}:\n"
        f"  fallback dict says = {fallback_template!r}\n"
        f"  en.json says       = {en_value!r}"
    )


# ---------------------------------------------------------------------------
# 3. Fallback substitution: t=None uses EN templates with kwargs interpolation
# ---------------------------------------------------------------------------

class TestWebhookFallback:
    """When t=None, send_webhook raises WebhookError with EN-formatted message."""

    def test_invalid_scheme_uses_en_fallback(self):
        with pytest.raises(WebhookError) as excinfo:
            send_webhook("ftp://example.com", MagicMock(), MagicMock(), "0.8.1")
        msg = str(excinfo.value)
        # The {url} placeholder got interpolated (with repr() — so includes quotes)
        assert "'ftp://example.com'" in msg
        # English baseline phrasing
        assert "must start with https://" in msg


class TestConfigFallback:
    """When t=None on UserConfig.set_*, raised ValueError uses EN fallback."""

    def test_set_invalid_key_en_fallback(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        with pytest.raises(ValueError) as excinfo:
            cfg.set("not-an-identifier!", "x")
        assert "Invalid config key" in str(excinfo.value)
        assert "'not-an-identifier!'" in str(excinfo.value)

    def test_set_webhook_url_invalid_scheme_en_fallback(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        with pytest.raises(ValueError) as excinfo:
            cfg.set_webhook_url("ftp://x.example.com")
        assert "must start with http://" in str(excinfo.value)
        assert "'ftp://x.example.com'" in str(excinfo.value)

    def test_set_webhook_format_invalid_en_fallback(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        with pytest.raises(ValueError) as excinfo:
            cfg.set_webhook_format("xml")
        assert "must be 'auto', 'generic', or 'slack'" in str(excinfo.value)

    def test_email_add_invalid_en_fallback(self, tmp_path):
        store = EmailStore.load(path=tmp_path / "emails")
        with pytest.raises(ValueError) as excinfo:
            store.add("not-an-email")
        assert "Invalid email address" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 4. Custom t: passed t callable controls the resulting message
# ---------------------------------------------------------------------------

class TestCustomT:
    """When a custom t is threaded, the raised message reflects the locale."""

    def test_webhook_custom_t_used(self):
        def _french_t(key, **kwargs):
            assert key == "webhook.error.scheme_invalid"
            assert "url" in kwargs
            return f"[FR-MOCK] schéma invalide : {kwargs['url']}"

        with pytest.raises(WebhookError) as excinfo:
            send_webhook("ftp://x", MagicMock(), MagicMock(), "0.8.1", t=_french_t)
        assert "[FR-MOCK]" in str(excinfo.value)
        assert "schéma invalide" in str(excinfo.value)

    def test_config_custom_t_used(self, tmp_path):
        def _french_t(key, **kwargs):
            # ``key`` here is the dotted locale key (e.g. config.error.invalid_config_key);
            # the original input is in kwargs under ``config_key`` to avoid the
            # name clash with t()'s first positional.
            return f"[FR-MOCK] clé invalide : {kwargs.get('config_key', '?')}"

        cfg = UserConfig.load(path=tmp_path / "config.conf")
        with pytest.raises(ValueError) as excinfo:
            cfg.set("bad!key", "v", t=_french_t)
        assert "[FR-MOCK]" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 5. Backwards-compatibility: legacy callers (no t kwarg) still work
# ---------------------------------------------------------------------------

class TestLegacyCallers:
    """Pre-T10 callers passing positional args without t= must still work."""

    def test_send_webhook_no_t_kwarg(self):
        # Old signature: send_webhook(url, engine, sys_info, version, fmt, timeout)
        with pytest.raises(WebhookError):
            send_webhook("ftp://nope", MagicMock(), MagicMock(), "0.8.1")

    def test_user_config_set_no_t_kwarg(self, tmp_path):
        cfg = UserConfig.load(path=tmp_path / "config.conf")
        # Valid call without t still works
        cfg.set("good_key", "value")
        assert cfg.get("good_key") == "value"

    def test_email_store_add_no_t_kwarg(self, tmp_path):
        store = EmailStore.load(path=tmp_path / "emails")
        # Valid email without t still works
        store.add("ok@example.com")
        assert "ok@example.com" in store.all()
