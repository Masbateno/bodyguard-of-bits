"""
Internationalisation module for BOB.

Usage:
    # Initialise once at startup
    from bob import i18n
    i18n.init(lang="fr")

    # Use anywhere in the codebase
    from bob.i18n import t
    t("sec_services")           # → "ANALYSE DES SERVICES RÉSEAU"
    t("samba.open_world")       # → "Samba est restreint à votre réseau local..."

Supported languages are determined by the locale files present in
the locales/ directory alongside this package. Each locale file is
a UTF-8 JSON file named <lang>.json (e.g. en.json, fr.json).

Missing keys return the key itself wrapped in brackets so they are
visible in output without causing a crash.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from bob._paths import resolve_share_dir

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state — initialised once via init()
# ---------------------------------------------------------------------------

_translations: dict[str, Any] = {}
_default_translations: dict[str, Any] = {}  # always EN — used as per-key fallback
_lang: str = "en"
_initialized: bool = False

# Locale files location:
# - If UFW_AUDIT_SHARE env var is set (installed), use that share directory
# - Otherwise fall back to locales/ next to this module (development)
_share_path = resolve_share_dir()
_LOCALES_DIR = (_share_path / "locales") if _share_path else (Path(__file__).parent / "locales")

SUPPORTED_LANGS = ("en", "fr")
DEFAULT_LANG = "en"
_MAX_LOCALE_SIZE = 512 * 1024  # 512 KB


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_system_lang() -> str:
    """
    Detect the user's preferred language from POSIX locale environment variables.

    Probes (in standard POSIX order): ``$LC_ALL``, ``$LC_MESSAGES``, ``$LANG``.
    Returns one of ``SUPPORTED_LANGS`` (``"en"`` or ``"fr"``).

    Falls back to ``DEFAULT_LANG`` when:
      - none of the env vars are set
      - the locale is ``C`` or ``POSIX``
      - the locale prefix doesn't match any supported language

    A locale of the form ``fr_FR.UTF-8``, ``fr_BE``, ``fr_CA@something`` resolves
    to ``"fr"``. Anything else (incl. ``ja_JP``, ``de_DE``) → ``"en"``.
    """
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var, "").strip()
        if not value or value in ("C", "POSIX", "C.UTF-8", "C.utf8"):
            continue
        # strip codeset (.UTF-8) and modifier (@euro)
        prefix = value.split(".", 1)[0].split("@", 1)[0]
        # 2-letter language code is the first segment of "ll_CC"
        lang = prefix.split("_", 1)[0].lower()
        if lang in SUPPORTED_LANGS:
            return lang
        return DEFAULT_LANG
    return DEFAULT_LANG

def init(lang: str = DEFAULT_LANG) -> None:
    """
    Load the locale file for the requested language.

    Must be called once before any call to t(). Calling init() a second
    time reloads the locale, allowing language switching in tests.

    Args:
        lang: Language code, e.g. "en" or "fr". Falls back to DEFAULT_LANG
              if the requested locale file does not exist.

    Raises:
        FileNotFoundError: If neither the requested nor the fallback locale
                           file can be found.
    """
    global _translations, _default_translations, _lang, _initialized

    locale_path = _LOCALES_DIR / f"{lang}.json"

    if not locale_path.exists():
        logger.warning(
            "Locale file not found for language %r, falling back to %r",
            lang,
            DEFAULT_LANG,
        )
        locale_path = _LOCALES_DIR / f"{DEFAULT_LANG}.json"

    if not locale_path.exists():
        raise FileNotFoundError(
            f"No locale file found at {locale_path}. "
            f"Expected files: {_LOCALES_DIR}/<lang>.json"
        )

    _translations = _load_locale(locale_path)

    _lang = locale_path.stem  # reflects actual loaded locale, not the requested one
    _initialized = True
    logger.debug("Loaded locale %r from %s", _lang, locale_path)

    # Load default (EN) translations for per-key fallback when using a non-default lang
    if _lang != DEFAULT_LANG:
        default_path = _LOCALES_DIR / f"{DEFAULT_LANG}.json"
        if default_path.exists():
            try:
                _default_translations = _load_locale(default_path)
            except (OSError, ValueError):
                _default_translations = {}
        else:
            _default_translations = {}
    else:
        _default_translations = _translations


def try_t(key: str, **kwargs: Any) -> "str | None":
    """
    Resolve ``key`` in the active locale or return ``None`` if absent.

    Unlike :func:`t`, this function distinguishes "key missing" from "key with
    bracket-formatted value": missing → ``None``, present → the rendered string.
    This is the helper to use when a caller needs to react to a missing key
    instead of degrading silently to the ``"[key]"`` sentinel.

    Args:
        key:    Dot-separated translation key.
        kwargs: Optional named placeholders for str.format().

    Returns:
        Rendered translated string, or ``None`` if:
          - i18n has not been initialised yet, OR
          - the key does not exist in the active locale and the default EN
            fallback, OR
          - the resolved value is not a string.

    Raises:
        KeyError: If a required placeholder is missing from kwargs at
                  interpolation time. (Same as ``str.format``.)

    Notes:
        Introduced in v0.4.1 to give ``bob.formatter`` a clean way to detect
        missing keys without parsing the ``"[key]"`` sentinel produced by
        :func:`t`. See :func:`t` for the legacy sentinel-returning variant
        used by the rest of the codebase.
    """
    if not _initialized:
        return None
    value = _resolve(key, _translations)
    if value is None and _default_translations is not _translations:
        value = _resolve(key, _default_translations)
    if value is None or not isinstance(value, str):
        return None
    if kwargs:
        # str.format raises KeyError for missing placeholders — we let it
        # propagate so callers can distinguish "key missing" (None return)
        # from "key present but call site forgot a kwarg" (KeyError).
        return value.format(**kwargs)
    return value


def t(key: str, **kwargs: Any) -> str:
    """
    Return the translated string for key.

    Supports dot-notation for nested keys:
        t("samba.open_world")  →  _translations["samba"]["open_world"]

    Supports optional str.format() interpolation:
        t("log.blocked_attempts", count=42)  →  "42 tentative(s) bloquée(s)"

    Args:
        key:    Dot-separated translation key.
        kwargs: Optional named placeholders for str.format().

    Returns:
        Translated string, or "[key]" if the key is not found.
    """
    if not _initialized:
        logger.warning("i18n.t() called before i18n.init() — returning key %r", key)
        return f"[{key}]"

    value = _resolve(key, _translations)

    if value is None and _default_translations is not _translations:
        value = _resolve(key, _default_translations)
        if value is not None:
            logger.debug("Key %r missing in %r — using EN fallback", key, _lang)

    if value is None:
        logger.debug("Missing translation key: %r (lang=%r)", key, _lang)
        return f"[{key}]"

    if not isinstance(value, str):
        logger.warning(
            "Translation key %r resolved to non-string type %s",
            key,
            type(value).__name__,
        )
        return f"[{key}]"

    if kwargs:
        try:
            return value.format(**kwargs)
        except KeyError as exc:
            logger.warning(
                "Missing placeholder %s in translation key %r", exc, key
            )
            return value

    return value


def current_lang() -> str:
    """Return the currently loaded language code."""
    return _lang


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_locale(path: Path) -> dict[str, Any]:
    """
    Read, size-check, parse and validate a single locale JSON file.

    Raises:
        ValueError:  On oversized file, invalid JSON, or non-dict root.
        OSError:     On read failure.
    """
    with path.open(encoding="utf-8") as fh:
        content = fh.read(_MAX_LOCALE_SIZE + 1)
    if len(content) > _MAX_LOCALE_SIZE:
        raise ValueError(f"Locale file {path} exceeds maximum allowed size (512 KB)")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Locale file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"Locale file {path} must contain a JSON object, got {type(data).__name__}"
        )
    return data


_MAX_KEY_DEPTH = 10  # guard against absurdly deep dot-notation keys


def _resolve(key: str, data: dict[str, Any]) -> Any:
    """
    Walk a nested dict using dot-separated key segments.

    Args:
        key:  Dot-separated key string, e.g. "samba.open_world".
        data: Dictionary to search.

    Returns:
        The value at the resolved path, or None if any segment is missing.
    """
    segments = key.split(".")
    if len(segments) > _MAX_KEY_DEPTH:
        logger.warning("Translation key %r exceeds max depth (%d)", key, _MAX_KEY_DEPTH)
        return None
    node: Any = data
    for segment in segments:
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node
