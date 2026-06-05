"""
i18n safety helpers — consolidate fallback patterns across modules.

Pre-v0.8.2, four modules (``config``, ``webhook``, ``markdown_output``,
``html_output``) each defined a private ``_fallback_t`` plus a
``_FALLBACK_LABELS`` dict. The function bodies drifted across the four
sites (markdown_output skipped ``.format()`` entirely, html_output
conditioned on kwargs presence, config/webhook always formatted) — same
intent, four implementations, three subtly different behaviours.

v0.8.2 consolidates via :func:`make_fallback_t` — a single factory that
returns the ``(key, **kwargs) -> str`` callable each module wants, with
consistent format-or-keep-template-on-error semantics.

The :func:`t_or_hardcoded` helper hoists the ``__main__._t_or_hardcoded``
pattern (gate ``i18n.t`` on the private ``_initialized`` flag) so other
entry points that may fire pre-init can share it.

This module has **zero runtime side effects** — it only exposes pure
helpers — so importing it from any check, snapshot, or output module is
safe and cycle-free.
"""

from __future__ import annotations

from typing import Callable


def make_fallback_t(labels: dict[str, str]) -> Callable[..., str]:
    """Build a ``t(key, **kwargs) -> str`` callable backed by *labels*.

    Used by ``config.py`` / ``webhook.py`` / ``markdown_output.py`` /
    ``html_output.py`` to provide a sane English fallback when no
    operator-bound translation function is wired (legacy callers, unit
    tests, helper smoke scripts).

    Returns the English template for *key* with ``str.format(**kwargs)``
    applied. Unknown keys return the key itself so a missing localisation
    is immediately visible to the developer rather than silently producing
    empty output. ``.format()`` failures (``KeyError`` / ``IndexError`` on
    a placeholder the caller didn't supply) return the raw template
    unchanged — defensive against fallback strings that drift from their
    documented kwarg contract.

    Static fallback strings without ``{}`` placeholders pass through
    ``.format()`` unchanged, so callers that never interpolate kwargs (the
    pre-v0.8.2 ``markdown_output`` pattern) keep working byte-for-byte.

    Args:
        labels: Mapping from canonical key (``"webhook.error.scheme_invalid"``)
                to English template (``"Webhook URL must start with… {url}"``).

    Returns:
        A ``t``-compatible callable suitable for the ``t=None`` fallback
        path in the module's public API.
    """
    def _fallback_t(key: str, **kwargs) -> str:
        template = labels.get(key, key)
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError):
            return template
    return _fallback_t


def t_or_hardcoded(key: str, fallback: str) -> str:
    """Translate *key* if ``bob.i18n`` is already initialised, else return
    *fallback*.

    T60 v0.8.1 introduced this pattern in ``bob/__main__.py`` for two
    entry-point sites that fire BEFORE or AFTER ``i18n.init``:

      * ``parse_args`` CLIError (pre-init — i18n hasn't read the locale yet)
      * ``main()`` catch-all ``Exception`` handler (may be either pre- or
        post-init depending on where the crash fires)

    The hardcoded *fallback* is the English baseline (matching the EN
    locale value verbatim including trailing colon-space per I-2 pass 7)
    so operators see consistent wording on the pre-init path.

    v0.8.2 promoted this helper out of ``__main__`` so other entry points
    (planned ``--test-webhook`` smoke command, future ``--unignore=``
    standalone path, etc.) can share the same gating logic without
    re-importing ``__main__`` (which would create a circular reference).
    """
    from bob import i18n
    if i18n._initialized:
        return i18n.t(key)
    return fallback
