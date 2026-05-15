"""
BOB locale-independent message formatter — Phase 2 of the distro-ready roadmap.

Status: this module is a **public API for external integrators** (CI dashboards,
distro packagers, JSON consumers). No production code path in BOB itself calls
``format_finding`` / ``format_deduction`` in v0.4.x — the terminal output and
report pipelines still rely on the pre-formatted ``message`` field of each
finding. The formatter exists so that downstream tooling can rebuild localized
text from ``(key, template_vars)`` without parsing the formatted strings.

This module bridges BOB's internal data structures (which carry locale-independent
``Finding.key`` + ``Finding.template_vars``) and a human-readable string in the
currently active locale.

Migration goal: make ``Finding.message`` / ``Deduction.reason`` **progressively
reconstructible** from ``(key, template_vars)`` using the active locale. As
checks are migrated to populate ``template_vars`` (3 pilot checks in v0.4.1,
more to come), external clients (CI dashboards, distro packagers, JSON parsers)
gain the ability to:

  1. Match findings by their stable ``key`` (already locale-independent since v0.3.7).
  2. Re-render the localized text from ``(key, template_vars)`` via this module.

Current state (v0.4.1):
  - Migrated checks fill ``template_vars`` AND keep a pre-formatted ``message``
    in parallel. The formatter prefers the structured path (key + vars) and
    falls back to the pre-formatted message for legacy checks.
  - The promise here is "reconstruction-capable when template_vars are
    provided" — NOT "every finding is reconstructible today". Until all
    ~40 checks are migrated, ``message=`` remains the source of truth for
    legacy findings.

Why the locale parameter is intentionally absent: today ``bob.i18n.t()`` reads
process-wide state. A ``lang=`` kwarg here would be a silent no-op (the global
locale would win), which would mislead callers. Once ``bob.i18n`` exposes a
pure translator object (planned for v0.5.x along with full ``bob.core``
extraction), this module will gain a real ``lang=`` parameter at that time.

Coupling note: this module makes ``Finding.key`` triple-purpose (i18n key,
``--explain`` key, JSON matching key). The freeze policy documented in
``bob/explain.py`` covers all three uses — renames must go through
``EXPLAIN_KEY_ALIASES``.
"""

from __future__ import annotations

from typing import Any

from bob.i18n import try_t
from bob.scoring import Deduction, Finding


def format_finding(finding: Finding) -> str:
    """
    Reconstruct a localized message for ``finding`` from its stable parts.

    Resolution order:
      1. If ``finding.key`` is set AND ``finding.template_vars`` is non-empty,
         render the i18n template for the active locale with those variables.
      2. If ``finding.key`` is set but no template_vars, return the raw
         template (some templates need no interpolation).
      3. Fall back to ``finding.message`` (legacy path — what every BOB ≤ v0.4.0
         did exclusively, and what unmigrated checks still do).

    Args:
        finding: A ``Finding`` instance.

    Returns:
        Localized message string. Falls back to ``finding.message`` whenever
        the key path cannot produce a result (key missing, placeholder
        mismatch). When the finding has neither a resolvable key nor a
        ``message``, returns an empty string.
    """
    if finding.key:
        rendered = _try_render(finding.key, finding.template_vars)
        if rendered is not None:
            return rendered
    return finding.message


def format_deduction(deduction: Deduction) -> str:
    """
    Reconstruct a localized reason for ``deduction``.

    Same resolution order as :func:`format_finding` but applied to
    ``Deduction.key`` + ``Deduction.template_vars`` → ``Deduction.reason``.
    """
    if deduction.key:
        rendered = _try_render(deduction.key, deduction.template_vars)
        if rendered is not None:
            return rendered
    return deduction.reason


def _try_render(key: str, template_vars: dict[str, Any]) -> "str | None":
    """
    Attempt to render ``key`` with ``template_vars`` in the active locale.

    Returns:
        The rendered string on success, or ``None`` when the key is absent
        from the active locale (and default EN fallback).

    Raises:
        KeyError: When the key resolves but ``template_vars`` is missing a
                  placeholder required by the template. We intentionally let
                  this propagate — it is a check-side bug, NOT a runtime
                  condition we want to swallow silently. A missing placeholder
                  means the check declared a key whose template demands a
                  variable the check did not provide.

    Notes:
        Unlike ``bob.i18n.t()`` which returns ``"[key]"`` for missing keys,
        ``try_t`` returns ``None`` — that distinction is the whole reason
        this helper exists. We do NOT pattern-match on the ``"[key]"``
        sentinel (fragile coupling to an internal i18n.t() convention).
    """
    # `try_t` returns None for missing keys, raises KeyError for missing
    # placeholders. KeyError propagates by design (see docstring).
    return try_t(key, **template_vars) if template_vars else try_t(key)
