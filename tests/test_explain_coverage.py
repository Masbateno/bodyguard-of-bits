"""
Coverage guard for ``--explain`` (v0.8.0 drift batch lesson).

The v0.7.4 structural audit surfaced a 38% coverage gap: 51 of 134
WARN/ALERT finding keys emitted by ``bob/checks/*.py`` had **no** entry
in ``EXPLAIN_KEYS`` AND no content under ``explain.*`` in the locales.
Result: ``bob --explain <missing_key>`` returned "No explanation
available for: ..." for over a third of actionable findings — exactly
the wrong third (real risks: SYN flood, MAC inactive, port uncovered,
bruteforce detected, Docker UFW bypass, etc.).

The pre-existing ``test_explain_naming_convention.py`` only asserted
canonical naming (lowercase, snake_case). It did **not** assert
coverage. This file closes that gap.

Pattern mirrors the v0.7.0b2 ``test_version_consistency.py`` lesson
and the v0.8.0 ``test_doc_version_consistency.py`` lesson: when an
invariant matters, pin it in code so drift fails the suite.

## How the whitelist works

The ``_KNOWN_GAPS`` frozenset below tracks the WARN/ALERT keys
KNOWN to lack ``--explain`` coverage at the time this guard was added.
Each entry is debt to be closed. As explain entries are written, keys
are removed from the whitelist. When the whitelist is empty, the
project has full ``--explain`` coverage for actionable findings.

**Adding a new WARN/ALERT finding key**:
  1. Add the explain content (title/why/how) in en.json + fr.json.
  2. Add the key to ``bob/explain.py::_EXPLAIN_GROUPS``.
  3. DON'T add it to ``_KNOWN_GAPS``. The whitelist is for legacy debt only.

**Closing debt**:
  Write the explain content, register in ``_EXPLAIN_GROUPS``, then
  remove the key from ``_KNOWN_GAPS``. The guard will catch it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHECKS_DIR = _REPO_ROOT / "bob" / "checks"


# Methods on CheckResult that produce a "finding to act on". OK/INFO are
# informational — users don't need an explain entry for "everything is fine".
_ACTIONABLE_METHODS = frozenset({
    "warn",
    "alert",
    "warn_with_deduction",
    "alert_with_deduction",
})


# Legacy debt: WARN/ALERT finding keys that emit today but have NO
# --explain coverage. Each entry is a TODO. Shrinks toward zero as
# explain content is written.
#
# DO NOT add new entries here. New checks MUST ship their explain
# content alongside the finding (see module docstring).
_KNOWN_GAPS: frozenset[str] = frozenset()


def _collect_emitted_actionable_keys() -> set[str]:
    """AST-scan every ``bob/checks/*.py`` for ``key=`` literals passed to
    ``.warn()`` / ``.alert()`` / ``.warn_with_deduction()`` /
    ``.alert_with_deduction()`` calls.

    Misses keys passed positionally or through helpers (e.g.
    ``_check_weak_algo(..., "ssh.weak_ciphers", ...)``) — those are
    accepted as "explicit by structure" and out of scope here.
    """
    keys: set[str] = set()
    for py in _CHECKS_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            method = None
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
            if method not in _ACTIONABLE_METHODS:
                continue
            for kw in node.keywords:
                if kw.arg != "key":
                    continue
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    keys.add(kw.value.value)
    return keys


def _covered_keys() -> set[str]:
    """Keys with --explain coverage = present in EXPLAIN_KEYS, aliased,
    or normalized via ``_NORMALIZE_RE`` (file_perms subkeys collapse to
    canonical entries)."""
    from bob.explain import EXPLAIN_KEYS, EXPLAIN_KEY_ALIASES, normalize_key

    canonical = set(EXPLAIN_KEYS)
    aliased = set(EXPLAIN_KEY_ALIASES.keys())
    return canonical | aliased


def _is_covered(key: str) -> bool:
    """Check if a key resolves via ``normalize_key`` to a covered entry."""
    from bob.explain import EXPLAIN_KEYS, EXPLAIN_KEY_ALIASES, normalize_key

    norm = normalize_key(key)
    return norm in EXPLAIN_KEYS or norm in EXPLAIN_KEY_ALIASES


def test_no_new_explain_gaps():
    """Every WARN/ALERT key emitted by checks/ must have --explain
    coverage OR be explicitly whitelisted as legacy debt.

    New checks MUST ship their explain content alongside the finding.
    Adding to ``_KNOWN_GAPS`` is forbidden (see docstring) — write the
    content instead.
    """
    emitted = _collect_emitted_actionable_keys()
    uncovered = {k for k in emitted if not _is_covered(k)}
    new_gaps = uncovered - _KNOWN_GAPS

    assert not new_gaps, (
        f"\n{len(new_gaps)} new WARN/ALERT finding key(s) without --explain coverage:\n"
        + "\n".join(f"  - {k}" for k in sorted(new_gaps))
        + "\n\nWrite the explain content in en.json + fr.json under "
        "explain.<prefix>.<key>.{title,why,how} and register the key in "
        "bob/explain.py::_EXPLAIN_GROUPS. DON'T add to _KNOWN_GAPS."
    )


def test_whitelist_is_actually_legacy():
    """Every entry in ``_KNOWN_GAPS`` must currently be emitted by a
    check AND currently uncovered.

    If an entry is no longer emitted (check renamed/removed), or has
    been covered (explain content written + registered), it must be
    removed from the whitelist. Otherwise the whitelist accumulates
    stale entries and stops working as a debt ledger.
    """
    emitted = _collect_emitted_actionable_keys()
    stale = []
    for k in _KNOWN_GAPS:
        if k not in emitted:
            stale.append(f"  - {k} (no longer emitted by any check)")
        elif _is_covered(k):
            stale.append(f"  - {k} (now has --explain coverage — remove from whitelist)")
    assert not stale, (
        f"\n{len(stale)} stale entry(ies) in _KNOWN_GAPS:\n"
        + "\n".join(stale)
        + "\n\nRemove them from tests/test_explain_coverage.py::_KNOWN_GAPS."
    )


def test_progress_counter_visible():
    """Sanity check that the whitelist size matches what's actually
    uncovered. This test exists purely to surface the count in pytest
    output so progress on the backfill is visible at every run."""
    emitted = _collect_emitted_actionable_keys()
    uncovered = {k for k in emitted if not _is_covered(k)}
    # The visible-progress assertion: equal subsets (one direction
    # is enforced by test_no_new_explain_gaps; this is the other).
    assert uncovered <= _KNOWN_GAPS, (
        f"Whitelist drift: {sorted(uncovered - _KNOWN_GAPS)} uncovered "
        "but not whitelisted (caught by test_no_new_explain_gaps too)."
    )
