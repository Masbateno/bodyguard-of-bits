"""
Shared test utilities for bob tests.

Centralises helpers that were previously duplicated across test modules.
Import what you need:

    from tests.helpers import _t, _levels, _keys, _has_finding, _get_finding
    from tests.helpers import _deduction_keys, _deduction_points
"""

from __future__ import annotations

from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Translation stub
# ---------------------------------------------------------------------------

def _t(key: str, **kwargs) -> str:
    """Minimal translation stub — returns the key so assertions stay readable."""
    return key


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------

def _levels(result) -> list[str]:
    """Return list of finding level string values from a CheckResult."""
    return [f.level.value for f in result.findings]


def _keys(result) -> list[str]:
    """Return list of finding keys from a CheckResult."""
    return [f.key for f in result.findings]


def _has_finding(result, key: str, level: FindingLevel) -> bool:
    """Return True if result contains a finding with the given key AND level."""
    return any(f.key == key and f.level == level for f in result.findings)


def _get_finding(result, key: str):
    """Return the first finding with the given key, or None."""
    return next((f for f in result.findings if f.key == key), None)


def _finding_level(result, key: str) -> FindingLevel:
    """Return the level of the first finding with key; raise AssertionError if missing."""
    f = _get_finding(result, key)
    if f is None:
        raise AssertionError(f"Key {key!r} not found in findings: {_keys(result)}")
    return f.level


# ---------------------------------------------------------------------------
# Deduction helpers
# ---------------------------------------------------------------------------

def _deduction_keys(result) -> list[str]:
    """Return list of deduction keys from a CheckResult."""
    return [d.key for d in result.deductions]


def _deduction_points(result) -> int:
    """Return total deduction points from a CheckResult."""
    return sum(d.points for d in result.deductions)
