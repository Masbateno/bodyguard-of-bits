"""Regression tests for v0.10.2 I-1.

The v0.9.0 D-1 prefix rename ``iptables_nft.*`` → ``firewall_iptables.*``
left a string-literal comparison in
``bob.scoring.set_posture_from_engine`` matching the retired prefix.
The bug was identified by the post-v0.10.1 deep hardening audit:

    iptables_input_accept=any(
        f.key == "iptables_nft.input_accept" for f in engine.findings
    ),

Result: the iptables-passthrough posture escalation (``forced HIGH when
UFW active but iptables INPUT policy is ACCEPT``) has been silently
dead since v0.9.0. Masked in practice by the ``firewall_inactive``
branch (UFW down + iptables ACCEPT both escalate to HIGH), but the
iptables-only escalation regressed to LOW.

These tests pin the canonical v0.9.0+ key. Pre-v0.10.2, the first
test fails (escalation does not fire). Post-fix, the canonical key is
recognised.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from bob.scoring import (
    Finding,
    RiskLevel,
    ScoreEngine,
    set_posture_from_engine,
)


# ---------------------------------------------------------------------------
# Static guard: the broken legacy key must not be referenced in production
# code (back-compat / migration shims excluded).
# ---------------------------------------------------------------------------


_BOB_ROOT = pathlib.Path(__file__).resolve().parent.parent / "bob"

# Migration / shim modules that *must* mention the legacy key — they
# document the rename so the v0.9.2 baseline migration shim can rewrite
# v0.7.x / v0.8.x baselines.
_LEGACY_KEY_ALLOWED = {
    "_v090_renames.py",   # SECTION_RENAMES_V090 documentation
    "compare.py",          # references the rename in a comment
}


def _iter_py_files() -> list[pathlib.Path]:
    return [p for p in _BOB_ROOT.rglob("*.py") if p.is_file()]


class TestPostureIptablesKey:
    """v0.10.2 I-1: pin the canonical iptables posture key."""

    def test_canonical_key_triggers_iptables_passthrough_escalation(self):
        """With UFW active + a finding carrying the v0.9.0+ canonical key,
        the iptables-passthrough escalation must fire (HIGH floor)."""
        engine = ScoreEngine()
        engine.findings.append(
            Finding(
                level="warn",
                message="iptables INPUT policy is ACCEPT",
                key="firewall_iptables.input_accept",
            )
        )

        # UFW is up, but iptables passthrough rule still ACCEPTs traffic.
        set_posture_from_engine(engine, fw_active=True)

        # Escalation must hit the iptables_input_accept branch.
        level, reason_key = engine.posture_escalation
        assert level is not None, (
            "iptables-passthrough escalation did not fire on canonical key — "
            "v0.10.2 I-1 regression"
        )
        assert level == RiskLevel.HIGH
        assert reason_key == "scoring.posture.iptables_input_accept"

    def test_legacy_key_does_not_trigger_escalation(self):
        """The legacy v0.7.x / v0.8.x key must NOT trigger the escalation
        (it would mean the v0.9.0 D-1 rename was reversed). This pins the
        intent: v0.9.2 baseline migration shim remaps the legacy key at
        load time, but live findings always emit the canonical prefix."""
        engine = ScoreEngine()
        engine.findings.append(
            Finding(
                level="warn",
                message="legacy key — should not match",
                key="iptables_nft.input_accept",  # legacy v0.7.x / v0.8.x
            )
        )

        set_posture_from_engine(engine, fw_active=True)

        # Only the legacy key is present; with UFW active, no escalation
        # should fire (the firewall_inactive branch is False, the
        # iptables_input_accept branch is False).
        level, _reason_key = engine.posture_escalation
        assert level is None, (
            "Legacy ``iptables_nft.input_accept`` should not trigger the "
            "v0.10.2 escalation — the canonical key is the contract"
        )

    def test_no_finding_no_escalation_with_fw_active(self):
        """Sanity baseline: UFW active + zero findings → no escalation."""
        engine = ScoreEngine()
        set_posture_from_engine(engine, fw_active=True)
        level, _reason_key = engine.posture_escalation
        assert level is None

    def test_fw_inactive_still_escalates_independently(self):
        """The ``firewall_inactive`` branch must still work — fix to I-1
        does not touch its escalation path."""
        engine = ScoreEngine()
        # UFW down (fw_active=False) but no iptables finding.
        set_posture_from_engine(engine, fw_active=False)

        level, reason_key = engine.posture_escalation
        assert level == RiskLevel.HIGH
        assert reason_key == "scoring.posture.firewall_inactive"


class TestNoLegacyKeyInLiveCheck:
    """Static guard: production code must not compare against the legacy
    ``iptables_nft.input_accept`` key. Shim / migration modules excluded."""

    def test_scoring_py_does_not_reference_legacy_key_for_match(self):
        """``bob/scoring.py`` must not contain
        ``f.key == "iptables_nft.input_accept"`` (or similar live match)."""
        scoring_src = (_BOB_ROOT / "scoring.py").read_text(encoding="utf-8")
        # Match the literal in a comparison context.
        pattern = re.compile(
            r'==\s*[\'"]iptables_nft\.input_accept[\'"]'
        )
        assert not pattern.search(scoring_src), (
            "bob/scoring.py still compares against the v0.9.0-retired key "
            "``iptables_nft.input_accept`` — v0.10.2 I-1 regression"
        )

    def test_no_other_production_module_references_legacy_key_for_match(self):
        """Sweep ``bob/`` for live comparisons against the legacy key.
        Allowed: comments + the v0.9.2 migration shim contract."""
        pattern = re.compile(
            r'==\s*[\'"]iptables_nft\.input_accept[\'"]'
        )
        offenders: list[str] = []
        for path in _iter_py_files():
            if path.name in _LEGACY_KEY_ALLOWED:
                continue
            src = path.read_text(encoding="utf-8")
            if pattern.search(src):
                offenders.append(str(path.relative_to(_BOB_ROOT.parent)))
        assert not offenders, (
            f"Live comparisons against the legacy key found in: {offenders}"
        )


@pytest.mark.parametrize(
    "canonical_key",
    [
        "firewall_iptables.input_accept",
        # Future canonical keys that should also drive the escalation if
        # the iptables-passthrough class grows new sub-keys — pinning the
        # contract surface here means a future split is caught by review.
    ],
)
def test_canonical_key_present_in_explain_catalog(canonical_key: str) -> None:
    """The canonical key the posture check matches against must also be
    present in ``EXPLAIN_KEYS`` — otherwise the finding has no
    ``bob --explain`` content and the upgrade story breaks."""
    from bob.explain import EXPLAIN_KEYS

    assert canonical_key in EXPLAIN_KEYS, (
        f"{canonical_key!r} drives a posture escalation but is missing "
        "from EXPLAIN_KEYS"
    )
