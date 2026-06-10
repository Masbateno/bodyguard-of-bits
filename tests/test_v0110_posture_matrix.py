"""v0.11.0 — exhaustive posture-escalation matrix.

The v0.10.2 I-1 bug (``iptables_input_accept`` posture escalation
silently dead since v0.9.0) was invisible for 3 majors because the
``firewall_inactive`` branch masked it on the most common deployment
shape. The lesson: a posture system with *overlapping* triggers must
be tested across the full input matrix — "fire when expected" is not
enough, each branch must be shown to fire (and yield) in isolation.

``ScoreEngine.posture_escalation`` has three triggers in priority
order (see ``scoring.py``):

  1. firewall_inactive       → HIGH   (scoring.posture.firewall_inactive)
  2. iptables_input_accept   → HIGH   (scoring.posture.iptables_input_accept)
  3. firewall_domain_score≤3 → MEDIUM (scoring.posture.firewall_domain_low)
  else                       → (None, "")

The three boolean-ish inputs are driven by ``set_posture_from_engine``:

  - ``fw_active``                  → firewall_inactive = not fw_active
  - a ``firewall_iptables.input_accept`` finding present → iptables_input_accept
  - ``domain_scores["firewall"]["score"] <= 3``          → domain-low branch

This module enumerates the full 2×2×2 = 8-cell matrix and pins the
exact ``posture_escalation`` output for every combination, including
the priority resolution when multiple triggers are live.
"""

from __future__ import annotations

import itertools

import pytest

from bob.scoring import (
    Finding,
    RiskLevel,
    ScoreEngine,
    set_posture_from_engine,
)


_IPTABLES_KEY = "firewall_iptables.input_accept"


def _build_engine(*, iptables_finding: bool, domain_low: bool) -> ScoreEngine:
    """Construct a finalised-enough engine for posture computation.

    ``iptables_finding`` adds a live ``firewall_iptables.input_accept``
    finding (the canonical v0.9.0+ key). ``domain_low`` sets the
    firewall domain score to 2 (≤3, triggers MEDIUM) vs 8 (>3, clear).
    """
    engine = ScoreEngine()
    if iptables_finding:
        engine.findings.append(
            Finding(level="warn", message="iptables INPUT ACCEPT", key=_IPTABLES_KEY)
        )
    score = 2 if domain_low else 8
    engine.set_domain_scores({"firewall": {"score": score}}, frozenset({"firewall"}))
    return engine


# ---------------------------------------------------------------------------
# The full truth table. Each row: (fw_active, iptables, domain_low) →
# (expected_floor, expected_reason_key).
#
# Priority: firewall_inactive > iptables_input_accept > domain_low > none.
# ---------------------------------------------------------------------------

_HIGH_INACTIVE = (RiskLevel.HIGH, "scoring.posture.firewall_inactive")
_HIGH_IPTABLES = (RiskLevel.HIGH, "scoring.posture.iptables_input_accept")
_MEDIUM_DOMAIN = (RiskLevel.MEDIUM, "scoring.posture.firewall_domain_low")
_NONE = (None, "")

_MATRIX = {
    # fw_active=True → firewall_inactive branch is False
    (True,  False, False): _NONE,            # all clear
    (True,  False, True):  _MEDIUM_DOMAIN,   # only domain-low fires
    (True,  True,  False): _HIGH_IPTABLES,   # iptables-only escalation (the v0.10.2 bug cell)
    (True,  True,  True):  _HIGH_IPTABLES,   # iptables wins over domain-low
    # fw_active=False → firewall_inactive branch is True (top priority)
    (False, False, False): _HIGH_INACTIVE,   # firewall_inactive alone
    (False, False, True):  _HIGH_INACTIVE,   # firewall_inactive wins over domain-low
    (False, True,  False): _HIGH_INACTIVE,   # firewall_inactive wins over iptables
    (False, True,  True):  _HIGH_INACTIVE,   # firewall_inactive wins over both
}


@pytest.mark.parametrize(
    ("fw_active", "iptables", "domain_low"),
    list(itertools.product([True, False], repeat=3)),
)
def test_posture_matrix_full(fw_active: bool, iptables: bool, domain_low: bool) -> None:
    """Every cell of the UFW × iptables × domain-score matrix yields the
    documented ``posture_escalation`` output."""
    engine = _build_engine(iptables_finding=iptables, domain_low=domain_low)
    set_posture_from_engine(engine, fw_active=fw_active)

    expected = _MATRIX[(fw_active, iptables, domain_low)]
    assert engine.posture_escalation == expected, (
        f"matrix cell (fw_active={fw_active}, iptables={iptables}, "
        f"domain_low={domain_low}) drifted"
    )


class TestPostureBranchIsolation:
    """Each escalation branch must fire in ISOLATION — the v0.10.2 lesson
    that a masking branch can hide a dead one for majors."""

    def test_iptables_branch_fires_without_firewall_inactive(self):
        """The branch that was dead v0.9.0 → v0.10.1: iptables escalation
        must fire on its own when UFW is active (firewall_inactive False)."""
        engine = _build_engine(iptables_finding=True, domain_low=False)
        set_posture_from_engine(engine, fw_active=True)
        floor, reason = engine.posture_escalation
        assert floor == RiskLevel.HIGH
        assert reason == "scoring.posture.iptables_input_accept"

    def test_firewall_inactive_branch_fires_without_iptables(self):
        engine = _build_engine(iptables_finding=False, domain_low=False)
        set_posture_from_engine(engine, fw_active=False)
        floor, reason = engine.posture_escalation
        assert floor == RiskLevel.HIGH
        assert reason == "scoring.posture.firewall_inactive"

    def test_domain_low_branch_fires_in_isolation(self):
        engine = _build_engine(iptables_finding=False, domain_low=True)
        set_posture_from_engine(engine, fw_active=True)
        floor, reason = engine.posture_escalation
        assert floor == RiskLevel.MEDIUM
        assert reason == "scoring.posture.firewall_domain_low"

    def test_no_branch_fires_when_all_clear(self):
        engine = _build_engine(iptables_finding=False, domain_low=False)
        set_posture_from_engine(engine, fw_active=True)
        floor, reason = engine.posture_escalation
        assert floor is None
        assert reason == ""


class TestPosturePriorityResolution:
    """When multiple triggers are live, the documented priority order
    (firewall_inactive > iptables > domain_low) must hold."""

    def test_firewall_inactive_beats_iptables(self):
        engine = _build_engine(iptables_finding=True, domain_low=False)
        set_posture_from_engine(engine, fw_active=False)
        _floor, reason = engine.posture_escalation
        assert reason == "scoring.posture.firewall_inactive"

    def test_iptables_beats_domain_low(self):
        engine = _build_engine(iptables_finding=True, domain_low=True)
        set_posture_from_engine(engine, fw_active=True)
        _floor, reason = engine.posture_escalation
        assert reason == "scoring.posture.iptables_input_accept"

    def test_firewall_inactive_beats_all(self):
        engine = _build_engine(iptables_finding=True, domain_low=True)
        set_posture_from_engine(engine, fw_active=False)
        _floor, reason = engine.posture_escalation
        assert reason == "scoring.posture.firewall_inactive"
