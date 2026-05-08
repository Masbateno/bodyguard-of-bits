"""
Golden scenario tests — full scoring pipeline validation.

Each scenario simulates a realistic machine configuration and validates that
the complete scoring pipeline produces the expected final score:

    CheckResult(s) → ScoreEngine.apply() → finalize()
    → apply_domain_score_override() → engine.score

These tests guard against silent regressions in the scoring model across
versions. Each scenario is pinned to a specific configuration and documents
the expected score range and key invariants.
"""

import pytest

from bob.domain_scores import (
    apply_domain_score_override,
    compute_domain_scores,
    active_domains_from_engine,
)
from bob.scoring import CheckResult, FindingLevel, MAX_SCORE, ScoreEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine(*key_points: tuple[int, str], cap: tuple[int, str, str] | None = None) -> ScoreEngine:
    """Build a finalized ScoreEngine from (points, key) pairs and optional cap."""
    engine = ScoreEngine()
    result = CheckResult()
    for points, key in key_points:
        result.add_deduction(reason=key, points=points, context="local", key=key)
        result.add_finding(
            level=FindingLevel.WARN,
            message=key,
            key=key,
        )
    if cap:
        maximum, reason, key = cap
        result.set_cap(maximum=maximum, reason=reason, key=key)
    engine.apply(result)
    engine.finalize()
    apply_domain_score_override(engine)
    return engine


# ---------------------------------------------------------------------------
# Scenario 1 — Clean machine
# ---------------------------------------------------------------------------

class TestCleanMachine:
    def test_no_deductions_score_ten(self):
        engine = ScoreEngine()
        engine.finalize()
        apply_domain_score_override(engine)
        assert engine.score == 10

    def test_no_deductions_no_breakdown(self):
        engine = ScoreEngine()
        engine.finalize()
        apply_domain_score_override(engine)
        assert engine.breakdown == []

    def test_no_active_domains(self):
        engine = ScoreEngine()
        engine.finalize()
        apply_domain_score_override(engine)
        assert active_domains_from_engine(engine) == frozenset()

    def test_info_findings_do_not_activate_domain(self):
        """INFO-level findings must not pull a domain into the active set (v0.2.2 fix)."""
        engine = ScoreEngine()
        result = CheckResult()
        result.add_finding(level=FindingLevel.INFO, message="info only", key="ssh.some_info")
        engine.apply(result)
        engine.finalize()
        apply_domain_score_override(engine)
        assert active_domains_from_engine(engine) == frozenset()
        assert engine.score == 10


# ---------------------------------------------------------------------------
# Scenario 2 — Hardened server (minor gaps only)
# ---------------------------------------------------------------------------

class TestHardenedServer:
    """Typical well-maintained server: 1-2 minor hardening gaps."""

    def _make(self) -> ScoreEngine:
        return _engine(
            (1, "kernel_hardening.ptrace_unrestricted"),
            (1, "kernel_modules.risky_fs"),
        )

    def test_score_exact(self):
        # hardening: 2 deductions → domain=8; average over 1 active domain = 8
        assert self._make().score == 8

    def test_hardening_domain_deducted(self):
        engine = self._make()
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 2
        # Verify against raw breakdown as independent source
        assert any(d.key == "kernel_hardening.ptrace_unrestricted" for d in engine.breakdown)
        assert any(d.key == "kernel_modules.risky_fs" for d in engine.breakdown)

    def test_other_domains_clean(self):
        scores, _ = compute_domain_scores(self._make())
        assert scores["ssh"]["score"] == MAX_SCORE
        assert scores["firewall"]["score"] == MAX_SCORE


# ---------------------------------------------------------------------------
# Scenario 3 — Default Ubuntu/Debian desktop
# ---------------------------------------------------------------------------

class TestDefaultDesktop:
    """Typical default install: several hardening gaps, SSH installed."""

    def _make(self) -> ScoreEngine:
        return _engine(
            (1, "hardening.rp_filter_disabled"),
            (1, "kernel_hardening.ptrace_unrestricted"),
            (1, "ssh.password_auth"),
            (1, "updates.packages_outdated"),
        )

    def test_score_exact(self):
        # hardening=8, ssh=9, updates=9 → average (8+9+9)/3 = 26/3 → round(8.67) = 9
        assert self._make().score == 9

    def test_ssh_domain_deducted(self):
        scores, _ = compute_domain_scores(self._make())
        assert scores["ssh"]["deductions"] == 1

    def test_updates_domain_deducted(self):
        scores, _ = compute_domain_scores(self._make())
        assert scores["updates"]["deductions"] == 1


# ---------------------------------------------------------------------------
# Scenario 4 — Poorly configured server
# ---------------------------------------------------------------------------

class TestPoorlyConfiguredServer:
    """Multiple significant findings across several domains."""

    def _make(self) -> ScoreEngine:
        return _engine(
            (2, "firewall.open_port"),
            (2, "ssh.open_world"),
            (1, "ssh.password_auth"),
            (1, "hardening.rp_filter_disabled"),
            (1, "updates.packages_outdated"),
        )

    def test_score_exact(self):
        # firewall=8, ssh=7, hardening=9, updates=9 → average (8+7+9+9)/4 = 33/4 → round(8.25) = 8
        assert self._make().score == 8

    def test_raw_score_exact(self):
        # 7 pts total deductions → raw = 10 - 7 = 3
        assert self._make().raw_score == 3

    def test_domain_average_improves_over_raw(self):
        engine = self._make()
        assert engine.score > engine.raw_score


# ---------------------------------------------------------------------------
# Scenario 5 — Firewall inactive (hard cap)
# ---------------------------------------------------------------------------

class TestFirewallInactive:
    """Firewall inactive → engine cap at 3/10 regardless of other deductions."""

    def _make(self, extra_deductions: int = 0) -> ScoreEngine:
        key_points = []
        for i in range(extra_deductions):
            key_points.append((1, f"hardening.gap_{i}"))
        return _engine(
            *key_points,
            cap=(3, "Firewall inactive", "firewall.inactive"),
        )

    def test_cap_enforced_no_other_deductions(self):
        # Only active domain is firewall (cap synthetic deduction of 7pt) → domain score=3
        # Domain average = 3/1 = 3 → final score = 3
        assert self._make().score == 3

    def test_cap_enforced_with_extra_deductions(self):
        # cap applies to raw_score; domain average (hardening=5, firewall=3)/2=4 can exceed cap
        engine = self._make(extra_deductions=5)
        assert engine.raw_score == 3
        assert engine.score == 4   # domain average overrides capped raw

    def test_cap_info_stored(self):
        engine = _engine(cap=(3, "Firewall inactive", "firewall.inactive"))
        assert engine.cap_info is not None
        assert engine.cap_info.maximum == 3


# ---------------------------------------------------------------------------
# Scenario 6 — Debian 13 minimal (real-world audit data)
# ---------------------------------------------------------------------------

class TestDebian13Minimal:
    """
    Matches the deduction set observed on a Debian 13 default install:
    password_policy, hardening sysctl, kernel hardening, backup, clamav, rootkit.
    Raw score 2/10 but domain average improves it significantly.
    """

    def _make(self) -> ScoreEngine:
        return _engine(
            (1, "password_policy.no_quality_module"),
            (1, "hardening.rp_filter_disabled"),
            (1, "hardening.send_redirects_enabled"),
            (1, "kernel_hardening.ptrace_unrestricted"),
            (1, "backup.no_backup"),
            (1, "clamav.db_outdated"),
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),           # rootkit capped at 1 pt
        )

    def test_raw_score_is_two(self):
        assert self._make().raw_score == 2

    def test_domain_average_above_raw(self):
        engine = self._make()
        assert engine.score > engine.raw_score

    def test_score_exact(self):
        # hardening=4 (6 deductions), disk=9 (1 deduction) → average (4+9)/2=6.5 → round=6
        assert self._make().score == 6

    def test_rootkit_cap_applied(self):
        engine = self._make()
        scores, _ = compute_domain_scores(engine)
        rootkit_raw = sum(
            d.points for d in engine.breakdown
            if d.key and d.key.startswith("rootkit.")
        )
        assert rootkit_raw == 2  # 2 raw rootkit deductions
        # 5 non-rootkit hardening pts + 1 rootkit (capped from 2) = 6 total, not 7
        assert scores["hardening"]["deductions"] == 6


# ---------------------------------------------------------------------------
# Scenario 7 — Tool cap invariants
# ---------------------------------------------------------------------------

class TestToolCapInvariants:
    def test_rootkit_two_deductions_capped_at_one(self):
        engine = _engine(
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1
        assert scores["hardening"]["score"] == 9

    def test_clamav_two_deductions_capped_at_one(self):
        engine = _engine(
            (1, "clamav.db_very_outdated"),
            (1, "clamav.scan_very_old"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1

    def test_file_integrity_two_deductions_capped_at_one(self):
        engine = _engine(
            (1, "file_integrity.not_installed"),
            (1, "file_integrity.db_outdated"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1

    def test_uncapped_tool_accumulates_normally(self):
        # ssh has no tool cap — two ssh deductions both counted
        engine = _engine(
            (1, "ssh.password_auth"),
            (1, "ssh.permit_root_login"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["deductions"] == 2


# ---------------------------------------------------------------------------
# Scenario 8 — Score stability and monotonicity
# ---------------------------------------------------------------------------

class TestScoreStability:
    def test_order_independent(self):
        """Deduction order does not affect the final score."""
        engine_a = _engine(
            (1, "ssh.password_auth"),
            (1, "rootkit.db_outdated"),
            (1, "updates.packages_outdated"),
        )
        engine_b = _engine(
            (1, "updates.packages_outdated"),
            (1, "rootkit.db_outdated"),
            (1, "ssh.password_auth"),
        )
        assert engine_a.score == engine_b.score

    def test_adding_deduction_in_same_domain_never_raises_score(self):
        """An additional deduction in the same domain cannot increase the final score.
        Note: a deduction in a NEW domain can raise the global score via domain averaging
        if that domain's score is higher than the existing average — this is by design."""
        base = _engine((1, "ssh.password_auth"))
        with_extra = _engine((1, "ssh.password_auth"), (1, "ssh.open_world"))
        assert with_extra.score <= base.score

    def test_domain_scores_independent(self):
        """A deduction in one domain does not affect another domain's score."""
        engine = _engine(
            (1, "ssh.password_auth"),
            (1, "firewall.open_port"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["score"] == 9
        assert scores["firewall"]["score"] == 9
        assert scores["updates"]["score"] == MAX_SCORE

    def test_score_always_in_valid_range(self):
        """Final score is always in [0, 10] regardless of deductions."""
        engine = _engine(*[(1, f"hardening.gap_{i}") for i in range(20)])
        assert 0 <= engine.score <= MAX_SCORE

    def test_raw_score_floor_zero(self):
        """Raw score never goes below 0."""
        engine = ScoreEngine()
        for i in range(30):
            engine.deduct(reason=f"gap {i}", points=1, context="local")
        engine.finalize()
        assert engine.raw_score == 0


# ---------------------------------------------------------------------------
# Scenario 9 — Multi-domain machine
# ---------------------------------------------------------------------------

class TestMultiDomainMachine:
    """Realistic machine with findings spread across 4+ domains."""

    def _make(self) -> ScoreEngine:
        return _engine(
            (1, "ssh.password_auth"),           # ssh domain
            (1, "updates.packages_outdated"),   # updates domain
            (1, "hardening.rp_filter_disabled"),# hardening domain
            (1, "samba.smb1_enabled"),          # samba domain
            (1, "disk.smart_failing"),          # disk domain
        )

    def test_active_domains_exact(self):
        active = active_domains_from_engine(self._make())
        assert active == frozenset({"ssh", "updates", "hardening", "samba", "disk"})

    def test_each_domain_deducted_once(self):
        scores, _ = compute_domain_scores(self._make())
        for domain in ("ssh", "updates", "hardening", "samba", "disk"):
            assert scores[domain]["deductions"] == 1, f"{domain} should have 1 pt deducted"

    def test_score_exact(self):
        # 5 domains each at 9/10 → average = 9
        assert self._make().score == 9
