"""
Tests for bob/domain_scores.py  (Phase B1)
and CIS reference lookup              (Phase B2)
and --diff CLI flag                   (Phase B3)
"""

from __future__ import annotations

import io
import sys

import pytest

from bob.domain_scores import (
    DOMAINS,
    TOOL_CAPS,
    key_to_domain,
    active_domains_from_engine,
    apply_domain_score_override,
    compute_domain_scores,
    compute_global_from_domains,
    render_domain_scores,
)
from bob.scoring import CheckResult, ScoreEngine
from bob.scoring import MAX_SCORE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(*deduction_specs) -> ScoreEngine:
    """
    Build a finalized ScoreEngine from a list of (points, key) tuples.

    Each tuple adds both a finding and a deduction so that domain_scores
    (which reads engine.breakdown) correctly attributes the points.

    Example:
        _make_engine((3, "ssh.permit_root_login"), (2, "updates.security_pending"))
    """
    engine = ScoreEngine()
    result = CheckResult()
    for points, key in deduction_specs:
        result.alert(message=f"Finding for {key}", key=key)
        result.add_deduction(reason=f"Deduction for {key}", points=points, key=key)
    engine.apply(result)
    engine.finalize()
    return engine


def _clean_engine() -> ScoreEngine:
    engine = ScoreEngine()
    engine.finalize()
    return engine


# ---------------------------------------------------------------------------
# key_to_domain
# ---------------------------------------------------------------------------

class TestKeyToDomain:
    def test_ssh_key(self):
        assert key_to_domain("ssh.password_auth") == "ssh"

    def test_file_perms_key(self):
        assert key_to_domain("file_perms.world_writable") == "file_perms"

    def test_updates_key(self):
        assert key_to_domain("updates.security_pending") == "updates"

    def test_hardening_key(self):
        assert key_to_domain("hardening.rp_filter_disabled") == "hardening"

    def test_firewall_key_falls_back(self):
        assert key_to_domain("firewall.inactive") == "firewall"

    def test_unknown_prefix_falls_back_to_firewall(self):
        assert key_to_domain("ports.public_port") == "firewall"

    def test_empty_key_returns_none(self):
        assert key_to_domain("") is None

    def test_none_key_returns_none(self):
        assert key_to_domain(None) is None

    def test_dot_only_key_falls_back_to_firewall(self):
        assert key_to_domain(".") == "firewall"

    def test_double_dot_key_uses_first_segment(self):
        assert key_to_domain("ssh..weird") == "ssh"

    def test_no_dot_key_falls_back_to_firewall(self):
        assert key_to_domain("something") == "firewall"


# ---------------------------------------------------------------------------
# compute_domain_scores — structure
# ---------------------------------------------------------------------------

class TestComputeDomainScoresStructure:
    def test_returns_all_domains(self):
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert d in scores

    def test_each_entry_has_score(self):
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert "score" in scores[d]

    def test_each_entry_has_deductions(self):
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert "deductions" in scores[d]

    def test_each_entry_has_label(self):
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert "label" in scores[d]
            assert scores[d]["label"]  # non-empty

    def test_clean_engine_all_max(self):
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert scores[d]["score"] == MAX_SCORE

    def test_clean_engine_zero_deductions(self):
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert scores[d]["deductions"] == 0


# ---------------------------------------------------------------------------
# compute_domain_scores — attribution
# ---------------------------------------------------------------------------

class TestComputeDomainScoresAttribution:
    def test_ssh_deduction_reduces_ssh_score(self):
        engine = _make_engine((3, "ssh.permit_root_login"))
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["score"] < MAX_SCORE

    def test_ssh_deduction_does_not_affect_other_domains(self):
        engine = _make_engine((3, "ssh.permit_root_login"))
        scores, _ = compute_domain_scores(engine)
        for d in DOMAINS:
            if d != "ssh":
                assert scores[d]["score"] == MAX_SCORE

    def test_updates_deduction_reduces_updates_score(self):
        engine = _make_engine((2, "updates.security_pending"))
        scores, _ = compute_domain_scores(engine)
        assert scores["updates"]["score"] < MAX_SCORE

    def test_hardening_deduction_reduces_hardening_score(self):
        engine = _make_engine((1, "hardening.rp_filter_disabled"))
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["score"] < MAX_SCORE

    def test_file_perms_deduction_reduces_file_perms_score(self):
        engine = _make_engine((2, "file_perms.world_writable"))
        scores, _ = compute_domain_scores(engine)
        assert scores["file_perms"]["score"] < MAX_SCORE

    def test_score_floor_is_zero(self):
        """Score never goes negative even with many deductions."""
        engine = ScoreEngine()
        result = CheckResult()
        for i in range(20):
            result.add_deduction(reason=f"ded {i}", points=5, key="ssh.permit_root_login")
        engine.apply(result)
        engine.finalize()
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["score"] >= 0

    def test_deductions_without_key_are_excluded(self):
        """Synthetic deductions (no key) must not affect any domain score."""
        engine = ScoreEngine()
        result = CheckResult()
        result.add_deduction(reason="synthetic", points=2, key="")
        engine.apply(result)
        engine.finalize()
        scores, _ = compute_domain_scores(engine)
        for d in DOMAINS:
            assert scores[d]["deductions"] == 0

    # --- additional coverage gaps -------------------------------------------

    def test_multiple_deductions_same_domain_accumulate(self):
        """Two SSH deductions must stack in the same domain bucket."""
        engine = _make_engine(
            (2, "ssh.password_auth"),
            (3, "ssh.permit_root_login"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["deductions"] == 5
        assert scores["ssh"]["score"] == MAX_SCORE - 5

    def test_multiple_deductions_cross_domain(self):
        """Deductions in different domains must each reduce only their own score."""
        engine = _make_engine(
            (2, "ssh.password_auth"),
            (3, "updates.security_pending"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["score"] < MAX_SCORE
        assert scores["updates"]["score"] < MAX_SCORE
        assert scores["hardening"]["score"] == MAX_SCORE
        assert scores["file_perms"]["score"] == MAX_SCORE

    def test_unknown_keys_go_to_firewall_domain(self):
        """Keys with unknown prefixes must be attributed to the firewall bucket."""
        engine = ScoreEngine()
        result = CheckResult()
        result.add_deduction(reason="open port", points=2, key="ports.public_port")
        engine.apply(result)
        engine.finalize()
        scores, _ = compute_domain_scores(engine)
        assert scores["firewall"]["deductions"] == 2
        assert scores["firewall"]["score"] == MAX_SCORE - 2

    def test_score_never_exceeds_max(self):
        """Domain score must never exceed MAX_SCORE even with a clean engine."""
        scores, _ = compute_domain_scores(_clean_engine())
        for d in DOMAINS:
            assert scores[d]["score"] <= MAX_SCORE

    def test_findings_without_deductions_do_not_affect_domain(self):
        """Findings alone (no add_deduction call) must leave domain scores at max."""
        engine = ScoreEngine()
        result = CheckResult()
        result.alert(message="test finding", key="ssh.password_auth")
        engine.apply(result)
        engine.finalize()
        scores, _ = compute_domain_scores(engine)
        assert scores["ssh"]["deductions"] == 0
        assert scores["ssh"]["score"] == MAX_SCORE


# ---------------------------------------------------------------------------
# Tool caps in compute_domain_scores
# ---------------------------------------------------------------------------

class TestToolCaps:
    def test_rootkit_two_findings_capped_at_one(self):
        engine = _make_engine(
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1
        assert scores["hardening"]["score"] == MAX_SCORE - 1

    def test_clamav_two_findings_capped_at_one(self):
        engine = _make_engine(
            (1, "clamav.db_outdated"),
            (1, "clamav.scan_old"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1
        assert scores["hardening"]["score"] == MAX_SCORE - 1

    def test_file_integrity_two_findings_capped_at_one(self):
        engine = _make_engine(
            (1, "file_integrity.not_installed"),
            (1, "file_integrity.no_run"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1

    def test_uncapped_prefix_accumulates_fully(self):
        engine = _make_engine(
            (1, "hardening.rp_filter_disabled"),
            (1, "hardening.send_redirects_enabled"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 2
        assert scores["hardening"]["score"] == MAX_SCORE - 2



# ---------------------------------------------------------------------------
# Engine-level domain cap (firewall.inactive → max 3/10 for firewall domain)
# ---------------------------------------------------------------------------

class TestEngineLevelDomainCap:
    """Cap set via engine.cap_info must always constrain the target domain score."""

    @staticmethod
    def _make_engine_with_cap(deduction_specs, cap_maximum=3,
                              cap_key="firewall.inactive") -> ScoreEngine:
        engine = ScoreEngine()
        result = CheckResult()
        for points, key in deduction_specs:
            result.alert(message=f"Finding for {key}", key=key)
            result.add_deduction(reason=f"Deduction for {key}", points=points, key=key)
        result.set_cap(maximum=cap_maximum, reason="pare-feu inactif", key=cap_key)
        engine.apply(result)
        engine.finalize()
        return engine

    def test_firewall_domain_capped_when_few_deductions(self):
        # INPUT -3, FORWARD -1 → raw domain = 6 > 3 → must be capped to 3
        engine = self._make_engine_with_cap([
            (3, "firewall.input_accept"),
            (1, "firewall.forward_accept"),
        ])
        scores, _ = compute_domain_scores(engine)
        assert scores["firewall"]["score"] == 3

    def test_firewall_domain_capped_when_many_global_deductions(self):
        # Many deductions push global raw_score below cap threshold so the
        # breakdown delta is never appended — cap must still apply to domain.
        engine = self._make_engine_with_cap([
            (3, "firewall.input_accept"),
            (1, "firewall.forward_accept"),
            (1, "hardening.icmp_redirects"),
            (1, "hardening.icmp6_redirects"),
            (1, "hardening.send_redirects"),
            (1, "backup.no_backup"),
            (1, "firmware.fwupd_updates"),
        ])
        # Global raw_score = 10 - 9 = 1, already below cap (3) → delta not in breakdown
        assert engine._raw_score <= 3  # cap did not fire via breakdown
        scores, _ = compute_domain_scores(engine)
        # But firewall domain (raw=6) must still be capped at 3
        assert scores["firewall"]["score"] == 3

    def test_firewall_domain_not_overcapped_when_already_at_cap(self):
        # If domain score is already at or below cap, no further reduction
        engine = self._make_engine_with_cap([
            (3, "firewall.input_accept"),
            (1, "firewall.forward_accept"),
            (3, "firewall.open_ports"),  # raw domain = 10-7 = 3 = cap
        ])
        scores, _ = compute_domain_scores(engine)
        assert scores["firewall"]["score"] == 3  # already there, not pushed below

    def test_firewall_domain_score_never_exceeds_cap(self):
        for extra in range(5):
            engine = self._make_engine_with_cap(
                [(1, f"firewall.issue_{i}") for i in range(extra)],
                cap_maximum=3,
            )
            scores, _ = compute_domain_scores(engine)
            assert scores["firewall"]["score"] <= 3, (
                f"firewall score {scores['firewall']['score']} exceeds cap=3 "
                f"with {extra} extra deductions"
            )

    def test_cap_does_not_affect_other_domains(self):
        engine = self._make_engine_with_cap([
            (3, "firewall.input_accept"),
            (1, "firewall.forward_accept"),
        ])
        scores, _ = compute_domain_scores(engine)
        # Only firewall is capped; hardening untouched
        assert scores["hardening"]["score"] == MAX_SCORE

    def test_all_domain_scores_in_valid_range_with_cap(self):
        engine = self._make_engine_with_cap([
            (3, "firewall.input_accept"),
            (1, "firewall.forward_accept"),
            (1, "hardening.send_redirects"),
        ])
        scores, _ = compute_domain_scores(engine)
        for d in DOMAINS:
            assert 0 <= scores[d]["score"] <= MAX_SCORE


    def test_caps_do_not_bleed_across_tools(self):
        # rootkit capped at 1 must not reduce clamav's allowed contribution
        engine = _make_engine(
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),
            (1, "clamav.db_outdated"),
        )
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 2   # rootkit=1 + clamav=1

    def test_cap_respects_first_deduction_points(self):
        # A single 2-point deduction against a cap of 1 is clamped to 1
        engine = _make_engine((2, "clamav.db_very_outdated"))
        scores, _ = compute_domain_scores(engine)
        assert scores["hardening"]["deductions"] == 1

    def test_tool_caps_dict_contains_expected_keys(self):
        assert "rootkit"        in TOOL_CAPS
        assert "clamav"         in TOOL_CAPS
        assert "file_integrity" in TOOL_CAPS


# ---------------------------------------------------------------------------
# compute_global_from_domains
# ---------------------------------------------------------------------------

class TestComputeGlobalFromDomains:
    def test_average_of_two_active_domains(self):
        # ssh=9 (one −1 deduction), hardening=8 (one −2 deduction)
        engine = _make_engine(
            (1, "ssh.password_auth"),
            (2, "hardening.ptrace_unrestricted"),
        )
        scores, _ = compute_domain_scores(engine)
        active = active_domains_from_engine(engine)
        result = compute_global_from_domains(scores, active)
        assert result == round((9 + 8) / 2)

    def test_no_active_domains_returns_max(self):
        result = compute_global_from_domains(
            compute_domain_scores(_clean_engine()),
            frozenset(),
        )
        assert result == MAX_SCORE

    def test_result_clamped_to_max(self):
        result = compute_global_from_domains(
            compute_domain_scores(_clean_engine()),
            frozenset(DOMAINS),
        )
        assert result <= MAX_SCORE

    def test_result_non_negative(self):
        engine = _make_engine(*[(10, f"hardening.issue_{i}") for i in range(8)])
        scores, _ = compute_domain_scores(engine)
        active = active_domains_from_engine(engine)
        assert compute_global_from_domains(scores, active) >= 0


# ---------------------------------------------------------------------------
# apply_domain_score_override — integration
# ---------------------------------------------------------------------------

class TestApplyDomainScoreOverride:
    def test_engine_score_changes_after_override(self):
        engine = _make_engine(
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),
            (1, "hardening.rp_filter_disabled"),
        )
        raw = engine._raw_score     # 10 - 3 = 7
        apply_domain_score_override(engine)
        # domain average (hardening=8 due to cap) differs from raw sum
        assert engine.score != raw or engine.score == MAX_SCORE

    def test_score_in_valid_range(self):
        engine = _make_engine(
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),
        )
        apply_domain_score_override(engine)
        assert 0 <= engine.score <= MAX_SCORE

    def test_debian13_scenario(self):
        """8 raw deductions → 2/10 raw. With caps + domain average the score improves significantly."""
        engine = _make_engine(
            (1, "password_policy.no_quality_module"),
            (1, "hardening.rp_filter_disabled"),
            (1, "hardening.send_redirects_enabled"),
            (1, "kernel_hardening.ptrace_unrestricted"),
            (1, "backup.no_backup"),
            (1, "clamav.db_outdated"),
            (1, "rootkit.db_outdated"),
            (1, "rootkit.no_scan"),           # capped — rootkit already at 1
        )
        assert engine._raw_score == 2, "sanity check: raw score before override"
        apply_domain_score_override(engine)
        # domain average (hardening=4, disk=9) >> raw sum of 2
        assert engine.score > engine._raw_score
        assert engine.score >= 5


# ---------------------------------------------------------------------------
# render_domain_scores
# ---------------------------------------------------------------------------

class TestRenderDomainScores:
    def test_returns_list_of_strings(self):
        scores, _ = compute_domain_scores(_clean_engine())
        lines = render_domain_scores(scores)
        assert isinstance(lines, list)
        assert all(isinstance(l, str) for l in lines)

    def test_contains_all_domain_labels(self):
        from bob.domain_scores import LABELS
        scores, _ = compute_domain_scores(_clean_engine())
        combined = "\n".join(render_domain_scores(scores))
        for label in LABELS.values():
            assert label in combined

    def test_shows_score_fractions(self):
        scores, _ = compute_domain_scores(_clean_engine())
        combined = "\n".join(render_domain_scores(scores))
        assert "/10" in combined

    def test_custom_title_via_t(self):
        scores, _ = compute_domain_scores(_clean_engine())
        lines = render_domain_scores(scores, t=lambda k, **_: "MY TITLE" if k == "domain_scores.title" else k)
        assert any("MY TITLE" in l for l in lines)

    def test_bar_chars_present(self):
        scores, _ = compute_domain_scores(_clean_engine())
        combined = "\n".join(render_domain_scores(scores))
        assert "█" in combined

    def test_render_order_matches_domains(self):
        """Domain labels must appear in the canonical DOMAINS order."""
        from bob.domain_scores import LABELS
        scores, _ = compute_domain_scores(_clean_engine())
        lines = render_domain_scores(scores)
        # Find which line each domain's label first appears on
        positions = []
        for domain in DOMAINS:
            label = LABELS[domain]
            for i, line in enumerate(lines):
                if label in line:
                    positions.append(i)
                    break
        assert positions == sorted(positions), "Domain labels are not in canonical order"

    def test_render_partial_score_bar(self):
        """A non-max score must produce a bar with both filled and empty chars."""
        engine = _make_engine((5, "ssh.permit_root_login"))
        scores, _ = compute_domain_scores(engine)
        lines = render_domain_scores(scores)
        ssh_line = next(l for l in lines if "SSH" in l)
        assert "█" in ssh_line
        assert "░" in ssh_line


# ---------------------------------------------------------------------------
# CIS references in explain (Phase B2)
# ---------------------------------------------------------------------------

class TestCISReferences:
    def _make_t(self):
        from bob import i18n
        i18n.init(lang="en")
        return i18n.t

    def test_explain_cis_key_exists_for_ssh_password_auth(self):
        from bob.cis_refs import get_cis_ref
        val = get_cis_ref("ssh.password_auth")
        assert val is not None
        assert "CIS" in val and "." in val

    def test_explain_cis_key_exists_for_updates(self):
        from bob.cis_refs import get_cis_ref
        val = get_cis_ref("updates.security_pending")
        assert val is not None
        assert "CIS" in val and "." in val

    def test_explain_cis_key_exists_for_hardening(self):
        from bob.cis_refs import get_cis_ref
        val = get_cis_ref("hardening.rp_filter_disabled")
        assert val is not None
        assert "CIS" in val and "." in val

    def test_explain_cis_all_keys_resolve(self):
        """Every key in EXPLAIN_KEYS must have a CIS or best-practice reference."""
        from bob.explain import EXPLAIN_KEYS, normalize_key
        from bob.cis_refs import get_cis_ref
        for key in EXPLAIN_KEYS:
            norm = normalize_key(key)
            val = get_cis_ref(norm)
            assert val is not None, f"Missing CIS ref for key: {key!r}"
            assert val.startswith("CIS") or val.startswith("Best practice"), \
                f"Unexpected ref prefix for {key!r}: {val!r}"

    def test_explain_output_shows_cis_line_with_correct_key(self):
        from bob.explain import run_explain
        t = self._make_t()
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            run_explain("ssh.password_auth", t)
        finally:
            sys.stdout = old
        output = buf.getvalue()
        assert "CIS" in output
        assert "ssh.password_auth" in output   # key shown in header

    def test_explain_cis_locale_independent(self):
        """CIS refs come from cis_refs.json, not locale — same result in fr and en."""
        from bob.cis_refs import get_cis_ref
        val = get_cis_ref("hardening.redirects_enabled")
        assert val is not None
        assert "CIS" in val
        assert len(val) > 10


# ---------------------------------------------------------------------------
# --diff CLI flag (Phase B3)
# ---------------------------------------------------------------------------

class TestDiffCLI:
    def test_diff_flag_parsed(self):
        from bob.cli import parse_args
        cfg = parse_args(["--diff"])
        assert cfg.diff_mode

    def test_diff_flag_default_false(self):
        from bob.cli import parse_args
        cfg = parse_args([])
        assert not cfg.diff_mode



    def test_diff_with_verbose_flag(self):
        from bob.cli import parse_args
        cfg = parse_args(["--diff", "--verbose"])
        assert cfg.diff_mode
        assert cfg.verbose

    def test_diff_domain_scores_in_json(self):
        """domain_scores must appear in JSON output with correct structure."""
        from unittest.mock import MagicMock
        from bob.json_output import build_json_data

        engine = _clean_engine()

        sys_info = MagicMock()
        sys_info.hostname = "host"
        ports_snapshot = MagicMock()
        ports_snapshot.ports = []
        snapshots = []
        stack_snapshot = MagicMock()
        net_snapshot = MagicMock()
        net_snapshot.remote_ips = {}

        data = build_json_data(
            engine, sys_info, "private", "",
            snapshots, ports_snapshot,
            stack_snapshot, net_snapshot,
            full=False, version="1.9.0",
        )
        assert "domain_scores" in data
        # Structural validation: each entry must have score and label
        for d in DOMAINS:
            assert d in data["domain_scores"], f"Missing domain: {d}"
            entry = data["domain_scores"][d]
            assert "score" in entry, f"domain_scores.{d} missing 'score'"
            assert "label" in entry, f"domain_scores.{d} missing 'label'"
            assert 0 <= entry["score"] <= MAX_SCORE

    def test_diff_domain_scores_in_webhook_payload(self):
        """domain_scores must appear in generic webhook payload."""
        from bob.webhook import build_generic_payload
        from dataclasses import dataclass

        @dataclass
        class _SI:
            hostname: str = "host"

        engine = _clean_engine()
        payload = build_generic_payload(engine, _SI(), "1.9.0")
        assert "domain_scores" in payload
        for d in DOMAINS:
            assert d in payload["domain_scores"]
            assert 0 <= payload["domain_scores"][d] <= MAX_SCORE


# ---------------------------------------------------------------------------
# Scoring invariants
# ---------------------------------------------------------------------------

class TestScoringInvariants:
    """Structural invariants for the domain scoring pipeline."""

    def test_info_only_findings_do_not_activate_domain(self):
        """INFO findings with no deductions must not mark a domain as active."""
        engine = ScoreEngine()
        result = CheckResult()
        result.info(message="service installed", key="ssh.installed")
        engine.apply(result)
        engine.finalize()
        active = active_domains_from_engine(engine)
        assert "ssh" not in active

    def test_warn_finding_activates_domain(self):
        engine = ScoreEngine()
        result = CheckResult()
        result.warn(message="weak config", key="ssh.password_auth")
        engine.apply(result)
        engine.finalize()
        active = active_domains_from_engine(engine)
        assert "ssh" in active

    def test_alert_finding_activates_domain(self):
        engine = ScoreEngine()
        result = CheckResult()
        result.alert(message="root login allowed", key="ssh.permit_root_login")
        engine.apply(result)
        engine.finalize()
        active = active_domains_from_engine(engine)
        assert "ssh" in active

    def test_deduction_alone_activates_domain(self):
        """A deduction (no finding) still marks the corresponding domain active."""
        engine = ScoreEngine()
        result = CheckResult()
        result.add_deduction(reason="manual", points=2, key="updates.security_pending")
        engine.apply(result)
        engine.finalize()
        active = active_domains_from_engine(engine)
        assert "updates" in active

    def test_global_average_bounded_by_active_domain_scores(self):
        """Global average must lie within [min, max] of active domain scores."""
        engine = _make_engine(
            (2, "ssh.password_auth"),             # ssh: 8
            (4, "hardening.rp_filter_disabled"),  # hardening: 6
        )
        scores, _ = compute_domain_scores(engine)
        active = active_domains_from_engine(engine)
        global_score = compute_global_from_domains(scores, active)
        active_scores = [scores[d]["score"] for d in active if d in scores]
        assert min(active_scores) <= global_score <= max(active_scores)

    def test_all_domain_scores_in_valid_range(self):
        """Every domain score must always be in [0, MAX_SCORE]."""
        engine = _make_engine(*[(5, f"hardening.issue_{i}") for i in range(5)])
        scores, _ = compute_domain_scores(engine)
        for d in DOMAINS:
            assert 0 <= scores[d]["score"] <= MAX_SCORE, f"{d} score out of range"

    def test_compute_global_always_in_valid_range(self):
        """compute_global_from_domains must return a value in [0, MAX_SCORE]."""
        engine = _make_engine(*[
            (10, f"{pref}.issue") for pref in ["ssh", "updates", "hardening", "file_perms"]
        ])
        scores, _ = compute_domain_scores(engine)
        active = active_domains_from_engine(engine)
        result = compute_global_from_domains(scores, active)
        assert 0 <= result <= MAX_SCORE


# ---------------------------------------------------------------------------
# capped_indices — returned by compute_domain_scores(), cached on engine
# ---------------------------------------------------------------------------

class TestCappedIndices:
    def test_uncapped_deduction_not_in_indices(self):
        engine = _make_engine((1, "rootkit.db_outdated"))
        _, capped = compute_domain_scores(engine)
        assert 0 not in capped

    def test_fully_absorbed_deduction_in_indices(self):
        # rootkit cap=1: first 1pt passes, second is fully absorbed
        engine = _make_engine((1, "rootkit.db_outdated"), (1, "rootkit.no_scan"))
        _, capped = compute_domain_scores(engine)
        assert 0 not in capped
        assert 1 in capped

    def test_partially_absorbed_deduction_in_indices(self):
        # rootkit cap=1: first deduction is 2pt but only 1 counted → partial cap
        engine = _make_engine((2, "rootkit.db_outdated"))
        _, capped = compute_domain_scores(engine)
        assert 0 in capped

    def test_non_tool_cap_key_never_in_indices(self):
        # ssh has no tool cap → capped_indices is empty
        engine = _make_engine((3, "ssh.password_auth"), (3, "ssh.x11_forwarding"))
        _, capped = compute_domain_scores(engine)
        assert len(capped) == 0

    def test_cached_domain_scores_on_engine(self):
        engine = _make_engine((1, "ssh.password_auth"))
        apply_domain_score_override(engine)
        scores, _ = compute_domain_scores(engine)
        assert engine.domain_scores == scores
        assert "ssh" in engine.active_domains

    def test_engine_capped_indices_empty_before_override(self):
        engine = _make_engine((1, "ssh.password_auth"))
        engine.finalize()
        assert engine.domain_scores == {}
        assert engine.active_domains == frozenset()
        assert engine.capped_indices == frozenset()

    def test_engine_capped_indices_set_after_override(self):
        engine = _make_engine((2, "rootkit.db_outdated"))
        apply_domain_score_override(engine)
        assert 0 in engine.capped_indices
