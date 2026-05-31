"""
JSON output schema v2 — integration-first test suite that DRIVES the v2
implementation.

These tests are written BEFORE the v2 production code lands. They will fail
on today's code base. As Sub-scope A / B / C of T2 are implemented, the
relevant test classes progressively turn green.

Step 2 of the integration-first sequence per project_v07x_phase1 strategy
rule 1. Step 1 = TestSchemaV1BaselineGaps in tests/test_json_schema.py.

Contract owners:
  - Sub-scope A (schema v2 + posture + network_context fix + --json-v1 flag)
        TestSchemaV2DefaultRequiredKeys
        TestSchemaV2NetworkContextAlwaysDict
        TestSchemaV2PostureEscalationBlock
        TestJsonV1FlagBackwardCompat
  - Sub-scope B (naming cleanup B-3, B-4, B-5, B-6, B-7)
        TestSchemaV2NamingCleanup
  - Sub-scope C (EXPLAIN_KEYS rationalization — non-JSON, see test_explain*)

B-2 (firewall_stack bypass rename) was retired during Step 1 — pluriel naming
was correct (lists not int counts).

Run with: python -m pytest tests/test_json_schema_v2.py -v
"""

from __future__ import annotations

import pytest

from bob.checks.firewall_stack import FirewallStackSnapshot
from bob.checks.hardening import HardeningSnapshot
from bob.checks.ipv6 import IPv6Snapshot
from bob.checks.network_context import NetworkContextSnapshot
from bob.checks.ports import PortsSnapshot
from bob.json_output import build_json_data
from bob.report import SystemInfo
from bob.scoring import CheckResult, ScoreEngine


# ---------------------------------------------------------------------------
# v2 contract constants — to be added in production at Step 3 (A-1).
#
# We hardcode them here so the test suite knows what to expect even before
# bob.json_output exposes them. After A-1 lands, these can be replaced by
# `from bob.json_output import SCHEMA_V2_REQUIRED_KEYS, ...`.
# ---------------------------------------------------------------------------

EXPECTED_REQUIRED_KEYS_V2 = frozenset({
    "schema_version",
    "version",
    "host",
    "timestamp_utc",          # B-3 renamed from "timestamp"
    "score",
    "score_max",
    "risk",
    "network_context",        # now always dict (P1 fix, A-2)
    "public_ip",
    "alerts",
    "warnings",
    "info_count",             # B-7 added for symmetry
    "deductions",
    "domain_scores",
    "posture_escalation",     # A-4 new block exposing escalation context
})

EXPECTED_FULL_KEYS_V2 = frozenset({
    "findings",
    "services",
    "open_ports",
    "open_ports_all",         # B-5 added (sans filtre is_all_interfaces)
    "firewall_stack",
    "deductions_raw",         # B-4 added (sans filtre points > 0)
    "hardening",
    "ipv6",
})


# ---------------------------------------------------------------------------
# Fixtures — real objects, no MagicMock (rationale: see test_json_schema.py).
# ---------------------------------------------------------------------------

def _make_sys_info() -> SystemInfo:
    return SystemInfo(
        os_name="Test Linux",
        hostname="test-host",
        kernel="0.0.0",
        ufw_version="0.0.0",
        iptables_version="0.0.0",
        nftables_version="0.0.0",
        user="tester",
        config_path="/dev/null",
        language="en",
        version="0.0.0-test",
    )


@pytest.fixture
def engine_clean() -> ScoreEngine:
    """Engine with no posture issue — used to test the non-escalated path."""
    eng = ScoreEngine()
    result = CheckResult()
    result.warn(
        message="UFW logging is off",
        nature="action",
        cmd="sudo ufw logging low",
        key="firewall.logging_off",
    )
    result.add_deduction(
        reason="UFW logging is off",
        points=2,
        context="local",
        key="firewall.logging_off",
    )
    eng.apply(result)
    return eng


@pytest.fixture
def engine_firewall_inactive() -> ScoreEngine:
    """Engine with firewall.inactive — posture escalation must apply."""
    eng = ScoreEngine()
    eng.finalize()
    eng.set_posture(firewall_inactive=True)
    return eng


@pytest.fixture
def minimal_args() -> dict:
    return {
        "sys_info": _make_sys_info(),
        "network_context": "private",
        "public_ip": "",
        "snapshots": [],
        "ports_snapshot": PortsSnapshot(ports=[], ufw_rules="", ss_output=""),
        "stack_snapshot": FirewallStackSnapshot(),
        "net_snapshot": NetworkContextSnapshot(),
        "version": "0.0.0-test",
    }


def _build_v2(engine: ScoreEngine, minimal_args: dict, full: bool = False) -> dict:
    """Build v2 output explicitly. Default schema_version is v2 in production
    after A-1 lands; we still pass it explicitly here for self-documentation."""
    return build_json_data(engine=engine, full=full, schema_version="2", **minimal_args)


def _build_v1(engine: ScoreEngine, minimal_args: dict, full: bool = False) -> dict:
    """Build v1 output for backward-compat tests (--json-v1 flag)."""
    return build_json_data(engine=engine, full=full, schema_version="1", **minimal_args)


# ===========================================================================
# A-1 + general v2 contract
# ===========================================================================

class TestSchemaV2DefaultRequiredKeys:
    """v2 default = schema_version=2 + extended top-level key set."""

    def test_schema_version_is_string_2(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        assert data["schema_version"] == "2"

    def test_v2_short_mode_has_all_required(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        missing = EXPECTED_REQUIRED_KEYS_V2 - set(data.keys())
        assert not missing, f"v2 short mode missing keys: {missing}"

    def test_v2_short_mode_strict_set(self, engine_clean, minimal_args):
        """No leak of full-only keys nor undocumented keys in short mode."""
        data = _build_v2(engine_clean, minimal_args)
        unexpected = set(data.keys()) - EXPECTED_REQUIRED_KEYS_V2
        assert not unexpected, (
            f"v2 short mode has undocumented keys: {unexpected}. "
            f"Either remove them or move to full=True."
        )

    def test_v2_full_mode_adds_full_keys(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args, full=True)
        # hardening + ipv6 are conditional — verified separately below
        always_in_full = EXPECTED_FULL_KEYS_V2 - {"hardening", "ipv6"}
        missing = always_in_full - set(data.keys())
        assert not missing, f"v2 full mode missing keys: {missing}"


# ===========================================================================
# A-2 — network_context always dict (fixes P1 type-inconsistency)
# ===========================================================================

class TestSchemaV2NetworkContextAlwaysDict:
    """The same key never changes type based on a flag."""

    def test_v2_network_context_is_dict_in_short_mode(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args, full=False)
        assert isinstance(data["network_context"], dict)

    def test_v2_network_context_has_label_in_short_mode(self, engine_clean, minimal_args):
        """Short mode dict carries the canonical context string under a field
        so consumers don't lose the v1 info."""
        data = _build_v2(engine_clean, minimal_args, full=False)
        assert "context" in data["network_context"]
        assert data["network_context"]["context"] in {"local", "private", "public", "ddns"}

    def test_v2_network_context_is_dict_in_full_mode(self, engine_clean, minimal_args):
        """Full mode retains the v1 enriched fields (interfaces etc.) plus
        the new context label."""
        data = _build_v2(engine_clean, minimal_args, full=True)
        nc = data["network_context"]
        assert isinstance(nc, dict)
        assert "context" in nc
        assert "interfaces" in nc
        assert "connections_count" in nc

    def test_v2_network_context_same_type_short_vs_full(self, engine_clean, minimal_args):
        """The fix point of P1: same type regardless of --json-full."""
        short = _build_v2(engine_clean, minimal_args, full=False)
        full = _build_v2(engine_clean, minimal_args, full=True)
        assert type(short["network_context"]) is type(full["network_context"])


# ===========================================================================
# A-4 — posture_escalation block exposed
# ===========================================================================

class TestSchemaV2PostureEscalationBlock:
    """Posture escalation context surfaced in JSON output."""

    def test_v2_posture_escalation_present_when_clean(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        assert "posture_escalation" in data
        pe = data["posture_escalation"]
        assert isinstance(pe, dict)
        # Required sub-fields
        assert "applied" in pe
        assert "reason_key" in pe
        assert "score_level" in pe

    def test_v2_posture_escalation_clean_engine_has_applied_false(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        pe = data["posture_escalation"]
        assert pe["applied"] is False
        assert pe["reason_key"] is None

    def test_v2_posture_escalation_score_level_is_valid_enum(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        pe = data["posture_escalation"]
        assert pe["score_level"] in {"low", "medium", "high", "critical"}

    def test_v2_posture_escalation_firewall_inactive(
            self, engine_firewall_inactive, minimal_args):
        """Firewall inactive must escalate from LOW → HIGH and surface the reason."""
        data = _build_v2(engine_firewall_inactive, minimal_args)
        pe = data["posture_escalation"]
        assert pe["applied"] is True
        assert pe["reason_key"] == "scoring.posture.firewall_inactive"
        # Engine had no deductions → score-derived level = LOW
        assert pe["score_level"] == "low"
        # Top-level risk reflects escalated value
        assert data["risk"] == "high"

    def test_v2_posture_escalation_consistent_with_top_level_risk(
            self, engine_firewall_inactive, minimal_args):
        """The top-level ``risk`` is the escalated/effective level, and the
        block ``score_level`` is the un-escalated baseline. They diverge
        whenever ``applied=True`` and converge when ``applied=False``.

        I-5 (v0.7.0 Phase 2.1): pre-fix the ``applied`` branch had
        ``assert ... or True`` which made the assertion vacuous. The
        engine_firewall_inactive fixture has no deductions so score is at
        MAX (LOW) and posture lifts to HIGH — the values always diverge.
        Pin that explicit shape here."""
        data = _build_v2(engine_firewall_inactive, minimal_args)
        pe = data["posture_escalation"]
        if pe["applied"]:
            # Fixture is firewall_inactive with no deductions → score = LOW,
            # posture → HIGH. Top-level risk reflects effective (HIGH).
            assert data["risk"] == "high"
            assert pe["score_level"] == "low"
            assert data["risk"] != pe["score_level"]
        else:
            assert data["risk"] == pe["score_level"]


# ===========================================================================
# A-5 — --json-v1 flag preserves v1 output exactly
# ===========================================================================

class TestJsonV1FlagBackwardCompat:
    """Backward compatibility: legacy consumers can pin v1 explicitly."""

    def test_v1_flag_emits_schema_version_1(self, engine_clean, minimal_args):
        data = _build_v1(engine_clean, minimal_args)
        assert data["schema_version"] == "1"

    def test_v1_flag_network_context_still_string_in_short(
            self, engine_clean, minimal_args):
        """v1 quirk preserved: network_context is a string at top-level in
        short mode."""
        data = _build_v1(engine_clean, minimal_args, full=False)
        assert isinstance(data["network_context"], str)

    def test_v1_flag_no_posture_escalation_block(self, engine_clean, minimal_args):
        """v1 had no posture_escalation field — must remain absent."""
        data = _build_v1(engine_clean, minimal_args)
        assert "posture_escalation" not in data

    def test_v1_flag_no_info_count(self, engine_clean, minimal_args):
        data = _build_v1(engine_clean, minimal_args)
        assert "info_count" not in data
        assert "infos" not in data

    def test_v1_flag_timestamp_not_renamed(self, engine_clean, minimal_args):
        data = _build_v1(engine_clean, minimal_args)
        assert "timestamp" in data
        assert "timestamp_utc" not in data

    def test_v1_flag_no_deductions_raw(self, engine_clean, minimal_args):
        data = _build_v1(engine_clean, minimal_args, full=True)
        assert "deductions" in data
        assert "deductions_raw" not in data

    def test_v1_flag_no_open_ports_all(self, engine_clean, minimal_args):
        data = _build_v1(engine_clean, minimal_args, full=True)
        assert "open_ports" in data
        assert "open_ports_all" not in data

    def test_v1_flag_domain_scores_score_and_label_only(self, engine_clean, minimal_args):
        data = _build_v1(engine_clean, minimal_args)
        for entry in data["domain_scores"].values():
            assert set(entry.keys()) == {"score", "label"}


# ===========================================================================
# Sub-scope B — naming cleanup additions
# ===========================================================================

class TestSchemaV2NamingCleanup:
    """B-3 / B-4 / B-5 / B-6 / B-7 — additive field changes."""

    # B-3 — timestamp_utc rename
    def test_v2_timestamp_utc_field_present(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        assert "timestamp_utc" in data
        # Implementation detail: still ISO 8601 with timezone, but the field
        # name now signals UTC explicitly.
        assert isinstance(data["timestamp_utc"], str)
        assert data["timestamp_utc"].endswith("+00:00") or data["timestamp_utc"].endswith("Z")

    def test_v2_timestamp_legacy_field_removed(self, engine_clean, minimal_args):
        """Legacy ``timestamp`` removed in v2 — v1 consumers must use --json-v1."""
        data = _build_v2(engine_clean, minimal_args)
        assert "timestamp" not in data

    # B-4 — deductions_raw added
    def test_v2_deductions_raw_in_full(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args, full=True)
        assert "deductions_raw" in data
        assert isinstance(data["deductions_raw"], list)

    def test_v2_deductions_filtered_keeps_v1_semantics(self, engine_clean, minimal_args):
        """The classical ``deductions`` field keeps its v1 ``points > 0`` filter
        for direct migration. ``deductions_raw`` exposes the unfiltered set."""
        data = _build_v2(engine_clean, minimal_args, full=True)
        for d in data["deductions"]:
            assert d["points"] > 0, (
                "deductions[] must keep its v1 points>0 filter; "
                "use deductions_raw for the unfiltered set"
            )

    # B-5 — open_ports_all added
    def test_v2_open_ports_all_in_full(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args, full=True)
        assert "open_ports_all" in data
        assert isinstance(data["open_ports_all"], list)

    # B-6 — domain_scores[d].deductions exposed
    def test_v2_domain_scores_includes_deductions_count(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        for domain, entry in data["domain_scores"].items():
            assert "deductions" in entry, (
                f"v2 domain_scores[{domain!r}] must expose 'deductions' (int count) "
                f"in addition to score+label"
            )
            assert isinstance(entry["deductions"], int)
            assert "score" in entry
            assert "label" in entry

    # B-7 — info_count top-level
    def test_v2_info_count_present(self, engine_clean, minimal_args):
        data = _build_v2(engine_clean, minimal_args)
        assert "info_count" in data
        assert isinstance(data["info_count"], int)
        assert data["info_count"] >= 0


# ===========================================================================
# Validation parameter — defensive type guard (per strategy rule 2)
# ===========================================================================

class TestSchemaVersionValidation:
    """build_json_data must reject unknown schema_version values cleanly."""

    def test_unknown_schema_version_raises_valueerror(self, engine_clean, minimal_args):
        with pytest.raises(ValueError):
            build_json_data(
                engine=engine_clean, full=False,
                schema_version="999",
                **minimal_args,
            )

    def test_non_string_schema_version_raises_typeerror(self, engine_clean, minimal_args):
        with pytest.raises(TypeError):
            build_json_data(
                engine=engine_clean, full=False,
                schema_version=2,  # int — must be str
                **minimal_args,
            )
