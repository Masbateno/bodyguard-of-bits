"""
JSON output schema invariants — public API contract tests.

These tests guard the stable shape of `bob.json_output.build_json_data()`. Any
removal/rename of a top-level key, or breaking change to nested schemas, must
trigger a `schema_version` major bump.

Run with: python -m pytest tests/test_json_schema.py -v
"""

from __future__ import annotations

from datetime import datetime

import pytest

from bob.checks.firewall_stack import FirewallStackSnapshot
from bob.checks.hardening import HardeningSnapshot
from bob.checks.ipv6 import IPv6Snapshot
from bob.checks.network_context import NetworkContextSnapshot
from bob.checks.ports import PortsSnapshot
from bob.json_output import (
    SCHEMA_V1_FULL_KEYS,
    SCHEMA_V1_REQUIRED_KEYS,
    build_json_data,
)
from bob.report import SystemInfo
from bob.scoring import CheckResult, ScoreEngine


# ---------------------------------------------------------------------------
# Defense-in-depth: duplicate the schema contract here.
# If the production constants in bob/json_output.py drift, this list catches it.
# Keep these in sync with SCHEMA_V1_REQUIRED_KEYS / SCHEMA_V1_FULL_KEYS — but
# that is the WHOLE POINT: a deliberate mismatch must surface here.
# ---------------------------------------------------------------------------

EXPECTED_REQUIRED_KEYS_V1 = frozenset({
    "schema_version",
    "version",
    "host",
    "timestamp",
    "score",
    "score_max",
    "risk",
    "network_context",
    "public_ip",
    "alerts",
    "warnings",
    "deductions",
    "domain_scores",
})

EXPECTED_FULL_KEYS_V1 = frozenset({
    "findings",
    "services",
    "open_ports",
    "firewall_stack",
    "hardening",
    "ipv6",
})


# ---------------------------------------------------------------------------
# Fixtures — real objects, no MagicMock.
#
# Why no MagicMock? It auto-invents attributes. If `build_json_data` starts
# accessing `sys_info.fqdn` instead of `sys_info.hostname`, MagicMock returns
# a Mock instance and the test silently passes. Real classes raise
# AttributeError, which is what we want.
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
def engine() -> ScoreEngine:
    """Engine with one finding + one deduction so serialization paths execute."""
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
def minimal_args() -> dict:
    """
    Minimum args to call build_json_data() without crashing.

    Uses real BOB dataclasses with empty defaults, NOT MagicMock — so any
    attribute renamed in the production code raises AttributeError instead
    of a silent pass.
    """
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


def _build(engine: ScoreEngine, minimal_args: dict, full: bool = False) -> dict:
    """v0.7.0: this file pins v1 baseline contract; we pass schema_version="1"
    explicitly so the v2 default (post-Step 3) does not shift these tests."""
    return build_json_data(engine=engine, full=full, schema_version="1", **minimal_args)


# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------

class TestSchemaVersion:
    def test_schema_version_is_string(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        assert isinstance(data["schema_version"], str)

    def test_schema_version_is_v1(self, engine, minimal_args):
        """Schema is currently v1. Bumping to v2 = explicit breaking change."""
        data = _build(engine, minimal_args)
        assert data["schema_version"] == "1"


# ---------------------------------------------------------------------------
# Top-level required keys (always present, full or not)
# ---------------------------------------------------------------------------

class TestRequiredKeysAlwaysPresent:
    def test_short_mode_has_all_required(self, engine, minimal_args):
        data = _build(engine, minimal_args, full=False)
        missing = SCHEMA_V1_REQUIRED_KEYS - set(data.keys())
        assert not missing, f"Schema v1 contract broken: missing keys {missing}"

    def test_full_mode_has_all_required(self, engine, minimal_args):
        data = _build(engine, minimal_args, full=True)
        missing = SCHEMA_V1_REQUIRED_KEYS - set(data.keys())
        assert not missing, f"Schema v1 contract broken: missing keys {missing}"

    def test_short_mode_has_no_full_keys(self, engine, minimal_args):
        data = _build(engine, minimal_args, full=False)
        leaked = SCHEMA_V1_FULL_KEYS & set(data.keys())
        assert not leaked, f"Full-only keys leaked into short mode: {leaked}"

    def test_full_mode_has_full_keys(self, engine, minimal_args):
        data = _build(engine, minimal_args, full=True)
        # `hardening` and `ipv6` are conditional on snapshots being passed —
        # they are NOT present here. The other 4 must be.
        always_in_full = SCHEMA_V1_FULL_KEYS - {"hardening", "ipv6"}
        missing = always_in_full - set(data.keys())
        assert not missing, f"Full-mode missing keys: {missing}"

    def test_short_mode_strict_set(self, engine, minimal_args):
        """
        Strict short mode contract: NOTHING beyond the required keys.
        Adding a new key without bumping the schema_version is a contract leak.
        """
        data = _build(engine, minimal_args, full=False)
        unexpected = set(data.keys()) - EXPECTED_REQUIRED_KEYS_V1
        assert not unexpected, (
            f"Unexpected keys leaked into short mode: {unexpected}. "
            "Either remove them, or move them under full=True, or bump schema_version."
        )

    def test_constants_match_expected_set(self):
        """
        Defense in depth: production constants must match the test's hard-coded
        expectation. If someone edits SCHEMA_V1_REQUIRED_KEYS without thinking
        of the contract, this test surfaces the change immediately.
        """
        assert SCHEMA_V1_REQUIRED_KEYS == EXPECTED_REQUIRED_KEYS_V1, (
            "Production constant drift. "
            "If this is intentional, update both in the same commit."
        )
        assert SCHEMA_V1_FULL_KEYS == EXPECTED_FULL_KEYS_V1, (
            "Production constant drift. "
            "If this is intentional, update both in the same commit."
        )


# ---------------------------------------------------------------------------
# Field types — guard against accidental type drift
# ---------------------------------------------------------------------------

class TestFieldTypes:
    def test_score_is_int(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        assert isinstance(data["score"], int)

    def test_score_max_is_int(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        assert isinstance(data["score_max"], int) and data["score_max"] == 10

    def test_alerts_warnings_are_int(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        assert isinstance(data["alerts"], int)
        assert isinstance(data["warnings"], int)

    def test_risk_is_string(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        assert isinstance(data["risk"], str)

    def test_timestamp_is_iso8601(self, engine, minimal_args):
        """
        Strict ISO 8601 parse — much stronger than a substring check.
        Python 3.11+ accepts the full ISO 8601 grammar including timezone.
        """
        data = _build(engine, minimal_args)
        ts = data["timestamp"]
        assert isinstance(ts, str)
        parsed = datetime.fromisoformat(ts)  # raises ValueError on bad input
        assert parsed.tzinfo is not None, "timestamp must include a timezone"


# ---------------------------------------------------------------------------
# Deductions and findings carry stable `key` field for client matching
# ---------------------------------------------------------------------------

class TestStableKeysExposed:
    def test_each_deduction_has_key_field(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        for d in data["deductions"]:
            assert "key" in d, "Deduction must expose stable i18n key for client matching"
            assert isinstance(d["key"], str)

    def test_each_finding_has_key_field(self, engine, minimal_args):
        data = _build(engine, minimal_args, full=True)
        for f in data["findings"]:
            assert "key" in f, "Finding must expose stable i18n key for client matching"
            assert isinstance(f["key"], str)

    def test_deduction_keys_are_dotted_paths(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        for d in data["deductions"]:
            if d["key"]:  # may be empty for legacy/uncategorized deductions
                assert "." in d["key"], f"Key {d['key']!r} should be dotted"

    def test_each_deduction_has_template_vars_field(self, engine, minimal_args):
        """v0.4.1+: every deduction exposes `template_vars` (dict, may be empty)."""
        data = _build(engine, minimal_args)
        for d in data["deductions"]:
            assert "template_vars" in d, (
                "Deduction must expose template_vars for locale-independent "
                "reconstruction (Phase 2 contract). Empty dict is OK for legacy checks."
            )
            assert isinstance(d["template_vars"], dict)

    def test_each_finding_has_template_vars_field(self, engine, minimal_args):
        """v0.4.1+: every finding exposes `template_vars` (dict, may be empty)."""
        data = _build(engine, minimal_args, full=True)
        for f in data["findings"]:
            assert "template_vars" in f
            assert isinstance(f["template_vars"], dict)


# ---------------------------------------------------------------------------
# Domain scores structure — already tested in test_domain_scores.py but
# we add a redundant guard here for the schema contract.
# ---------------------------------------------------------------------------

class TestDomainScoresStructure:
    def test_domain_scores_is_dict_of_dicts(self, engine, minimal_args):
        data = _build(engine, minimal_args)
        assert isinstance(data["domain_scores"], dict)
        for domain, entry in data["domain_scores"].items():
            assert isinstance(domain, str)
            assert isinstance(entry, dict)
            assert "score" in entry
            assert "label" in entry
            assert isinstance(entry["score"], int)
            assert isinstance(entry["label"], str)


# ---------------------------------------------------------------------------
# --json-full + optional snapshots (hardening, ipv6) — regression for v0.4.2
# where build_json_data crashed with AttributeError because the "hardening"
# block read attributes that had migrated out of HardeningSnapshot (fail2ban,
# auto_updates, apparmor_*) when AppArmor moved to mac_policy.py. The minimal
# fixtures above did not exercise the full+hardening_snapshot path.
# ---------------------------------------------------------------------------

class TestFullModeWithOptionalSnapshots:
    def test_full_with_hardening_snapshot_does_not_crash(self, engine, minimal_args):
        """build_json_data must not raise when given full=True + a default HardeningSnapshot."""
        data = build_json_data(
            engine=engine, full=True, schema_version="1",
            hardening_snapshot=HardeningSnapshot(),
            ipv6_snapshot=None,
            **minimal_args,
        )
        assert "hardening" in data
        assert isinstance(data["hardening"], dict)

    def test_full_with_hardening_keys_match_dataclass_attrs(self, engine, minimal_args):
        """Every key in data["hardening"] must correspond to a real attribute of
        the live HardeningSnapshot. Catches the v0.4.2 class of regression
        (key removed from dataclass but still read by json_output)."""
        snap = HardeningSnapshot()
        data = build_json_data(
            engine=engine, full=True, schema_version="1",
            hardening_snapshot=snap, ipv6_snapshot=None,
            **minimal_args,
        )
        for key in data["hardening"]:
            assert hasattr(snap, key), (
                f"json_output.py exposes 'hardening.{key}' but HardeningSnapshot "
                f"has no such attribute — likely a leftover after a refactor."
            )

    def test_full_with_ipv6_snapshot_does_not_crash(self, engine, minimal_args):
        """Same regression guard for ipv6 block."""
        data = build_json_data(
            engine=engine, full=True, schema_version="1",
            hardening_snapshot=None,
            ipv6_snapshot=IPv6Snapshot(),
            **minimal_args,
        )
        assert "ipv6" in data
        assert isinstance(data["ipv6"], dict)

    def test_full_with_both_snapshots_does_not_crash(self, engine, minimal_args):
        """The real CLI path passes both snapshots at once."""
        data = build_json_data(
            engine=engine, full=True, schema_version="1",
            hardening_snapshot=HardeningSnapshot(),
            ipv6_snapshot=IPv6Snapshot(),
            **minimal_args,
        )
        assert "hardening" in data
        assert "ipv6" in data


# ---------------------------------------------------------------------------
# v0.7.0 Phase 2 — Pin v1 baseline behavior before introducing schema v2
#
# These tests document the CURRENT v1 contract — including the pain points
# (P1, P3) that drive the v2 migration. They run green on today's code base
# and will need to be either:
#   (a) adapted to test the --json-v1 flag explicitly when v2 lands, OR
#   (b) retired with a note that they pinned the legacy contract.
#
# This is Step 1 of the integration-first sequence per project_v07x_phase1
# strategy rule 1. Step 2 = TestSchemaV2Default in a new test file.
# ---------------------------------------------------------------------------

class TestSchemaV1BaselineGaps:
    """Pin the v1 oddities + missing fields that v2 must address."""

    # ---- P1 — network_context type inconsistency ---------------------------
    def test_v1_network_context_is_string_in_short_mode(self, engine, minimal_args):
        """Pre-v2 baseline: ``network_context`` is a string at top-level in
        short mode (the value of the constant context detection — "private",
        "public", "ddns"). v2 (A-2) will make it always a dict for type-safety
        in JSON consumers."""
        data = _build(engine, minimal_args, full=False)
        assert isinstance(data["network_context"], str)

    def test_v1_network_context_overwritten_to_dict_in_full_mode(self, engine, minimal_args):
        """Pre-v2 baseline: same ``network_context`` key gets overwritten to
        a dict in full mode (interfaces + connections_count + top_remote_ips).
        Two different types under one key based on a flag — exactly the bug
        v2 A-2 will fix."""
        data = _build(engine, minimal_args, full=True)
        assert isinstance(data["network_context"], dict)
        assert "interfaces" in data["network_context"]

    # ---- P3 — no posture_escalation field exposed --------------------------
    def test_v1_short_has_no_posture_escalation_field(self, engine, minimal_args):
        """Pre-v2 baseline: posture escalation is computed in Phase 1 commit
        e3d998f and CHANGES the value of ``risk`` field (now effective_level),
        but the escalation context (applied? reason? raw score_level?) is NOT
        exposed in v1 JSON. v2 A-4 will add a top-level ``posture_escalation``
        block."""
        data = _build(engine, minimal_args, full=False)
        assert "posture_escalation" not in data

    def test_v1_full_has_no_posture_escalation_field(self, engine, minimal_args):
        data = _build(engine, minimal_args, full=True)
        assert "posture_escalation" not in data

    # ---- P2 — risk field value semantics (Phase 1 silently shifted) --------
    def test_v1_risk_is_one_of_canonical_values(self, engine, minimal_args):
        """Pre-v2 baseline: ``risk`` ∈ {low, medium, high, critical}. v2 keeps
        the same enum (no value added/removed) but documents that since Phase
        1 (commit e3d998f) the value comes from ``effective_level`` rather
        than the raw score-derived ``level``."""
        data = _build(engine, minimal_args)
        assert data["risk"] in {"low", "medium", "high", "critical"}

    # ---- B-3 / B-7 baseline pins (current short-form fields) ---------------
    #
    # B-2 (firewall_stack bypass field rename) was retired from T2 scope
    # during Step 1: ``input_bypasses`` / ``forward_bypasses`` are actually
    # lists of rule descriptions, not int counts, so the plural naming is
    # already correct. No rename needed.

    def test_v1_firewall_stack_bypasses_are_lists(self, engine, minimal_args):
        """Pre-v2 baseline (correctly named, retained as-is in v2):
        ``firewall_stack.input_bypasses`` / ``forward_bypasses`` are lists
        of rule descriptions, not counts."""
        data = _build(engine, minimal_args, full=True)
        fs = data["firewall_stack"]
        assert isinstance(fs["input_bypasses"], list)
        assert isinstance(fs["forward_bypasses"], list)

    def test_v1_timestamp_field_has_no_utc_marker(self, engine, minimal_args):
        """Pre-v2 baseline: ``timestamp`` is UTC-encoded but the name doesn't
        say so. v2 B-3 will rename to ``timestamp_utc`` or add a sibling
        timezone field."""
        data = _build(engine, minimal_args)
        assert "timestamp" in data
        assert "timestamp_utc" not in data
        assert "timezone" not in data

    def test_v1_has_no_info_count(self, engine, minimal_args):
        """Pre-v2 baseline: only ``alerts`` and ``warnings`` counts are
        exposed. v2 B-7 will add ``info_count`` for symmetry with the
        FindingLevel enum."""
        data = _build(engine, minimal_args)
        assert "alerts" in data
        assert "warnings" in data
        assert "info_count" not in data
        assert "infos" not in data

    def test_v1_no_deductions_raw_field(self, engine, minimal_args):
        """Pre-v2 baseline: ``deductions`` filters ``points > 0`` (skips
        synthetic zero-point caps). v2 B-4 will add ``deductions_raw`` in
        full mode for consumers that want every entry."""
        data = _build(engine, minimal_args, full=True)
        assert "deductions" in data
        assert "deductions_raw" not in data

    def test_v1_no_open_ports_all_field(self, engine, minimal_args):
        """Pre-v2 baseline: ``open_ports`` filters ``is_all_interfaces``
        (skips localhost). v2 B-5 will add ``open_ports_all`` in full mode."""
        data = _build(engine, minimal_args, full=True)
        assert "open_ports" in data
        assert "open_ports_all" not in data

    def test_v1_domain_scores_no_deductions_count(self, engine, minimal_args):
        """Pre-v2 baseline: ``domain_scores[d]`` exposes only ``{score, label}``.
        v2 B-6 will add ``deductions`` (the int count already computed
        internally by compute_domain_scores)."""
        data = _build(engine, minimal_args)
        for domain, entry in data["domain_scores"].items():
            assert set(entry.keys()) == {"score", "label"}, (
                f"v1 domain_scores[{domain!r}] must have exactly score+label keys, "
                f"got {set(entry.keys())}"
            )
