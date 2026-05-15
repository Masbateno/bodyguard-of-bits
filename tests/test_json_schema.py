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
    return build_json_data(engine=engine, full=full, **minimal_args)


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
            engine=engine, full=True,
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
            engine=engine, full=True,
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
            engine=engine, full=True,
            hardening_snapshot=None,
            ipv6_snapshot=IPv6Snapshot(),
            **minimal_args,
        )
        assert "ipv6" in data
        assert isinstance(data["ipv6"], dict)

    def test_full_with_both_snapshots_does_not_crash(self, engine, minimal_args):
        """The real CLI path passes both snapshots at once."""
        data = build_json_data(
            engine=engine, full=True,
            hardening_snapshot=HardeningSnapshot(),
            ipv6_snapshot=IPv6Snapshot(),
            **minimal_args,
        )
        assert "hardening" in data
        assert "ipv6" in data
