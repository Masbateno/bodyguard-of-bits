"""
Unit tests for bob.compare module.

Tests cover: baseline build, save/load round-trip, delta computation,
display routing, and edge cases.

Run with: python -m pytest tests/test_compare.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from bob.compare import (
    AuditBaseline,
    AuditDelta,
    build_baseline,
    compute_delta,
    display_delta,
    load_baseline,
    save_baseline,
)
from tests.helpers import _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_delta(**overrides) -> AuditDelta:
    """Build an AuditDelta with all-zero/empty defaults for focused testing."""
    defaults = dict(
        prev_timestamp="2026-01-01T00:00:00+00:00",
        score_delta=0, alert_delta=0, warn_delta=0, info_delta=0,
        new_ports=[], closed_ports=[],
        new_services=[], stopped_services=[],
    )
    defaults.update(overrides)
    return AuditDelta(**defaults)


def make_baseline(**overrides) -> AuditBaseline:
    defaults = dict(
        timestamp="2026-01-01T00:00:00+00:00",
        score=9,
        alert_count=0,
        warn_count=1,
        info_count=2,
        open_ports=["22/tcp", "80/tcp"],
        active_services=["sshd", "nginx"],
    )
    defaults.update(overrides)
    return AuditBaseline(**defaults)


def make_engine(score=9, alert_count=0, warn_count=1, info_count=0):
    return SimpleNamespace(
        score=score,
        alert_count=alert_count,
        warn_count=warn_count,
        info_count=info_count,
        findings=[],
        breakdown=[],
    )


def make_ports_snapshot(port_protos: list[str]):
    """Build a fake PortsSnapshot with is_all_interfaces ports."""
    ports = [
        SimpleNamespace(port_proto=pp, is_all_interfaces=True)
        for pp in port_protos
    ]
    return SimpleNamespace(ports=ports)


def make_snapshots(active_labels: list[str]):
    """Build a list of fake ServiceSnapshot objects."""
    return [
        SimpleNamespace(
            installed=True,
            service=SimpleNamespace(label=label),
            state=SimpleNamespace(is_active=True),
        )
        for label in active_labels
    ]


# ---------------------------------------------------------------------------
# build_baseline
# ---------------------------------------------------------------------------

class TestBuildBaseline:
    def test_score_copied(self):
        engine = make_engine(score=8)
        bl = build_baseline(engine, make_ports_snapshot([]), make_snapshots([]))
        assert bl.score == 8

    def test_alert_count_copied(self):
        engine = make_engine(alert_count=2)
        bl = build_baseline(engine, make_ports_snapshot([]), make_snapshots([]))
        assert bl.alert_count == 2

    def test_warn_count_copied(self):
        engine = make_engine(warn_count=3)
        bl = build_baseline(engine, make_ports_snapshot([]), make_snapshots([]))
        assert bl.warn_count == 3

    def test_open_ports_extracted(self):
        engine = make_engine()
        bl = build_baseline(engine, make_ports_snapshot(["22/tcp", "443/tcp"]), make_snapshots([]))
        assert "22/tcp" in bl.open_ports
        assert "443/tcp" in bl.open_ports

    def test_open_ports_sorted(self):
        engine = make_engine()
        bl = build_baseline(engine, make_ports_snapshot(["80/tcp", "22/tcp"]), make_snapshots([]))
        assert bl.open_ports == sorted(bl.open_ports)

    def test_active_services_extracted(self):
        engine = make_engine()
        bl = build_baseline(engine, make_ports_snapshot([]), make_snapshots(["sshd", "nginx"]))
        assert "sshd" in bl.active_services
        assert "nginx" in bl.active_services

    def test_ephemeral_ports_excluded(self):
        """Ports >= 32768 must not appear in the baseline (too noisy)."""
        engine = make_engine()
        bl = build_baseline(
            engine,
            make_ports_snapshot(["22/tcp", "32768/udp", "50000/udp", "443/tcp"]),
            make_snapshots([]),
        )
        assert "22/tcp" in bl.open_ports
        assert "443/tcp" in bl.open_ports
        assert "32768/udp" not in bl.open_ports
        assert "50000/udp" not in bl.open_ports

    def test_stable_ports_included(self):
        """Ports just below 32768 must be included."""
        engine = make_engine()
        bl = build_baseline(
            engine,
            make_ports_snapshot(["32767/udp"]),
            make_snapshots([]),
        )
        assert "32767/udp" in bl.open_ports

    def test_timestamp_is_set(self):
        engine = make_engine()
        bl = build_baseline(engine, make_ports_snapshot([]), make_snapshots([]))
        assert bl.timestamp  # non-empty

    def test_deduplicates_ports(self):
        """Duplicate port entries (IPv4 + IPv6 both on 0.0.0.0/::) must appear once."""
        ports = [SimpleNamespace(port_proto="22/tcp", is_all_interfaces=True)] * 3
        snap = SimpleNamespace(ports=ports)
        bl = build_baseline(make_engine(), snap, [])
        assert bl.open_ports.count("22/tcp") == 1

    def test_non_all_interfaces_port_excluded(self):
        """Ports bound to loopback only (is_all_interfaces=False) must not appear."""
        ports = [
            SimpleNamespace(port_proto="22/tcp", is_all_interfaces=True),
            SimpleNamespace(port_proto="9090/tcp", is_all_interfaces=False),
        ]
        snap = SimpleNamespace(ports=ports)
        bl = build_baseline(make_engine(), snap, [])
        assert "22/tcp" in bl.open_ports
        assert "9090/tcp" not in bl.open_ports

    def test_inactive_service_excluded(self):
        """Services that are installed but not active must not appear in baseline."""
        snaps = [
            SimpleNamespace(installed=True, service=SimpleNamespace(label="nginx"),
                            state=SimpleNamespace(is_active=False)),
            SimpleNamespace(installed=True, service=SimpleNamespace(label="sshd"),
                            state=SimpleNamespace(is_active=True)),
        ]
        bl = build_baseline(make_engine(), make_ports_snapshot([]), snaps)
        assert "sshd" in bl.active_services
        assert "nginx" not in bl.active_services

    def test_not_installed_service_excluded(self):
        """Services with installed=False must not appear in baseline."""
        snaps = [
            SimpleNamespace(installed=False, service=SimpleNamespace(label="fail2ban"),
                            state=SimpleNamespace(is_active=False)),
        ]
        bl = build_baseline(make_engine(), make_ports_snapshot([]), snaps)
        assert "fail2ban" not in bl.active_services


# ---------------------------------------------------------------------------
# save_baseline / load_baseline round-trip
# ---------------------------------------------------------------------------

class TestSaveLoad:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "baseline.json"
        original = make_baseline()
        save_baseline(original, path=path)
        loaded = load_baseline(path=path)
        assert loaded is not None
        assert loaded.score       == original.score
        assert loaded.open_ports  == original.open_ports
        assert loaded.active_services == original.active_services

    def test_load_returns_none_when_missing(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        assert load_baseline(path=path) is None

    def test_load_returns_none_on_corrupt_json(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text("NOT JSON", encoding="utf-8")
        assert load_baseline(path=path) is None

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions not applicable on Windows")
    def test_file_created_with_restricted_permissions(self, tmp_path):
        """File must not be readable by group or others — umask-independent check."""
        path = tmp_path / "baseline.json"
        save_baseline(make_baseline(), path=path)
        mode = path.stat().st_mode & 0o077   # group + other bits
        assert mode == 0, f"Expected no group/other access, got mode {oct(mode)}"

    def test_save_is_atomic(self, tmp_path):
        """Saving must produce a valid JSON file and leave no .tmp file behind."""
        path = tmp_path / "baseline.json"
        save_baseline(make_baseline(), path=path)
        assert path.exists()
        # Final file must be valid JSON
        assert json.loads(path.read_text(encoding="utf-8"))
        # No temporary artefact left
        assert not any(tmp_path.glob("*.tmp"))

    def test_saves_all_fields(self, tmp_path):
        path = tmp_path / "baseline.json"
        bl = make_baseline(alert_count=2, warn_count=5)
        save_baseline(bl, path=path)
        raw = json.loads(path.read_text())
        assert raw["alert_count"] == 2
        assert raw["warn_count"]  == 5

    def test_load_missing_optional_fields(self, tmp_path):
        """load_baseline must not crash when optional fields are missing."""
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps({"timestamp": "t", "score": 7,
                                    "alert_count": 0, "warn_count": 0}),
                        encoding="utf-8")
        bl = load_baseline(path=path)
        assert bl is not None
        assert bl.open_ports == []
        assert bl.active_services == []

    def test_load_returns_none_on_invalid_field_type(self, tmp_path):
        """Unparseable field values (e.g. score='abc') must return None, not raise."""
        path = tmp_path / "baseline.json"
        path.write_text(
            json.dumps({"timestamp": "t", "score": "abc",
                        "alert_count": 0, "warn_count": 0}),
            encoding="utf-8",
        )
        assert load_baseline(path=path) is None

    def test_load_returns_none_on_wrong_root_type(self, tmp_path):
        """A JSON array (not object) at root must return None, not raise."""
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        assert load_baseline(path=path) is None


# ---------------------------------------------------------------------------
# compute_delta
# ---------------------------------------------------------------------------

class TestComputeDelta:
    def test_score_delta_positive_when_improved(self):
        prev = make_baseline(score=7)
        curr = make_baseline(score=9)
        d = compute_delta(prev, curr)
        assert d.score_delta == 2

    def test_score_delta_negative_when_degraded(self):
        prev = make_baseline(score=9)
        curr = make_baseline(score=7)
        d = compute_delta(prev, curr)
        assert d.score_delta == -2

    def test_score_delta_zero_when_unchanged(self):
        bl = make_baseline(score=8)
        d = compute_delta(bl, bl)
        assert d.score_delta == 0

    def test_new_ports_detected(self):
        prev = make_baseline(open_ports=["22/tcp"])
        curr = make_baseline(open_ports=["22/tcp", "8080/tcp"])
        d = compute_delta(prev, curr)
        assert "8080/tcp" in d.new_ports
        assert "22/tcp" not in d.new_ports

    def test_closed_ports_detected(self):
        prev = make_baseline(open_ports=["22/tcp", "80/tcp"])
        curr = make_baseline(open_ports=["22/tcp"])
        d = compute_delta(prev, curr)
        assert "80/tcp" in d.closed_ports
        assert "22/tcp" not in d.closed_ports

    def test_new_services_detected(self):
        prev = make_baseline(active_services=["sshd"])
        curr = make_baseline(active_services=["sshd", "redis"])
        d = compute_delta(prev, curr)
        assert "redis" in d.new_services

    def test_stopped_services_detected(self):
        prev = make_baseline(active_services=["sshd", "nginx"])
        curr = make_baseline(active_services=["sshd"])
        d = compute_delta(prev, curr)
        assert "nginx" in d.stopped_services

    def test_alert_delta(self):
        prev = make_baseline(alert_count=0)
        curr = make_baseline(alert_count=2)
        d = compute_delta(prev, curr)
        assert d.alert_delta == 2

    def test_warn_delta_negative_when_improved(self):
        prev = make_baseline(warn_count=4)
        curr = make_baseline(warn_count=1)
        d = compute_delta(prev, curr)
        assert d.warn_delta == -3

    def test_prev_timestamp_preserved(self):
        prev = make_baseline(timestamp="2026-01-01T00:00:00+00:00")
        curr = make_baseline(timestamp="2026-04-01T00:00:00+00:00")
        d = compute_delta(prev, curr)
        assert d.prev_timestamp == "2026-01-01T00:00:00+00:00"

    def test_no_changes_when_identical(self):
        bl = make_baseline()
        d = compute_delta(bl, bl)
        assert d.score_delta == 0
        assert d.alert_delta == 0
        assert d.warn_delta  == 0
        assert d.new_ports   == []
        assert d.closed_ports == []
        assert d.new_services == []
        assert d.stopped_services == []


# ---------------------------------------------------------------------------
# AuditDelta.is_empty
# ---------------------------------------------------------------------------

class TestAuditDeltaIsEmpty:
    def test_true_when_no_changes(self):
        assert _make_delta().is_empty()

    def test_false_when_score_delta(self):
        assert not _make_delta(score_delta=1).is_empty()

    def test_false_when_alert_delta(self):
        assert not _make_delta(alert_delta=1).is_empty()

    def test_false_when_warn_delta(self):
        assert not _make_delta(warn_delta=-1).is_empty()

    def test_false_when_new_ports(self):
        assert not _make_delta(new_ports=["8080/tcp"]).is_empty()

    def test_false_when_closed_ports(self):
        assert not _make_delta(closed_ports=["80/tcp"]).is_empty()

    def test_false_when_new_services(self):
        assert not _make_delta(new_services=["redis"]).is_empty()

    def test_false_when_stopped_services(self):
        assert not _make_delta(stopped_services=["nginx"]).is_empty()


# ---------------------------------------------------------------------------
# display_delta
# ---------------------------------------------------------------------------

class TestDisplayDelta:
    """Verify that the right display methods are called for each delta type."""

    def _run(self, delta: AuditDelta) -> dict[str, list]:
        calls: dict[str, list] = {
            "ok": [], "warn": [], "info": [], "dim": [], "section": [],
        }
        output_mod = MagicMock()
        output_mod.print_ok      = lambda msg, **kw: calls["ok"].append(msg)
        output_mod.print_warn    = lambda msg, **kw: calls["warn"].append(msg)
        output_mod.print_info    = lambda msg, **kw: calls["info"].append(msg)
        output_mod.print_dim     = lambda msg, **kw: calls["dim"].append(msg)
        output_mod.print_section = lambda msg: calls["section"].append(msg)
        display_delta(delta, _t, output_mod)
        return calls

    def test_section_always_printed(self):
        calls = self._run(_make_delta())
        assert calls["section"]

    def test_score_improved_uses_ok(self):
        calls = self._run(_make_delta(score_delta=1))
        assert any("compare.score_improved" in m for m in calls["ok"])

    def test_score_degraded_uses_warn(self):
        calls = self._run(_make_delta(score_delta=-2))
        assert any("compare.score_degraded" in m for m in calls["warn"])

    def test_score_unchanged_uses_info(self):
        calls = self._run(_make_delta(score_delta=0))
        assert any("compare.score_unchanged" in m for m in calls["info"])

    def test_new_port_uses_warn(self):
        calls = self._run(_make_delta(new_ports=["8080/tcp"]))
        assert any("compare.port_appeared" in m for m in calls["warn"])

    def test_closed_port_uses_ok(self):
        calls = self._run(_make_delta(closed_ports=["8080/tcp"]))
        assert any("compare.port_closed" in m for m in calls["ok"])

    def test_new_service_uses_info(self):
        calls = self._run(_make_delta(new_services=["redis"]))
        assert any("compare.service_appeared" in m for m in calls["info"])

    def test_stopped_service_uses_info(self):
        calls = self._run(_make_delta(stopped_services=["nginx"]))
        assert any("compare.service_stopped" in m for m in calls["info"])

    def test_no_changes_uses_ok(self):
        calls = self._run(_make_delta())
        assert any("compare.no_changes" in m for m in calls["ok"])

    def test_alerts_increased_uses_warn(self):
        calls = self._run(_make_delta(alert_delta=1))
        assert any("compare.alerts_increased" in m for m in calls["warn"])

    def test_alerts_decreased_uses_ok(self):
        calls = self._run(_make_delta(alert_delta=-1))
        assert any("compare.alerts_decreased" in m for m in calls["ok"])

    def test_warns_increased_uses_warn(self):
        calls = self._run(_make_delta(warn_delta=2))
        assert any("compare.warns_increased" in m for m in calls["warn"])

    def test_warns_decreased_uses_ok(self):
        calls = self._run(_make_delta(warn_delta=-1))
        assert any("compare.warns_decreased" in m for m in calls["ok"])

    def test_info_decreased_uses_ok(self):
        calls = self._run(_make_delta(info_delta=-2))
        assert any("compare.info_decreased" in m for m in calls["ok"])

    def test_info_increased_uses_info(self):
        calls = self._run(_make_delta(info_delta=3))
        assert any("compare.info_increased" in m for m in calls["info"])

    def test_info_unchanged_no_output(self):
        calls = self._run(_make_delta(info_delta=0))
        assert not any("compare.info_" in m for m in calls.get("ok", []) + calls.get("info", []))

    def test_is_empty_includes_info_delta(self):
        delta = _make_delta(info_delta=-1)
        assert not delta.is_empty()

    def test_is_empty_true_when_all_zero(self):
        delta = _make_delta()
        assert delta.is_empty()

    def test_new_finding_key_uses_warn(self):
        calls = self._run(_make_delta(new_finding_keys=["hardening.rp_filter_disabled"]))
        assert any("compare.key_appeared" in m for m in calls["warn"])

    def test_resolved_finding_key_uses_ok(self):
        calls = self._run(_make_delta(resolved_finding_keys=["clamav.db_outdated"]))
        assert any("compare.key_resolved" in m for m in calls["ok"])

    def test_variable_deductions_increased_shown_without_structural_change(self):
        calls = self._run(_make_delta(deduction_delta=3))
        assert any("compare.variable_deductions_increased" in m for m in calls["info"])

    def test_variable_deductions_decreased_shown_without_structural_change(self):
        calls = self._run(_make_delta(deduction_delta=-2))
        assert any("compare.variable_deductions_decreased" in m for m in calls["info"])

    def test_variable_deductions_suppressed_when_warn_delta(self):
        calls = self._run(_make_delta(deduction_delta=5, warn_delta=1))
        assert not any("compare.variable_deductions" in m for m in calls["info"])

    def test_variable_deductions_suppressed_when_new_finding_key(self):
        calls = self._run(_make_delta(deduction_delta=5, new_finding_keys=["hardening.rp_filter_disabled"]))
        assert not any("compare.variable_deductions" in m for m in calls["info"])


# ---------------------------------------------------------------------------
# deduction_total tracking — pre-v0.2.3 baseline sentinel
# ---------------------------------------------------------------------------

class TestDeductionTracking:
    def test_deduction_total_none_in_new_baseline_defaults(self):
        bl = make_baseline()
        assert bl.deduction_total is None

    def test_load_baseline_returns_none_when_field_absent(self, tmp_path):
        path = tmp_path / "bl.json"
        path.write_text(json.dumps({"timestamp": "t", "score": 8,
                                    "alert_count": 0, "warn_count": 2}),
                        encoding="utf-8")
        bl = load_baseline(path=path)
        assert bl is not None
        assert bl.deduction_total is None

    def test_load_baseline_returns_int_when_field_present(self, tmp_path):
        path = tmp_path / "bl.json"
        path.write_text(json.dumps({"timestamp": "t", "score": 8,
                                    "alert_count": 0, "warn_count": 2,
                                    "deduction_total": 5}),
                        encoding="utf-8")
        bl = load_baseline(path=path)
        assert bl is not None
        assert bl.deduction_total == 5

    def test_deduction_delta_zero_when_prev_is_old_baseline(self):
        prev = make_baseline(deduction_total=None)
        curr = make_baseline(deduction_total=13)
        d = compute_delta(prev, curr)
        assert d.deduction_delta == 0

    def test_deduction_delta_computed_when_both_tracked(self):
        prev = make_baseline(deduction_total=8)
        curr = make_baseline(deduction_total=11)
        d = compute_delta(prev, curr)
        assert d.deduction_delta == 3

    def test_deduction_delta_zero_when_unchanged(self):
        bl = make_baseline(deduction_total=7)
        d = compute_delta(bl, bl)
        assert d.deduction_delta == 0
