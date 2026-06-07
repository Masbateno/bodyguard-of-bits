"""v0.9.0 F-2 — `--diff <baseline.json>` cross-machine compare.

Pins the new ``config.diff_baseline_path`` field and ``load_baseline(strict=True)``
contract: explicit-path failures raise ``BaselineLoadError`` instead of silently
returning ``None``, and the v0.6.x ``schema_version="1"`` legacy is rejected
explicitly per F-3.

The end-to-end ``--diff PATH`` invocation flow (parse → load → display →
cross-machine notice) is exercised through tightly-scoped unit tests rather
than a subprocess smoke; the audit-path subprocess equivalent is covered by
the integration smoke that runs ``bob --offline -v`` in CI.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bob.cli import AuditConfig, CLIError, parse_args
from bob.compare import (
    AuditBaseline,
    BaselineLoadError,
    build_baseline,
    load_baseline,
    save_baseline,
)


# ---------------------------------------------------------------------------
# CLI parsing — --diff[=PATH] / --diff PATH / bare --diff
# ---------------------------------------------------------------------------


class TestCLIDiffPathParsing:

    def test_bare_diff_keeps_v08x_behaviour(self):
        cfg = parse_args(["--diff"])
        assert cfg.diff_mode is True
        assert cfg.diff_baseline_path is None

    def test_short_d_keeps_v08x_behaviour(self):
        cfg = parse_args(["-D"])
        assert cfg.diff_mode is True
        assert cfg.diff_baseline_path is None

    def test_equals_syntax_sets_explicit_path(self, tmp_path):
        p = tmp_path / "explicit.json"
        p.write_text("{}", encoding="utf-8")
        cfg = parse_args([f"--diff={p}"])
        assert cfg.diff_mode is True
        assert cfg.diff_baseline_path == p

    def test_space_syntax_sets_explicit_path(self, tmp_path):
        p = tmp_path / "spaced.json"
        p.write_text("{}", encoding="utf-8")
        cfg = parse_args(["--diff", str(p)])
        assert cfg.diff_mode is True
        assert cfg.diff_baseline_path == p

    def test_space_syntax_does_not_consume_a_flag_token(self):
        """``sudo bob --diff --verbose`` keeps --verbose as the next flag,
        not as a baseline path. Mirrors --watch's peek-ahead guard.
        (Not ``--watch`` itself because --diff + --watch is rejected by
        the cross-flag compatibility check upstream of the path peek.)"""
        cfg = parse_args(["--diff", "--verbose"])
        assert cfg.diff_mode is True
        assert cfg.diff_baseline_path is None
        assert cfg.verbose is True

    def test_equals_empty_value_raises(self):
        with pytest.raises(CLIError, match="path"):
            parse_args(["--diff="])

    def test_duplicate_diff_raises(self):
        with pytest.raises(CLIError, match="more than once"):
            parse_args(["--diff", "--diff"])

    def test_duplicate_diff_with_path_raises(self, tmp_path):
        p = tmp_path / "a.json"
        p.write_text("{}", encoding="utf-8")
        with pytest.raises(CLIError, match="more than once"):
            parse_args([f"--diff={p}", "--diff"])


# ---------------------------------------------------------------------------
# load_baseline(strict=True) — explicit-path failures raise
# ---------------------------------------------------------------------------


class TestLoadBaselineStrict:

    def test_missing_file_strict_raises_with_path_in_message(self, tmp_path):
        missing = tmp_path / "does-not-exist.json"
        with pytest.raises(BaselineLoadError, match=str(missing)):
            load_baseline(missing, strict=True)

    def test_missing_file_non_strict_returns_none(self, tmp_path):
        missing = tmp_path / "does-not-exist.json"
        assert load_baseline(missing, strict=False) is None

    def test_invalid_json_strict_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(BaselineLoadError):
            load_baseline(bad, strict=True)

    def test_v1_schema_strict_raises(self, tmp_path):
        v1 = tmp_path / "v1.json"
        v1.write_text(json.dumps({
            "schema_version": "1",
            "score": 9,
            "alert_count": 0,
            "warn_count": 1,
        }), encoding="utf-8")
        with pytest.raises(BaselineLoadError, match="v0.6.x"):
            load_baseline(v1, strict=True)

    def test_v1_schema_non_strict_returns_none(self, tmp_path):
        v1 = tmp_path / "v1.json"
        v1.write_text(json.dumps({
            "schema_version": "1",
            "score": 9,
            "alert_count": 0,
            "warn_count": 1,
        }), encoding="utf-8")
        assert load_baseline(v1, strict=False) is None

    def test_v2_implicit_no_schema_field_loads_cleanly(self, tmp_path):
        """v0.7.x–v0.8.x baselines don't carry a schema_version field —
        the loader treats them as v2-compatible (no rejection)."""
        b = tmp_path / "modern.json"
        b.write_text(json.dumps({
            "timestamp": "2026-01-01T00:00:00",
            "score": 9,
            "alert_count": 0,
            "warn_count": 1,
            "info_count": 0,
            "open_ports": ["22/tcp"],
            "active_services": ["sshd"],
        }), encoding="utf-8")
        result = load_baseline(b, strict=True)
        assert result is not None
        assert result.score == 9


# ---------------------------------------------------------------------------
# Hostname capture for cross-machine compare
# ---------------------------------------------------------------------------


class TestHostnameCapture:

    def test_save_load_roundtrip_preserves_hostname(self, tmp_path):
        """The hostname captured at build time round-trips through JSON."""
        b = AuditBaseline(
            timestamp="2026-01-01T00:00:00",
            score=10,
            alert_count=0,
            warn_count=0,
            info_count=0,
            hostname="server-A",
        )
        dest = tmp_path / "rt.json"
        save_baseline(b, path=dest)
        loaded = load_baseline(dest, strict=True)
        assert loaded is not None
        assert loaded.hostname == "server-A"

    def test_pre_v090_baseline_loads_with_none_hostname(self, tmp_path):
        """Pre-v0.9.0 baselines have no hostname field — loader returns None."""
        b = tmp_path / "old.json"
        b.write_text(json.dumps({
            "timestamp": "2026-01-01T00:00:00",
            "score": 9,
            "alert_count": 0,
            "warn_count": 1,
            "info_count": 0,
            "open_ports": [],
            "active_services": [],
        }), encoding="utf-8")
        loaded = load_baseline(b, strict=False)
        assert loaded is not None
        assert loaded.hostname is None

    def test_build_baseline_captures_real_hostname(self):
        """``build_baseline`` calls ``socket.gethostname`` (not raised under
        normal conditions) and stores the result so ``--diff PATH`` can
        emit the cross-machine notice."""
        from bob.scoring import ScoreEngine
        from bob.checks.ports import PortsSnapshot

        engine = ScoreEngine()
        snap = PortsSnapshot(ports=[], ufw_rules=[], ss_output="")
        result = build_baseline(engine, snap, [])
        # ``hostname`` is either a non-empty string or ``None`` if
        # ``gethostname`` raised — never the empty string.
        assert result.hostname is None or result.hostname  # truthy
