"""
Smoke tests for bob/runner.py — the audit orchestrator (665 LoC, top
out-degree, no dedicated test file pre-v0.8.0 drift batch).

The v0.7.4 structural audit flagged runner.py as a STRATEGIC test gap:

  - 665 LoC of orchestration with the highest import out-degree
  - the actual ``run_checks()`` body is only exercised end-to-end by
    the 7-distro integration matrix (cycle ~30 minutes)
  - ``_section_enabled`` + ``validate_check_filters`` are already
    covered by ``tests/test_cli.py`` (TestSectionEnabled +
    TestValidateCheckFilters classes)

This file adds the missing coverage on the public API surface of
``runner.py`` that does NOT require full snapshot fixtures:

  - ``init_report`` — null vs file branch
  - ``ChecksResult`` NamedTuple shape (defaults + named/positional access)
  - module-level constants (``_ALL_SECTIONS``, ``_ALWAYS_ON_SECTIONS``)
    are non-empty and disjoint
  - ``run_checks`` is importable and has the expected signature

Full end-to-end coverage of ``run_checks()`` still lives in the
integration matrix (every distro × every Python version × every install
mode) — these smoke tests are the pytest-local fast-feedback layer for
"did somebody break the orchestrator's contract".
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# init_report — null vs file branch
# ---------------------------------------------------------------------------

class TestInitReport:
    """``init_report`` returns the right concrete report type given ``detailed``."""

    def test_returns_null_report_when_not_detailed(self, tmp_path):
        """No ``-d`` flag → no log file, NullReport returned (zero I/O)."""
        from bob.cli import AuditConfig
        from bob.config import UserConfig
        from bob.report import AuditReport
        from bob.runner import init_report

        config = AuditConfig(detailed=False)
        user_config = UserConfig.load(path=tmp_path / "config.conf")
        t = lambda key, **_kw: key

        report = init_report(config, user_config, t, "1.0.0")

        # NullReport instance — the no-op variant
        assert isinstance(report, AuditReport)
        # The null branch produces a non-functional report (no file path)
        assert report.path is None or not getattr(report, "enabled", True)

    def test_returns_file_report_when_detailed(self, tmp_path, monkeypatch):
        """``-d`` flag → writes a .log file under user-configured log dir."""
        from bob.cli import AuditConfig
        from bob.config import UserConfig
        from bob.report import AuditReport
        from bob.runner import init_report

        # Skip the interactive directory prompt by pre-populating user_config
        user_config = UserConfig.load(path=tmp_path / "config.conf")
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        user_config.set("log_dir", str(log_dir))

        config = AuditConfig(detailed=True, quiet=True)
        t = lambda key, **_kw: key

        report = init_report(config, user_config, t, "1.0.0")

        assert isinstance(report, AuditReport)
        # The non-null branch produces an actual file
        assert report.path is not None
        assert report.path.parent == log_dir
        assert report.path.name.startswith("bob_")
        assert report.path.suffix == ".log"


# ---------------------------------------------------------------------------
# ChecksResult NamedTuple shape
# ---------------------------------------------------------------------------

class TestChecksResultShape:
    """``ChecksResult`` is the canonical return shape from ``run_checks()``."""

    def test_named_field_access(self):
        from bob.runner import ChecksResult

        # Fake the structural fields (only check shape, not contents)
        snapshots = []
        ports = MagicMock()
        stack = MagicMock()
        net = MagicMock()
        hardening = MagicMock()
        ipv6 = MagicMock()

        result = ChecksResult(snapshots, ports, stack, net, hardening, ipv6)

        assert result.snapshots is snapshots
        assert result.ports_snapshot is ports
        assert result.stack_snapshot is stack
        assert result.net_snapshot is net
        assert result.hardening_snapshot is hardening
        assert result.ipv6_snapshot is ipv6
        # Defaults
        assert result.fw_active is False
        assert result.fw_policy == "unknown"
        assert result.network_context == "local"

    def test_default_overrides(self):
        from bob.runner import ChecksResult

        result = ChecksResult(
            [], MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            fw_active=True, fw_policy="deny", network_context="public",
        )
        assert result.fw_active is True
        assert result.fw_policy == "deny"
        assert result.network_context == "public"

    def test_is_immutable_tuple(self):
        """``NamedTuple`` semantics — fields cannot be reassigned."""
        from bob.runner import ChecksResult

        result = ChecksResult([], MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock())
        with pytest.raises(AttributeError):
            result.fw_active = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

class TestRunnerConstants:
    """Module-level section name constants must be non-empty and disjoint
    (a section is either filterable or always-on, never both)."""

    def test_all_sections_non_empty(self):
        from bob.runner import _ALL_SECTIONS
        assert len(_ALL_SECTIONS) > 0
        assert all(isinstance(s, str) and s for s in _ALL_SECTIONS)

    def test_always_on_sections_non_empty(self):
        from bob.runner import _ALWAYS_ON_SECTIONS
        assert len(_ALWAYS_ON_SECTIONS) > 0
        assert all(isinstance(s, str) and s for s in _ALWAYS_ON_SECTIONS)

    def test_filterable_and_always_on_disjoint(self):
        """A section cannot be both filterable (via --check/--skip) and
        always-on (M-7 v0.7.0 contract). If this fails, ``--check=X`` for
        an always-on section X behaves ambiguously."""
        from bob.runner import _ALL_SECTIONS, _ALWAYS_ON_SECTIONS
        overlap = set(_ALL_SECTIONS) & set(_ALWAYS_ON_SECTIONS)
        assert not overlap, (
            f"Sections present in both _ALL_SECTIONS and _ALWAYS_ON_SECTIONS: "
            f"{sorted(overlap)}. Pick one bucket per section."
        )


# ---------------------------------------------------------------------------
# run_checks signature & importability
# ---------------------------------------------------------------------------

class TestRunChecksSignature:
    """``run_checks`` is the public orchestrator. Its signature is part of
    the implicit contract with ``__main__.py`` (and any future external
    caller). If the signature drifts, ``__main__`` breaks at runtime."""

    def test_run_checks_is_importable(self):
        from bob.runner import run_checks
        assert callable(run_checks)

    def test_run_checks_signature_stable(self):
        """The 6 required parameters + 3 optionals are the contract."""
        import inspect

        from bob.runner import run_checks

        sig = inspect.signature(run_checks)
        params = list(sig.parameters)
        # Required positional/keyword: config, t, engine, report, registry, network_context
        assert params[:6] == [
            "config", "t", "engine", "report", "registry", "network_context",
        ]
        # Optional with defaults
        assert "profile" in params
        assert "prev_recurrence" in params
        assert "user_config" in params
        # Defaults expected: profile=None, prev_recurrence=None, user_config=None
        assert sig.parameters["profile"].default is None
        assert sig.parameters["prev_recurrence"].default is None
        assert sig.parameters["user_config"].default is None

    def test_init_report_signature_stable(self):
        """init_report is called by __main__ as a 4-arg function."""
        import inspect

        from bob.runner import init_report

        sig = inspect.signature(init_report)
        assert list(sig.parameters) == ["config", "user_config", "t", "version"]
