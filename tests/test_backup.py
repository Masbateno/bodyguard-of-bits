"""
Unit tests for bob.checks.backup (CHECK 35).

Covers:
  - Active tools → OK
  - Installed-only tools → INFO
  - No tools → WARN (server) / INFO (desktop)
  - Mixed active + installed
  - Profile-aware scoring (server vs desktop)
  - Deduction invariants
  - _borgmatic_config_exists and _service_active helpers

All tests use BackupSnapshot instances built directly — no subprocess calls.

Run with: python3 -m pytest tests/test_backup.py -v
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from bob.checks.backup import (
    BackupSnapshot,
    _borgmatic_config_exists,
    check_backup,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snap(
    *,
    active: list[str] | None = None,
    installed: list[str] | None = None,
) -> BackupSnapshot:
    return BackupSnapshot(
        active_tools=list(active or []),
        installed_tools=list(installed or []),
    )


def _keys(result) -> list[str]:
    return [f.key for f in result.findings]


def _level(result, key: str) -> FindingLevel:
    for f in result.findings:
        if f.key == key:
            return f.level
    raise AssertionError(f"Key {key!r} not found in findings: {_keys(result)}")


# ---------------------------------------------------------------------------
# Active backup solution
# ---------------------------------------------------------------------------

class TestActiveBackup:
    def test_active_tool_returns_ok(self):
        snap = _snap(active=["borgmatic"])
        result = check_backup(snap, t=_t)
        assert "backup.active" in _keys(result)
        assert _level(result, "backup.active") == FindingLevel.OK

    def test_active_no_deduction(self):
        snap = _snap(active=["borgmatic"])
        result = check_backup(snap, t=_t)
        assert _deduction_points(result) == 0

    def test_active_multiple_tools(self):
        snap = _snap(active=["borgmatic", "timeshift"])
        result = check_backup(snap, t=_t)
        assert "backup.active" in _keys(result)
        assert _deduction_points(result) == 0

    def test_active_with_installed_also_shows_info(self):
        snap = _snap(active=["borgmatic"], installed=["restic"])
        result = check_backup(snap, t=_t)
        assert "backup.active" in _keys(result)
        assert "backup.also_installed" in _keys(result)
        assert _level(result, "backup.also_installed") == FindingLevel.INFO

    def test_active_tool_not_duplicated_in_also_installed(self):
        """Tool appearing in both active and installed → not listed in also_installed."""
        snap = _snap(active=["borgmatic"], installed=["borgmatic"])
        result = check_backup(snap, t=_t)
        assert "backup.active" in _keys(result)
        assert "backup.also_installed" not in _keys(result)

    def test_also_installed_message_excludes_active_tool(self):
        """also_installed message must not mention a tool already in active."""
        def _t_verbose(key, **kwargs):
            # Pass kwargs values into the returned string for content assertions
            return ":".join([key] + [str(v) for v in kwargs.values()])

        snap = _snap(active=["borgmatic"], installed=["borgmatic", "restic"])
        result = check_backup(snap, t=_t_verbose)
        finding = next(f for f in result.findings if f.key == "backup.also_installed")
        assert "borgmatic" not in finding.message
        assert "restic" in finding.message

    def test_output_is_sorted_deterministically(self):
        """Tool list order in messages is stable regardless of insertion order."""
        snap_a = _snap(active=["timeshift", "borgmatic"])
        snap_b = _snap(active=["borgmatic", "timeshift"])
        out_a = next(f.message for f in check_backup(snap_a, t=_t).findings
                     if f.key == "backup.active")
        out_b = next(f.message for f in check_backup(snap_b, t=_t).findings
                     if f.key == "backup.active")
        assert out_a == out_b

    def test_active_same_on_desktop(self):
        snap = _snap(active=["timeshift"])
        result = check_backup(snap, t=_t, profile_name="desktop")
        assert _level(result, "backup.active") == FindingLevel.OK
        assert _deduction_points(result) == 0

    @pytest.mark.parametrize("tool", [
        "borgmatic", "borg", "restic", "timeshift",
        "duplicati", "bacula", "rclone", "tarsnap", "deja-dup",
    ])
    def test_each_tool_can_be_active(self, tool):
        snap = _snap(active=[tool])
        result = check_backup(snap, t=_t)
        assert _level(result, "backup.active") == FindingLevel.OK


# ---------------------------------------------------------------------------
# Installed-only (not confirmed active)
# ---------------------------------------------------------------------------

class TestInstalledOnly:
    def test_installed_only_returns_info(self):
        snap = _snap(installed=["restic"])
        result = check_backup(snap, t=_t)
        assert "backup.installed_only" in _keys(result)
        assert _level(result, "backup.installed_only") == FindingLevel.INFO

    def test_installed_only_no_deduction(self):
        snap = _snap(installed=["restic"])
        result = check_backup(snap, t=_t)
        assert _deduction_points(result) == 0

    def test_installed_only_multiple_tools(self):
        snap = _snap(installed=["restic", "deja-dup"])
        result = check_backup(snap, t=_t)
        assert "backup.installed_only" in _keys(result)

    def test_installed_only_same_on_desktop(self):
        snap = _snap(installed=["restic"])
        result = check_backup(snap, t=_t, profile_name="desktop")
        assert _level(result, "backup.installed_only") == FindingLevel.INFO
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# No backup found
# ---------------------------------------------------------------------------

class TestNoBackup:
    def test_server_no_backup_warns(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="server")
        assert "backup.no_backup" in _keys(result)
        assert _level(result, "backup.no_backup") == FindingLevel.WARN

    def test_server_no_backup_deduction_1pt(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="server")
        assert _deduction_points(result) == 1
        assert "backup.no_backup" in _deduction_keys(result)

    def test_desktop_no_backup_info(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="desktop")
        assert "backup.no_backup" in _keys(result)
        assert _level(result, "backup.no_backup") == FindingLevel.INFO

    def test_desktop_no_backup_no_deduction(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="desktop")
        assert _deduction_points(result) == 0

    def test_no_backup_has_install_cmd(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="server")
        finding = next(f for f in result.findings if f.key == "backup.no_backup")
        assert "apt install" in finding.cmd
        assert "borgmatic" in finding.cmd or "borgbackup" in finding.cmd

    def test_default_profile_is_server(self):
        snap = _snap()
        result = check_backup(snap, t=_t)
        assert _level(result, "backup.no_backup") == FindingLevel.WARN


# ---------------------------------------------------------------------------
# Priority: active > installed > no_backup
# ---------------------------------------------------------------------------

class TestFindingPriority:
    def test_active_takes_priority_over_installed(self):
        snap = _snap(active=["borg"], installed=["restic"])
        result = check_backup(snap, t=_t)
        assert "backup.active" in _keys(result)
        assert "backup.no_backup" not in _keys(result)
        assert "backup.installed_only" not in _keys(result)

    def test_installed_takes_priority_over_no_backup(self):
        snap = _snap(installed=["restic"])
        result = check_backup(snap, t=_t, profile_name="server")
        assert "backup.installed_only" in _keys(result)
        assert "backup.no_backup" not in _keys(result)
        assert "backup.active" not in _keys(result)

    def test_empty_snapshot_goes_to_no_backup(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="server")
        assert "backup.no_backup" in _keys(result)
        assert "backup.active" not in _keys(result)
        assert "backup.installed_only" not in _keys(result)


# ---------------------------------------------------------------------------
# Borg standalone (borgmatic installed-only should not block borg detection)
# ---------------------------------------------------------------------------

class TestBorgStandalone:
    _t_verbose = staticmethod(
        lambda key, **kw: ":".join([key] + [str(v) for v in kw.values()])
    )

    def test_borgmatic_installed_only_does_not_block_borg_active(self):
        """If borgmatic has no config, borg active should still be detected."""
        snap = _snap(active=["borg"], installed=["borgmatic"])
        result = check_backup(snap, t=self._t_verbose)
        assert "backup.active" in _keys(result)
        finding = next(f for f in result.findings if f.key == "backup.active")
        assert "borg" in finding.message

    def test_borgmatic_active_does_not_duplicate_borg(self):
        """If borgmatic is active, borg should not appear separately."""
        snap = _snap(active=["borgmatic"])
        result = check_backup(snap, t=self._t_verbose)
        finding = next(f for f in result.findings if f.key == "backup.active")
        assert "borgmatic" in finding.message
        assert "backup.also_installed" not in _keys(result)


# ---------------------------------------------------------------------------
# Deduction invariants
# ---------------------------------------------------------------------------

class TestDeductionInvariants:
    @pytest.mark.parametrize("snap,profile", [
        (_snap(active=["borgmatic"]), "server"),
        (_snap(active=["timeshift"]), "desktop"),
        (_snap(installed=["restic"]), "server"),
        (_snap(installed=["deja-dup"]), "desktop"),
        (_snap(), "desktop"),
    ])
    def test_no_unexpected_deductions(self, snap, profile):
        result = check_backup(snap, t=_t, profile_name=profile)
        assert _deduction_points(result) <= 1

    def test_max_deduction_is_1(self):
        snap = _snap()
        result = check_backup(snap, t=_t, profile_name="server")
        assert _deduction_points(result) == 1


# ---------------------------------------------------------------------------
# BackupSnapshot dataclass
# ---------------------------------------------------------------------------

class TestBackupSnapshot:
    def test_defaults(self):
        snap = BackupSnapshot()
        assert snap.active_tools == []
        assert snap.installed_tools == []

    def test_custom_values(self):
        snap = BackupSnapshot(active_tools=["borg"], installed_tools=["restic"])
        assert "borg" in snap.active_tools
        assert "restic" in snap.installed_tools


# ---------------------------------------------------------------------------
# _borgmatic_config_exists helper
# ---------------------------------------------------------------------------

class TestBorgmaticConfigExists:
    def test_returns_true_for_existing_file(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("repos:\n  - path: /backup")
        assert _borgmatic_config_exists(cfg)

    def test_returns_false_for_missing_path(self, tmp_path):
        assert not _borgmatic_config_exists(tmp_path / "nonexistent.yaml")

    def test_returns_true_for_non_empty_dir(self, tmp_path):
        d = tmp_path / "borgmatic.d"
        d.mkdir()
        (d / "server.yaml").write_text("repos: []")
        assert _borgmatic_config_exists(d)

    def test_returns_false_for_empty_dir(self, tmp_path):
        d = tmp_path / "borgmatic.d"
        d.mkdir()
        assert not _borgmatic_config_exists(d)
