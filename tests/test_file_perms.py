"""
Tests for bob/checks/file_perms.py — sensitive file permissions and sudoers audit.

Coverage:
  - check_file_perms(): all branches (world-writable, too-permissive, SSH host keys,
    NOPASSWD ALL, NOPASSWD specific, all-OK)
  - Deduction capping (3 max for file perms, 2 max for SSH host keys)
  - _is_nopasswd_all(): various sudoers patterns
  - FileInfo and FilePermsSnapshot dataclass construction
"""

from __future__ import annotations

import pytest

from bob.checks.file_perms import (
    FileInfo,
    FilePermsSnapshot,
    _is_nopasswd_all,
    check_file_perms,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _has_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


def base_snapshot(**kwargs) -> FilePermsSnapshot:
    """Return a clean FilePermsSnapshot with no issues (all fields at defaults)."""
    defaults = dict(
        sensitive_files=[],
        ssh_host_key_issues=[],
        sudoers_nopasswd_all=[],
        sudoers_nopasswd_specific=[],
    )
    defaults.update(kwargs)
    return FilePermsSnapshot(**defaults)


def make_file_info(
    path: str = "/etc/shadow",
    exists: bool = True,
    mode: int = 0o640,
    max_mode: int = 0o640,
    key: str = "shadow",
) -> FileInfo:
    return FileInfo(path=path, exists=exists, mode=mode, max_mode=max_mode, key=key)


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_empty_snapshot_returns_ok(self):
        result = check_file_perms(base_snapshot())
        assert any(f.level == FindingLevel.OK for f in result.findings)
        assert _deduction_points(result) == 0

    def test_ok_key(self):
        result = check_file_perms(base_snapshot())
        assert _has_finding(result, "file_perms.ok", FindingLevel.OK)

    def test_files_at_correct_permissions_return_ok(self):
        files = [
            make_file_info("/etc/passwd",  mode=0o644, max_mode=0o644, key="passwd"),
            make_file_info("/etc/shadow",  mode=0o640, max_mode=0o640, key="shadow"),
            make_file_info("/etc/sudoers", mode=0o440, max_mode=0o440, key="sudoers_file"),
        ]
        result = check_file_perms(base_snapshot(sensitive_files=files))
        assert _has_finding(result, "file_perms.ok", FindingLevel.OK)
        assert _deduction_points(result) == 0

    def test_absent_files_produce_no_findings(self):
        files = [
            make_file_info("/etc/shadow", exists=False, mode=0, key="shadow"),
        ]
        result = check_file_perms(base_snapshot(sensitive_files=files))
        assert _has_finding(result, "file_perms.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# World-writable files
# ---------------------------------------------------------------------------

class TestWorldWritable:
    def test_world_writable_produces_alert(self):
        fi = make_file_info("/etc/shadow", mode=0o646, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert _has_finding(result, "file_perms.shadow.world_writable", FindingLevel.ALERT)

    def test_world_writable_deducts_3_points(self):
        fi = make_file_info("/etc/passwd", mode=0o777, max_mode=0o644, key="passwd")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert _deduction_points(result) == 3

    def test_world_writable_correct_deduction_key(self):
        # Deduction keys are part of the public contract — used by apply_profile().
        fi = make_file_info("/etc/sudoers", mode=0o442, max_mode=0o440, key="sudoers_file")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert "file_perms.sudoers_file.world_writable" in _deduction_keys(result)

    def test_world_writable_takes_priority_over_too_permissive(self):
        """When both ALERT and WARN bits are set, ALERT (world-write) wins — no WARN duplicate."""
        # 0o666 on a max-0o640 file: extra = 0o026 → bit 0o002 set → ALERT path taken
        fi = make_file_info("/etc/shadow", mode=0o666, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert _has_finding(result, "file_perms.shadow.world_writable", FindingLevel.ALERT)
        assert not _has_finding(result, "file_perms.shadow.too_permissive", FindingLevel.WARN)

    def test_world_writable_mode_002_bit(self):
        """0o641 has world-execute only, not world-write — should not be ALERT."""
        fi = make_file_info("/etc/shadow", mode=0o641, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        # world-execute is not world-writable
        assert not _has_finding(result, "file_perms.shadow.world_writable", FindingLevel.ALERT)

    def test_multiple_world_writable_files(self):
        files = [
            make_file_info("/etc/shadow", mode=0o642, max_mode=0o640, key="shadow"),
            make_file_info("/etc/passwd", mode=0o646, max_mode=0o644, key="passwd"),
        ]
        result = check_file_perms(base_snapshot(sensitive_files=files))
        alerts = [f for f in result.findings if f.level == FindingLevel.ALERT]
        assert len(alerts) == 2
        assert _deduction_points(result) == 6

    def test_world_writable_no_ok_finding(self):
        fi = make_file_info("/etc/shadow", mode=0o642, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert not any(f.level == FindingLevel.OK for f in result.findings)


# ---------------------------------------------------------------------------
# Too-permissive (non-world-writable extra bits)
# ---------------------------------------------------------------------------

class TestTooPermissive:
    def test_too_permissive_produces_warn(self):
        # shadow at 0o644 — world-readable but not world-writable
        fi = make_file_info("/etc/shadow", mode=0o644, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert _has_finding(result, "file_perms.shadow.too_permissive", FindingLevel.WARN)

    def test_too_permissive_deducts_1_point(self):
        fi = make_file_info("/etc/shadow", mode=0o644, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert _deduction_points(result) == 1

    def test_too_permissive_sudoers_group_write(self):
        # sudoers at 0o460 — group has write
        fi = make_file_info("/etc/sudoers", mode=0o460, max_mode=0o440, key="sudoers_file")
        result = check_file_perms(base_snapshot(sensitive_files=[fi]))
        assert _has_finding(result, "file_perms.sudoers_file.too_permissive", FindingLevel.WARN)

    def test_deduction_cap_at_3_for_permissive_files(self):
        """4 too-permissive files should generate at most 3 deductions."""
        files = [
            make_file_info("/etc/passwd",  mode=0o664, max_mode=0o644, key="passwd"),
            make_file_info("/etc/shadow",  mode=0o644, max_mode=0o640, key="shadow"),
            make_file_info("/etc/gshadow", mode=0o644, max_mode=0o640, key="gshadow"),
            make_file_info("/etc/group",   mode=0o664, max_mode=0o644, key="group"),
        ]
        result = check_file_perms(base_snapshot(sensitive_files=files))
        assert _deduction_points(result) == 3

    def test_4th_permissive_still_gets_finding_but_no_extra_deduction(self):
        """4th file: finding is emitted but no deduction added."""
        files = [
            make_file_info("/etc/passwd",  mode=0o664, max_mode=0o644, key="passwd"),
            make_file_info("/etc/shadow",  mode=0o644, max_mode=0o640, key="shadow"),
            make_file_info("/etc/gshadow", mode=0o644, max_mode=0o640, key="gshadow"),
            make_file_info("/etc/group",   mode=0o664, max_mode=0o644, key="group"),
        ]
        result = check_file_perms(base_snapshot(sensitive_files=files))
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 4
        assert _deduction_points(result) == 3   # capped


# ---------------------------------------------------------------------------
# SSH host key permissions
# ---------------------------------------------------------------------------

class TestSshHostKeyPerms:
    def test_host_key_wrong_perms_produces_warn(self):
        result = check_file_perms(base_snapshot(
            ssh_host_key_issues=[("/etc/ssh/ssh_host_rsa_key", 0o644)]
        ))
        assert _has_finding(
            result, "file_perms.ssh_host_key.ssh_host_rsa_key", FindingLevel.WARN
        )

    def test_host_key_deducts_1_point(self):
        result = check_file_perms(base_snapshot(
            ssh_host_key_issues=[("/etc/ssh/ssh_host_rsa_key", 0o644)]
        ))
        assert _deduction_points(result) == 1

    def test_host_key_deduction_cap_at_2(self):
        result = check_file_perms(base_snapshot(
            ssh_host_key_issues=[
                ("/etc/ssh/ssh_host_rsa_key",     0o644),
                ("/etc/ssh/ssh_host_ecdsa_key",   0o644),
                ("/etc/ssh/ssh_host_ed25519_key",  0o644),
            ]
        ))
        assert _deduction_points(result) == 2  # capped at 2

    def test_3_host_keys_still_get_3_warnings(self):
        result = check_file_perms(base_snapshot(
            ssh_host_key_issues=[
                ("/etc/ssh/ssh_host_rsa_key",     0o644),
                ("/etc/ssh/ssh_host_ecdsa_key",   0o644),
                ("/etc/ssh/ssh_host_ed25519_key",  0o644),
            ]
        ))
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) == 3
        assert _deduction_points(result) == 2


# ---------------------------------------------------------------------------
# Sudoers NOPASSWD ALL
# ---------------------------------------------------------------------------

class TestSudoersNopasswdAll:
    def test_nopasswd_all_produces_warn(self):
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_all=["john ALL=(ALL) NOPASSWD:ALL"]
        ))
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) >= 1

    def test_nopasswd_all_deducts_2_points(self):
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_all=["john ALL=(ALL) NOPASSWD:ALL"]
        ))
        assert _deduction_points(result) == 2

    def test_nopasswd_all_deduction_key(self):
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_all=["john ALL=(ALL) NOPASSWD:ALL"]
        ))
        assert "file_perms.sudoers_nopasswd_all" in _deduction_keys(result)

    def test_multiple_nopasswd_all_lines_single_deduction(self):
        """Multiple NOPASSWD:ALL lines → multiple findings but only one deduction block."""
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_all=[
                "john ALL=(ALL) NOPASSWD:ALL",
                "%admin ALL=(ALL) NOPASSWD:ALL",
            ]
        ))
        assert _deduction_points(result) == 2  # single deduction regardless of count
        warns = [f for f in result.findings
                 if f.level == FindingLevel.WARN
                 and f.key == "file_perms.sudoers_nopasswd_all"]
        assert len(warns) == 2  # one finding per line

    def test_nopasswd_all_no_ok_finding(self):
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_all=["root ALL=(ALL) NOPASSWD:ALL"]
        ))
        assert not any(f.level == FindingLevel.OK for f in result.findings)


# ---------------------------------------------------------------------------
# Sudoers NOPASSWD specific commands
# ---------------------------------------------------------------------------

class TestSudoersNopasswdSpecific:
    def test_nopasswd_specific_produces_info(self):
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_specific=["john ALL=(ALL) NOPASSWD:/usr/bin/apt"]
        ))
        assert _has_finding(result, "file_perms.sudoers_nopasswd_specific", FindingLevel.INFO)

    def test_nopasswd_specific_no_deduction(self):
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_specific=["john ALL=(ALL) NOPASSWD:/usr/bin/apt"]
        ))
        assert _deduction_points(result) == 0

    def test_nopasswd_specific_two_entries_single_finding(self):
        """Two specific-command entries → single INFO finding (not one per line)."""
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_specific=[
                "john ALL=(ALL) NOPASSWD:/usr/bin/apt",
                "john ALL=(ALL) NOPASSWD:/usr/bin/systemctl",
            ]
        ))
        infos = [f for f in result.findings if f.key == "file_perms.sudoers_nopasswd_specific"]
        assert len(infos) == 1

    def test_nopasswd_specific_does_not_produce_ok(self):
        """INFO finding → result.findings is not empty → OK is never appended."""
        result = check_file_perms(base_snapshot(
            sudoers_nopasswd_specific=["john ALL=(ALL) NOPASSWD:/usr/bin/apt"]
        ))
        assert not any(f.level == FindingLevel.OK for f in result.findings)


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_permissive_file_and_nopasswd_all(self):
        fi = make_file_info("/etc/shadow", mode=0o644, max_mode=0o640, key="shadow")
        result = check_file_perms(base_snapshot(
            sensitive_files=[fi],
            sudoers_nopasswd_all=["john ALL=(ALL) NOPASSWD:ALL"],
        ))
        assert _deduction_points(result) == 3  # 1 (shadow) + 2 (nopasswd)

    def test_world_writable_and_host_key(self):
        fi = make_file_info("/etc/passwd", mode=0o666, max_mode=0o644, key="passwd")
        result = check_file_perms(base_snapshot(
            sensitive_files=[fi],
            ssh_host_key_issues=[("/etc/ssh/ssh_host_rsa_key", 0o644)],
        ))
        assert _deduction_points(result) == 4  # 3 (world-write) + 1 (host key)

    def test_all_caps_combined_no_global_cap(self):
        """Caps are per-category, not global — all deductions accumulate freely."""
        # 3 too-permissive files (cap 3) + 2 SSH host keys (cap 2) + NOPASSWD:ALL (2) = 7
        files = [
            make_file_info("/etc/passwd",  mode=0o664, max_mode=0o644, key="passwd"),
            make_file_info("/etc/shadow",  mode=0o644, max_mode=0o640, key="shadow"),
            make_file_info("/etc/gshadow", mode=0o644, max_mode=0o640, key="gshadow"),
        ]
        result = check_file_perms(base_snapshot(
            sensitive_files=files,
            ssh_host_key_issues=[
                ("/etc/ssh/ssh_host_rsa_key",   0o644),
                ("/etc/ssh/ssh_host_ecdsa_key",  0o644),
            ],
            sudoers_nopasswd_all=["john ALL=(ALL) NOPASSWD:ALL"],
        ))
        assert _deduction_points(result) == 7   # 3 + 2 + 2

    def test_clean_snapshot_with_all_files_correct(self):
        files = [
            make_file_info("/etc/passwd",  mode=0o644, max_mode=0o644, key="passwd"),
            make_file_info("/etc/shadow",  mode=0o640, max_mode=0o640, key="shadow"),
            make_file_info("/etc/gshadow", mode=0o640, max_mode=0o640, key="gshadow"),
            make_file_info("/etc/group",   mode=0o644, max_mode=0o644, key="group"),
            make_file_info("/etc/sudoers", mode=0o440, max_mode=0o440, key="sudoers_file"),
        ]
        result = check_file_perms(base_snapshot(sensitive_files=files))
        assert _has_finding(result, "file_perms.ok", FindingLevel.OK)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# _is_nopasswd_all
# ---------------------------------------------------------------------------

class TestIsNopasswdAll:
    @pytest.mark.parametrize("line", [
        "john ALL=(ALL) NOPASSWD:ALL",
        "%sudo ALL=(ALL:ALL) NOPASSWD: ALL",
        "  root  ALL=(ALL) NOPASSWD:ALL",
        "john ALL=(ALL) nopasswd:all",          # lowercase
    ])
    def test_returns_true(self, line):
        assert _is_nopasswd_all(line)

    @pytest.mark.parametrize("line", [
        "john ALL=(ALL) NOPASSWD:/usr/bin/apt",
        "john ALL=(ALL) NOPASSWD:/usr/bin/systemctl status",
        "Defaults !requiretty",
        "john ALL=(ALL) ALL",   # no NOPASSWD keyword
        "",
        # "NOPASSWD: ALL /bin/sh" → after stripping ": \t" → "ALL /bin/sh" ≠ "ALL" → False
        # Strict exact-match prevents false-positives when a command list happens to start with ALL.
        "john ALL=(ALL) NOPASSWD: ALL /bin/sh",
    ])
    def test_returns_false(self, line):
        # Note: comment lines are filtered upstream in _collect_nopasswd_entries
        # before _is_nopasswd_all is ever called.
        assert not _is_nopasswd_all(line)


# ---------------------------------------------------------------------------
# FilePermsSnapshot construction
# ---------------------------------------------------------------------------

class TestFilePermsSnapshot:
    def test_dataclass_defaults(self):
        snap = FilePermsSnapshot()
        assert snap.sensitive_files == []
        assert snap.ssh_host_key_issues == []
        assert snap.sudoers_nopasswd_all == []
        assert snap.sudoers_nopasswd_specific == []

    def test_file_info_fields(self):
        fi = FileInfo(
            path="/etc/shadow", exists=True,
            mode=0o640, max_mode=0o640, key="shadow"
        )
        assert fi.path == "/etc/shadow"
        assert fi.exists
        assert fi.mode == 0o640
        assert fi.max_mode == 0o640
        assert fi.key == "shadow"
