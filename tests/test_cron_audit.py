"""
Tests for bob/checks/cron_audit.py — cron job security audit.

Coverage:
  - check_cron_audit(): all branches (pipe-to-shell, world-writable scripts,
    unexpected users, all-OK)
  - Deduction values and keys
  - Combined scenarios
  - CronAuditSnapshot dataclass construction
  - Edge cases: empty lists, None, duplicates

Note on deduction sign convention:
  Deduction.points is stored as a positive integer throughout the codebase
  (e.g. points=2 means "subtract 2 from the score"). _deduction_points()
  returns the sum of these positive values; comments indicating "-2 pts"
  describe the score effect, not the stored value.
"""

from __future__ import annotations

import pytest

from bob.checks.cron_audit import (
    CronAuditSnapshot,
    check_cron_audit,
    _chmod_cmd,
    _PIPE_TO_SHELL_RE,
)
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _deduction_points, _get_finding, _has_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_keys(result) -> list[str]:
    return [f.key for f in result.findings]


def base_snapshot(**kwargs) -> CronAuditSnapshot:
    """Return a clean CronAuditSnapshot with no risky patterns."""
    defaults = dict(
        pipe_to_shell_entries=[],
        world_writable_scripts=[],
        unexpected_user_crons=[],
    )
    defaults.update(kwargs)
    return CronAuditSnapshot(**defaults)


# ---------------------------------------------------------------------------
# All OK
# ---------------------------------------------------------------------------

class TestAllOk:
    def test_empty_snapshot_returns_ok(self):
        result = check_cron_audit(base_snapshot())
        assert _has_finding(result, "cron_audit.ok", FindingLevel.OK)

    def test_empty_snapshot_no_deduction(self):
        result = check_cron_audit(base_snapshot())
        assert _deduction_points(result) == 0

    def test_ok_not_emitted_when_finding_present(self):
        snap = base_snapshot(pipe_to_shell_entries=["entry"])
        result = check_cron_audit(snap)
        assert not _has_finding(result, "cron_audit.ok", FindingLevel.OK)


# ---------------------------------------------------------------------------
# Pipe-to-shell patterns
# ---------------------------------------------------------------------------

class TestPipeToShell:
    def test_pipe_entry_produces_warn(self):
        snap = base_snapshot(pipe_to_shell_entries=["/etc/cron.d/update: curl http://x | sh"])
        result = check_cron_audit(snap)
        assert _has_finding(result, "cron_audit.pipe_to_shell", FindingLevel.WARN)

    def test_pipe_entry_deducts_2_points(self):
        # business rule: penalty is flat per category regardless of occurrence count
        snap = base_snapshot(pipe_to_shell_entries=["entry"])
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 2  # stored as +2, effect is score −2

    def test_pipe_entry_deduction_key(self):
        snap = base_snapshot(pipe_to_shell_entries=["entry"])
        result = check_cron_audit(snap)
        assert "cron_audit.pipe_to_shell" in _deduction_keys(result)

    def test_flat_deduction_regardless_of_count(self):
        # business rule: multiple pipe-to-shell entries → single flat penalty
        snap = base_snapshot(pipe_to_shell_entries=["e1", "e2", "e3"])
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 2

    def test_nature_is_action(self):
        snap = base_snapshot(pipe_to_shell_entries=["entry"])
        result = check_cron_audit(snap)
        finding = _get_finding(result, "cron_audit.pipe_to_shell")
        assert finding is not None
        assert finding.nature == "action"

    def test_duplicate_pipe_entries_single_deduction(self):
        """Duplicate entries in the list must not inflate deductions."""
        snap = base_snapshot(pipe_to_shell_entries=["e1", "e1", "e1"])
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 2


# ---------------------------------------------------------------------------
# World-writable scripts
# ---------------------------------------------------------------------------

class TestWorldWritableScripts:
    def test_world_writable_produces_warn(self):
        snap = base_snapshot(world_writable_scripts=["/etc/cron.daily/backup.sh"])
        result = check_cron_audit(snap)
        assert _has_finding(result, "cron_audit.world_writable", FindingLevel.WARN)

    def test_world_writable_deducts_1_point(self):
        # business rule: flat penalty regardless of number of world-writable scripts
        snap = base_snapshot(world_writable_scripts=["/etc/cron.daily/backup.sh"])
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 1  # stored as +1, effect is score −1

    def test_world_writable_deduction_key(self):
        snap = base_snapshot(world_writable_scripts=["/tmp/script.sh"])
        result = check_cron_audit(snap)
        assert "cron_audit.world_writable" in _deduction_keys(result)

    def test_flat_deduction_regardless_of_script_count(self):
        # business rule: flat per category
        snap = base_snapshot(world_writable_scripts=["/a", "/b", "/c", "/d"])
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 1

    def test_nature_is_action(self):
        snap = base_snapshot(world_writable_scripts=["/tmp/script.sh"])
        result = check_cron_audit(snap)
        finding = _get_finding(result, "cron_audit.world_writable")
        assert finding is not None
        assert finding.nature == "action"

    def test_cmd_references_script_path(self):
        """The fix command must reference the affected script path."""
        snap = base_snapshot(world_writable_scripts=["/tmp/script.sh"])
        result = check_cron_audit(snap)
        finding = _get_finding(result, "cron_audit.world_writable")
        assert finding is not None
        assert "/tmp/script.sh" in finding.cmd

    def test_cmd_is_non_empty(self):
        """A world-writable finding must always carry a fix command."""
        snap = base_snapshot(world_writable_scripts=["/tmp/script.sh"])
        result = check_cron_audit(snap)
        finding = _get_finding(result, "cron_audit.world_writable")
        assert finding is not None
        assert finding.cmd


# ---------------------------------------------------------------------------
# Unexpected user crontabs
# ---------------------------------------------------------------------------

class TestUnexpectedUserCrons:
    def test_unexpected_user_produces_info(self):
        snap = base_snapshot(unexpected_user_crons=["alice"])
        result = check_cron_audit(snap)
        assert _has_finding(result, "cron_audit.unexpected_users", FindingLevel.INFO)

    def test_unexpected_user_no_deduction(self):
        snap = base_snapshot(unexpected_user_crons=["alice"])
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 0

    def test_unexpected_user_no_ok(self):
        snap = base_snapshot(unexpected_user_crons=["alice"])
        result = check_cron_audit(snap)
        assert not _has_finding(result, "cron_audit.ok", FindingLevel.OK)

    def test_multiple_unexpected_users(self):
        snap = base_snapshot(unexpected_user_crons=["alice", "bob"])
        result = check_cron_audit(snap)
        assert _has_finding(result, "cron_audit.unexpected_users", FindingLevel.INFO)
        assert _deduction_points(result) == 0


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_pipe_and_world_writable_total(self):
        # pipe-to-shell (score −2) + world-writable (score −1) = score −3
        snap = base_snapshot(
            pipe_to_shell_entries=["entry"],
            world_writable_scripts=["/tmp/s.sh"],
        )
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 3

    def test_all_three_issues(self):
        snap = base_snapshot(
            pipe_to_shell_entries=["entry"],
            world_writable_scripts=["/tmp/s.sh"],
            unexpected_user_crons=["alice"],
        )
        result = check_cron_audit(snap)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        infos = [f for f in result.findings if f.level == FindingLevel.INFO]
        assert len(warns) == 2
        assert len(infos) == 1
        assert _deduction_points(result) == 3

    def test_world_writable_and_user_cron(self):
        snap = base_snapshot(
            world_writable_scripts=["/tmp/s.sh"],
            unexpected_user_crons=["bob"],
        )
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 1
        assert _has_finding(result, "cron_audit.world_writable", FindingLevel.WARN)
        assert _has_finding(result, "cron_audit.unexpected_users", FindingLevel.INFO)


# ---------------------------------------------------------------------------
# _chmod_cmd helper
# ---------------------------------------------------------------------------

class TestChmodCmd:
    def test_single_script(self):
        assert _chmod_cmd(["/tmp/s.sh"]) == "sudo chmod o-w /tmp/s.sh"

    def test_multiple_scripts(self):
        cmd = _chmod_cmd(["/tmp/a.sh", "/tmp/b.sh"])
        assert cmd == "sudo chmod o-w /tmp/a.sh /tmp/b.sh"

    def test_empty_list_returns_empty_string(self):
        """An empty list must not produce an invalid shell command."""
        assert _chmod_cmd([]) == ""

    def test_cmd_quotes_path_with_special_chars(self):
        """Shell metacharacters in paths must be quoted — prevent injection."""
        cmd = _chmod_cmd(["/tmp/foo; rm -rf /"])
        assert cmd == "sudo chmod o-w '/tmp/foo; rm -rf /'"


# ---------------------------------------------------------------------------
# _PIPE_TO_SHELL_RE regex
# ---------------------------------------------------------------------------

class TestPipeToShellRegex:
    @pytest.mark.parametrize("line", [
        "curl http://example.com/install.sh | sh",
        "curl http://example.com/install.sh | bash",
        "wget -qO- http://example.com | sh",
        "wget http://x.com/s.sh | bash",
        "CURL http://x | SH",              # case insensitive
        "curl http://x |  sh",             # multiple spaces before shell
        "curl $URL | sh",                  # variable interpolation
        "curl http://x | bash -s",         # bash with flags
        "curl http://x | /bin/sh",         # absolute path to shell
        "wget http://x | zsh",             # zsh variant
    ])
    def test_matches_risky_patterns(self, line):
        assert _PIPE_TO_SHELL_RE.search(line), f"Should match: {line!r}"

    @pytest.mark.parametrize("line", [
        "curl http://example.com -o /tmp/file.sh",
        "wget http://example.com -O /tmp/file.sh",
        "/etc/cron.daily/backup.sh",
        "rsync -av /src /dst",
    ])
    def test_does_not_match_safe_patterns(self, line):
        assert not _PIPE_TO_SHELL_RE.search(line), f"Should not match: {line!r}"


# ---------------------------------------------------------------------------
# CronAuditSnapshot dataclass
# ---------------------------------------------------------------------------

class TestCronAuditSnapshot:
    def test_defaults(self):
        snap = CronAuditSnapshot()
        assert snap.pipe_to_shell_entries == []
        assert snap.world_writable_scripts == []
        assert snap.unexpected_user_crons == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_none_lists_produce_ok_finding(self):
        """None instead of empty lists must not crash check_cron_audit()."""
        snap = CronAuditSnapshot(
            pipe_to_shell_entries=None,
            world_writable_scripts=None,
            unexpected_user_crons=None,
        )
        result = check_cron_audit(snap)
        assert isinstance(result.findings, list)
        assert _has_finding(result, "cron_audit.ok", FindingLevel.OK)

    def test_none_lists_produce_no_deduction(self):
        """None fields must be treated as empty — no spurious deductions."""
        snap = CronAuditSnapshot(
            pipe_to_shell_entries=None,
            world_writable_scripts=None,
            unexpected_user_crons=None,
        )
        result = check_cron_audit(snap)
        assert _deduction_points(result) == 0

    def test_snapshot_not_mutated(self):
        """check_cron_audit() must not modify the snapshot."""
        snap = base_snapshot(pipe_to_shell_entries=["entry"])
        original = list(snap.pipe_to_shell_entries)
        check_cron_audit(snap)
        assert snap.pipe_to_shell_entries == original

    def test_max_deduction_is_three(self):
        """Maximum total deduction: pipe-to-shell (−2) + world-writable (−1) = 3."""
        snap = base_snapshot(
            pipe_to_shell_entries=["e1", "e2", "e3"],
            world_writable_scripts=["/a", "/b", "/c"],
            unexpected_user_crons=["alice", "bob"],
        )
        result = check_cron_audit(snap)
        assert _deduction_points(result) <= 3

    def test_finding_keys_independent_of_order(self):
        snap = base_snapshot(
            world_writable_scripts=["/tmp/s.sh"],
            pipe_to_shell_entries=["entry"],
        )
        result = check_cron_audit(snap)
        keys = set(_finding_keys(result))
        assert "cron_audit.pipe_to_shell" in keys
        assert "cron_audit.world_writable" in keys
