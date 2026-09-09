"""BOB reads OpenRC, and says so in OpenRC's own vocabulary.

Until v0.18.0 every service on a host without systemd came back UNKNOWN. That
was honest and useless: Alpine, Gentoo and Devuan run OpenRC, and BOB had
nothing to say about any daemon on them.

Measured on Alpine Linux 3.22, which is where the whole contract comes from::

    rc-service sshd status        exit 0    * status: started
    rc-service crond status       exit 3    * status: stopped
    rc-service nexistepas status  exit 1    (no such service)
    rc-update show                sshd | default

Existence is settled by ``/etc/init.d/<name>``, not by the exit code, so
"the probe could not run" and "the daemon is stopped" stay different answers —
the mistake v0.17.1 had to undo four times, including on this machine.

**This is a breaking change.** Hosts that reported UNKNOWN now report real
states, which become verdicts, which become deductions. A baseline taken on an
OpenRC host before v0.18.0 will differ.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from bob.checks import _run
from bob.checks._run import (
    CommandResult, openrc_enabled, openrc_state, service_enable_cmd,
    service_restart_cmd, unit_active_state,
)
from bob.checks.services import ServiceState, _openrc_unit_state


def _rc(code, stdout=""):
    return CommandResult(stdout, code == 0, "", code)


def _alpine(*, started=(), stopped=(), enabled=(), has_rc=True, has_systemd=False):
    """Stand in for an OpenRC host with exactly these services."""
    known = set(started) | set(stopped)

    def cmd_exists(c):
        return {"rc-service": has_rc, "systemctl": has_systemd}.get(c, False)

    def exists(p):
        return Path(p).name in known and "init.d" in str(p)

    def result(*argv, **kw):
        if argv[0] == "rc-service":
            name = argv[1]
            if name in started:
                return _rc(0, " * status: started")
            if name in stopped:
                return _rc(3, " * status: stopped")
            return _rc(1)
        if argv[0] == "rc-update":
            return _rc(0, "".join(f"  {n} | default\n" for n in enabled))
        return _rc(None)

    return (patch.object(_run, "_command_exists", side_effect=cmd_exists),
            patch.object(_run, "path_exists", side_effect=exists),
            patch.object(_run, "run_result", side_effect=result))


class TestTheExitStatusIsTheAnswer:
    def test_started_is_active(self):
        a, b, c = _alpine(started=("sshd",))
        with a, b, c:
            assert openrc_state("sshd") == "active"

    def test_stopped_is_inactive(self):
        a, b, c = _alpine(stopped=("crond",))
        with a, b, c:
            assert openrc_state("crond") == "inactive"

    def test_an_unknown_service_is_not_stopped(self):
        a, b, c = _alpine(started=("sshd",))
        with a, b, c:
            assert openrc_state("nexistepas") is None

    def test_a_host_without_openrc_says_nothing(self):
        a, b, c = _alpine(started=("sshd",), has_rc=False)
        with a, b, c:
            assert openrc_state("sshd") is None

    def test_a_probe_that_could_not_run_is_not_stopped(self):
        """`code is None` means the command never ran. It is not exit 3."""
        a, b, _ = _alpine(started=("sshd",))
        with a, b, patch.object(_run, "run_result", return_value=_rc(None)):
            assert openrc_state("sshd") is None


class TestEnabledness:
    def test_a_service_in_a_runlevel_is_enabled(self):
        a, b, c = _alpine(started=("sshd",), enabled=("sshd",))
        with a, b, c:
            assert openrc_enabled("sshd") is True

    def test_a_service_in_no_runlevel_is_not(self):
        a, b, c = _alpine(stopped=("crond",), enabled=("sshd",))
        with a, b, c:
            assert openrc_enabled("crond") is False

    def test_an_unknown_service_gets_no_answer(self):
        a, b, c = _alpine(started=("sshd",))
        with a, b, c:
            assert openrc_enabled("nexistepas") is None


class TestOneVocabularyForBothInitSystems:
    def test_unit_active_state_falls_through_to_openrc(self):
        a, b, c = _alpine(started=("sshd",))
        with a, b, c:
            assert unit_active_state("sshd") == "active"

    def test_systemd_keeps_precedence_when_it_answers(self):
        def result(*argv, **kw):
            if argv[0] == "systemctl":
                return _rc(0, "active")
            raise AssertionError("OpenRC was asked while systemd had an answer")
        with patch.object(_run, "run_result", side_effect=result):
            assert unit_active_state("ssh") == "active"

    @pytest.mark.parametrize("state,enabled,expected", [
        ("active", True, ServiceState.ACTIVE_ENABLED),
        ("active", False, ServiceState.ACTIVE_DISABLED),
        ("inactive", True, ServiceState.INACTIVE_ENABLED),
        ("inactive", False, ServiceState.INACTIVE_DISABLED),
        (None, None, ServiceState.UNKNOWN),
    ])
    def test_the_panorama_gets_the_same_four_states(self, state, enabled, expected):
        from bob.checks import services as _svc
        with patch.object(_svc, "openrc_state", return_value=state), \
             patch.object(_svc, "openrc_enabled", return_value=enabled):
            assert _openrc_unit_state("sshd") is expected


class TestTheCommandMatchesTheInitSystem:
    """`systemctl restart sshd` on Alpine is the wrong program, not a typo."""

    def test_openrc_hosts_get_rc_service(self):
        with patch.object(_run, "openrc_available", return_value=True), \
             patch.object(_run, "_command_exists", side_effect=lambda c: c != "systemctl"):
            assert service_restart_cmd("sshd") == "sudo rc-service sshd restart"

    def test_openrc_splits_enable_into_two_verbs(self):
        with patch.object(_run, "openrc_available", return_value=True), \
             patch.object(_run, "_command_exists", side_effect=lambda c: c != "systemctl"):
            cmd = service_enable_cmd("sshd")
            assert "rc-update add sshd default" in cmd
            assert "rc-service sshd start" in cmd

    def test_systemd_hosts_are_unchanged(self):
        with patch.object(_run, "openrc_available", return_value=False):
            assert service_restart_cmd("ssh") == "sudo systemctl restart ssh"
            assert service_enable_cmd("ssh") == "sudo systemctl enable --now ssh"

    def test_a_host_with_both_prefers_systemd(self):
        with patch.object(_run, "openrc_available", return_value=True), \
             patch.object(_run, "_command_exists", return_value=True):
            assert service_restart_cmd("ssh") == "sudo systemctl restart ssh"


class TestTheExitStatusIsCarried:
    """Without it, "exited 3" and "could not run" are the same False."""

    def test_command_result_reports_the_code(self):
        from bob.checks._run import run_result
        assert run_result("sh", "-c", "exit 3").code == 3
        assert run_result("true").code == 0

    def test_a_command_that_never_ran_has_no_code(self):
        from bob.checks._run import run_result
        assert run_result("no-such-binary-xyzzy").code is None
