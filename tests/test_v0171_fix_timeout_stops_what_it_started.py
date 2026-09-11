"""A fix that runs past its budget must be stopped, and reported honestly.

Measured on a Debian 13 VM, v0.17.1 development. BOB proposed
``sudo apt-get upgrade -y`` for pending updates, ran it under ``--fix --apply
--yes``, and printed::

    ✖ manual — apply the command manually (TimeoutExpired)
    0 of 1 fix(es) applied.

Both lines were false. ``subprocess.run(timeout=…)`` kills the direct child
and nothing below it; the direct child was *sudo*, so ``apt-get`` survived and
kept running — the VM still had pid 15962 ``apt-get upgrade -y`` with a
``dpkg --status-fd 23 --configure`` child and the apt lock held, minutes after
BOB had reported nothing applied and exited. The machine was left with
packages unpacked but not configured.

Two failures, guarded separately here: the timeout did not stop what it
started, and the report told the operator to run the command again by hand
while the first one was still mid-transaction.
"""

from __future__ import annotations

import errno
import io
import os
import signal
import subprocess
import sys
import time
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from bob.fixes import _run_fix_command, _timeout_for, run_fixes
import bob.fixes as _fixes


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    # A killed process lingers as a zombie until its parent reaps it, and
    # kill(pid, 0) still succeeds on a zombie. The grandchild's parent was
    # killed too, so it is reparented to PID 1 — which in a container with no
    # init never reaps it. Measured on python:3.14-slim: fails without
    # `--init`, passes with it. A zombie runs nothing; it is dead for the
    # purpose of this test, which is whether apt-get kept working.
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return True
    return state not in ("Z", "X")


def _describe(pid: int) -> str:
    """What the survivor is, captured at the moment the assertion fails.

    This test failed twice in full-suite runs and never in isolation. The
    first time nothing was recorded, so the cause could only be guessed at;
    the process's own view of itself is what tells a stray signal mask from
    a missed group, a zombie from a runner.
    """
    out = [f"survivor {pid}:"]
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        out.append(f"  state={fields[0]} ppid={fields[1]} pgrp={fields[2]} session={fields[3]}")
        with open(f"/proc/{pid}/status", encoding="ascii") as fh:
            out += [f"  {ln.strip()}" for ln in fh
                    if ln.startswith(("SigBlk", "SigIgn", "SigCgt", "PPid"))]
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            out.append("  cmdline=" + fh.read().replace(b"\0", b" ").decode(errors="replace")[:160])
    except OSError as exc:
        out.append(f"  /proc unreadable: {exc}")
    return "\n".join(out)


class TestTheTimeoutStopsTheWholeTree:
    """The exact shape of the incident: a wrapper with a child under it."""

    def test_the_grandchild_does_not_survive_the_timeout(self, tmp_path):
        # `sh -c` stands in for sudo: it is the direct child, and the sleep
        # underneath it is the apt-get that outlived BOB on the VM.
        pidfile = tmp_path / "grandchild.pid"
        script = (
            f'{sys.executable} -c "'
            "import os,time,sys;"
            f"open(r'{pidfile}','w').write(str(os.getpid()));"
            'time.sleep(120)" & wait'
        )
        status, rc, err = _run_fix_command(["sh", "-c", script], timeout=2)
        assert status == "timeout"

        deadline = time.time() + 20
        while time.time() < deadline and not pidfile.exists():
            time.sleep(0.05)
        assert pidfile.exists(), "the grandchild never started — test is inert"
        pid = int(pidfile.read_text())

        deadline = time.time() + 20
        while time.time() < deadline and _alive(pid):
            time.sleep(0.1)
        assert not _alive(pid), (
            f"{_describe(pid)}\n"
            f"pid {pid} outlived the timeout that claimed to stop it — "
            "this is the apt-get that kept running while BOB reported "
            "0 of 1 fix(es) applied"
        )

    def test_a_command_that_finishes_in_time_is_not_disturbed(self):
        status, rc, err = _run_fix_command(["sh", "-c", "exit 0"], timeout=30)
        assert (status, rc) == ("ok", 0)

    def test_a_failing_command_keeps_its_exit_code_and_stderr(self):
        status, rc, err = _run_fix_command(
            ["sh", "-c", "echo boom >&2; exit 3"], timeout=30)
        assert status == "failed"
        assert rc == 3
        assert b"boom" in err

    def test_the_child_leads_its_own_group(self):
        """Without a new session there is no group to signal."""
        seen = {}
        real = subprocess.Popen

        def spy(*args, **kwargs):
            seen.update(kwargs)
            return real(*args, **kwargs)

        with patch.object(_fixes.subprocess, "Popen", spy):
            _run_fix_command(["sh", "-c", "exit 0"], timeout=30)
        assert seen.get("start_new_session") is True

    def test_stdin_stays_closed(self):
        """An unattended fix must never sit waiting on a keyboard."""
        status, rc, err = _run_fix_command(
            ["sh", "-c", "read x; echo $x"], timeout=10)
        assert status in ("ok", "failed"), "read on a closed stdin should return"


class TestPackageTransactionsGetABudgetTheyCanFinishIn:
    """Thirty seconds was a budget for `ufw delete`, never for apt."""

    @pytest.mark.parametrize("cmd", [
        "sudo apt-get upgrade -y",
        "sudo apt upgrade -y",
        "sudo dnf upgrade -y",
        "sudo pacman -Syu --noconfirm",
        "sudo zypper --non-interactive up",
        "sudo apk upgrade",
        "sudo /usr/bin/apt-get install -y auditd",
    ])
    def test_package_commands_get_the_long_budget(self, cmd):
        import shlex
        assert _timeout_for(shlex.split(cmd)) == _fixes._TIMEOUT_PACKAGE

    @pytest.mark.parametrize("cmd", [
        "sudo ufw --force delete 1",
        "sudo systemctl restart ssh",
        "sudo chmod 600 /etc/shadow",
    ])
    def test_ordinary_commands_keep_the_short_one(self, cmd):
        import shlex
        assert _timeout_for(shlex.split(cmd)) == _fixes._TIMEOUT_DEFAULT

    def test_the_long_budget_is_minutes_not_seconds(self):
        assert _fixes._TIMEOUT_PACKAGE >= 300

    def test_every_package_fix_bob_ships_is_covered(self):
        """The buckets are decided from BOB's own catalogue, not from a hunch."""
        import shlex
        from bob.checks import _run as _runmod
        cmds = [_runmod.install_command(pkg) for pkg in ("auditd", "ufw", "fail2ban")]
        cmds = [c for c in cmds if c]
        assert cmds, "no install command to check — test is inert"
        for cmd in cmds:
            assert _timeout_for(shlex.split(cmd)) == _fixes._TIMEOUT_PACKAGE, cmd


class TestTheReportDoesNotLie:
    """What the operator reads after a timeout."""

    def _render(self, result):
        from tests.test_fixes import make_engine, make_finding, make_config, _t
        engine = make_engine(make_finding(cmd="sudo apt-get upgrade -y"))
        buf = io.StringIO()
        with patch("bob.fixes._run_fix_command", return_value=result), \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)
        return buf.getvalue()

    def test_a_timeout_is_never_dressed_as_manual(self):
        out = self._render(("timeout", None, b""))
        assert "fixes.manual" not in out, (
            "'apply the command manually' after a timeout is advice to start a "
            "second package transaction over an unfinished first one"
        )

    def test_a_timeout_names_itself_and_the_budget(self):
        out = self._render(("timeout", None, b""))
        assert "fixes.timed_out" in out

    def test_a_timeout_is_listed_where_the_operator_will_look(self):
        out = self._render(("timeout", None, b""))
        assert "fixes.unknown_items_title" in out
        assert "apt-get upgrade" in out

    def test_a_timeout_is_not_counted_as_applied(self):
        out = self._render(("timeout", None, b""))
        assert "fixes.done_summary" in out

    def test_a_clean_run_shows_no_unknown_block(self):
        out = self._render(("ok", 0, b""))
        assert "fixes.unknown_items_title" not in out


class TestBothLocalesSayIt:
    def test_the_two_keys_exist_everywhere(self):
        import json
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent / "bob" / "locales"
        for path in sorted(root.glob("*.json")):
            fixes = json.loads(path.read_text(encoding="utf-8"))["fixes"]
            for key in ("timed_out", "unknown_items_title"):
                assert key in fixes, f"{path.name} is missing fixes.{key}"
            assert "{seconds}" in fixes["timed_out"], path.name
