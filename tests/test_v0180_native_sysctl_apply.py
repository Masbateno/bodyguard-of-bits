"""The sysctl fixes are applied by BOB's own code, not by a shell.

Thirteen of the fixes BOB proposes look like this::

    sudo sysctl -w net.ipv4.conf.all.rp_filter=1 && { grep -qxF … || echo … | sudo tee -a … ; }

`--fix --apply` refused all of them, and was right to. A pipeline hides its
left-hand failure — `/bin/sh` is dash, `pipefail` is off, `false | true` exits
0 — and `A && B` can leave a state neither half describes: the value live but
not persisted, which reverts at the next boot while the audit says OK.

The command is unchanged, because a one-liner is what a human reads. The same
change now also travels as data on the finding — ``{"kind": "sysctl", "param":
"net.ipv4.conf.all.rp_filter=1"}`` — and `bob/_sysctl_apply.py` carries it out:
set, persist through the atomic writer, then **read back**.

Measured end to end on a Debian 13 VM with three settings broken:

    before      0 0 1     no /etc/sysctl.d/99-hardening.conf
    --fix       2 automatic fixes → 5
    --apply     5 of 5 fix(es) applied.
    after       1 1 0     five lines in the file, one per key
    twice more  still five lines, still one rp_filter
    re-audit    ✔ Reverse path filtering enabled in strict mode (rp_filter=1)
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from bob import _sysctl_apply as mod
from bob._sysctl_apply import apply_sysctl, parse_param


def _proc(code, stderr=b""):
    return subprocess.CompletedProcess([], code, b"", stderr)


class TestNothingButAnAssignmentIsAccepted:
    @pytest.mark.parametrize("param,expected", [
        ("net.ipv4.conf.all.rp_filter=1", ("net.ipv4.conf.all.rp_filter", "1")),
        ("kernel.yama.ptrace_scope=1", ("kernel.yama.ptrace_scope", "1")),
        ("vm.swappiness=10", ("vm.swappiness", "10")),
        ("  net.ipv4.tcp_syncookies=1  ", ("net.ipv4.tcp_syncookies", "1")),
    ])
    def test_real_parameters_parse(self, param, expected):
        assert parse_param(param) == expected

    @pytest.mark.parametrize("param", [
        "rm -rf /", "a.b=1; id", "a.b=$(id)", "a.b=1 && reboot", "nokey", "",
        "a.b=`id`", "../../etc/passwd=1", "a.b=1\nc.d=2",
    ])
    def test_anything_else_is_refused(self, param):
        assert parse_param(param) is None, (
            f"{param!r} would reach argv; the table this comes from is exactly "
            "the kind of thing that grows an entry from somewhere else"
        )

    def test_a_refused_parameter_applies_nothing(self, tmp_path):
        with patch.object(mod.subprocess, "run") as run:
            result = apply_sysctl("rm -rf /", tmp_path / "conf")
        run.assert_not_called()
        assert result.applied is False


class TestItReadsBackBeforeClaimingAnything:
    def _apply(self, tmp_path, *, code=0, live="1", value="1"):
        conf = tmp_path / "99-hardening.conf"
        with patch.object(mod.subprocess, "run", return_value=_proc(code)), \
             patch.object(mod, "_read_live", return_value=live):
            return apply_sysctl(f"net.ipv4.conf.all.rp_filter={value}", conf), conf

    def test_the_happy_path_says_so(self, tmp_path):
        result, conf = self._apply(tmp_path)
        assert result.applied and result.persisted
        assert conf.read_text().strip() == "net.ipv4.conf.all.rp_filter = 1"

    def test_a_kernel_holding_another_value_is_not_success(self, tmp_path):
        """A write can be accepted and clamped; only the read-back settles it."""
        result, conf = self._apply(tmp_path, live="0", value="1")
        assert result.applied is False
        assert "kernel holds" in result.reason
        assert not conf.exists(), "it wrote the file for a value that did not take"

    def test_an_unreadable_key_is_not_success(self, tmp_path):
        conf = tmp_path / "c.conf"
        with patch.object(mod.subprocess, "run", return_value=_proc(0)), \
             patch.object(mod, "_read_live", return_value=None):
            result = apply_sysctl("net.ipv4.conf.all.rp_filter=1", conf)
        assert result.applied is False
        assert "cannot read" in result.reason

    def test_a_failing_sysctl_writes_nothing(self, tmp_path):
        result, conf = self._apply(tmp_path, code=1)
        assert result.applied is False
        assert not conf.exists()

    @pytest.mark.parametrize("exc", [OSError("no sysctl"),
                                     subprocess.TimeoutExpired("sysctl", 10)])
    def test_a_probe_that_never_ran_is_not_success(self, tmp_path, exc):
        with patch.object(mod.subprocess, "run", side_effect=exc):
            result = apply_sysctl("net.ipv4.conf.all.rp_filter=1", tmp_path / "c")
        assert result.applied is False


class TestLiveButNotPersistedIsReported:
    """The state the shell one-liner could reach silently."""

    def test_it_is_not_rounded_up_to_success(self, tmp_path):
        conf = tmp_path / "sub" / "c.conf"
        with patch.object(mod.subprocess, "run", return_value=_proc(0)), \
             patch.object(mod, "_read_live", return_value="1"), \
             patch.object(mod, "atomic_write", side_effect=OSError("read-only")):
            result = apply_sysctl("net.ipv4.conf.all.rp_filter=1", conf)
        assert result.applied is True
        assert result.persisted is False, (
            "live but not persisted reverts at the next reboot while the audit "
            "reports OK — the exact class v0.17.1 spent a release removing"
        )
        assert "OSError" in result.reason


class TestPersistingIsIdempotentByConstruction:
    def _write(self, tmp_path, existing, param="net.ipv4.conf.all.rp_filter=1"):
        conf = tmp_path / "99-hardening.conf"
        if existing is not None:
            conf.write_text(existing)
        with patch.object(mod.subprocess, "run", return_value=_proc(0)), \
             patch.object(mod, "_read_live", return_value="1"):
            apply_sysctl(param, conf)
        return conf.read_text()

    def test_applying_twice_leaves_one_line(self, tmp_path):
        first = self._write(tmp_path, None)
        second = self._write(tmp_path, first)
        assert second.count("rp_filter") == 1, (
            "the defect v0.17.1 fixed in the advice, made structural here"
        )

    def test_an_existing_value_is_replaced_not_appended(self, tmp_path):
        out = self._write(tmp_path, "net.ipv4.conf.all.rp_filter = 0\n")
        assert out.strip() == "net.ipv4.conf.all.rp_filter = 1"

    def test_other_keys_are_left_alone(self, tmp_path):
        out = self._write(tmp_path, "kernel.yama.ptrace_scope = 1\n")
        assert "kernel.yama.ptrace_scope = 1" in out
        assert "net.ipv4.conf.all.rp_filter = 1" in out

    def test_a_commented_line_is_not_mistaken_for_a_setter(self, tmp_path):
        out = self._write(tmp_path, "# net.ipv4.conf.all.rp_filter = 0\n")
        assert "# net.ipv4.conf.all.rp_filter = 0" in out


class TestEveryFindingWrapperCarriesTheAction:
    """A wrapper that drops it turns the whole section into "unavailable".

    Threading `fix_action` through `warn` but not `info` made
    `check_hardening` raise TypeError on a host where log_martians was
    disabled. BOB's fault isolation caught it and printed *"Section not
    evaluated — an internal error prevented this check from running"*, which is
    the honest thing to do and hid the defect from the suite for an afternoon.
    """

    @pytest.mark.parametrize("method,kwargs", [
        ("info", {}),
        ("warn", {}),
        ("alert", {}),
        ("warn_with_deduction", {"points": 1, "key": "k"}),
        ("alert_with_deduction", {"points": 1, "key": "k"}),
    ])
    def test_it_is_accepted_and_kept(self, method, kwargs):
        from bob.scoring import CheckResult
        action = {"kind": "sysctl", "param": "net.ipv4.conf.all.rp_filter=1"}
        result = CheckResult()
        getattr(result, method)(message="m", fix_action=action, **kwargs)
        assert result.findings[0].fix_action == action


class TestTheFixLoopUsesIt:
    def _run(self, finding_action):
        import io
        from contextlib import redirect_stdout
        from bob import fixes as fx
        from tests.test_fixes import make_engine, make_finding, make_config, _t
        f = make_finding(cmd="sudo sysctl -w a.b=1 && { grep -qxF a.b=1 x || y ; }")
        f.fix_action = finding_action
        buf = io.StringIO()
        with patch.object(fx, "_apply_native", return_value=("ok", 0, b"")) as native, \
             patch.object(fx, "_run_fix_command", return_value=("ok", 0, b"")) as shell, \
             patch("builtins.input", return_value="y"), redirect_stdout(buf):
            fx.run_fixes(make_engine(f), make_config(), _t)
        return native, shell, buf.getvalue()

    def test_a_native_action_bypasses_the_shell_path(self):
        native, shell, out = self._run({"kind": "sysctl", "param": "a.b=1"})
        native.assert_called_once()
        shell.assert_not_called()
        assert "fixes.skipped_unsafe_shell" not in out, (
            "the execution-time shell barrier fired on a fix that runs no shell"
        )

    def test_without_one_nothing_runs_it(self):
        """The selection filter catches it first — the v0.16.4 design.

        `_can_apply_unattended` decides before consent is given, so a shell
        one-liner with no native action never reaches either applier; it is
        listed under "BOB can only show you where to look". The execution-time
        barrier is the second line of defence, reached only when the two
        disagree — as they did the first time this change was made.
        """
        native, shell, out = self._run({})
        native.assert_not_called()
        shell.assert_not_called()
        assert "fixes.diagnostic_items_title" in out
