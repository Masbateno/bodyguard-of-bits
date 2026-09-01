"""v0.15.3 — stderr was captured and thrown away.

`subprocess.run(capture_output=True)` fills `proc.stderr`; `run_result` dropped
it. That mattered in one measured case where stdout and the exit status both
look ordinary: `auditctl -l` reports a switched-off audit subsystem on stderr
while exiting 0 with an empty stdout — indistinguishable from a reachable audit
system holding no rules, which is what BOB was calling it.

"Rules could not be listed" and "the operator turned auditing off" are
different statements, and only the second is not a gap in the audit.

stderr stays untrusted subprocess text: it is matched against a known marker,
never rendered. The last test here enforces that.
"""

from unittest.mock import patch

import pytest

from bob.checks._run import CommandResult, run_result


class TestTheStreamIsKept:
    def test_stderr_reaches_the_caller(self):
        result = run_result("sh", "-c", "echo out; echo err >&2")
        assert result.stdout.strip() == "out"
        assert result.stderr.strip() == "err"

    def test_a_silent_command_leaves_it_empty(self):
        assert run_result("echo", "ok").stderr == ""

    def test_a_command_that_never_ran_leaves_it_empty(self):
        assert run_result("bob-no-such-binary").stderr == ""

    def test_two_field_construction_still_compares_equal(self):
        """Existing call sites build a CommandResult with two fields."""
        assert run_result("echo", "ok") == CommandResult("ok\n", True)


def _snapshot(stdout: str, stderr: str):
    """Drive the real collector with one `auditctl -l` answer."""
    from bob.checks import auditd as mod

    def fake_run_result(*args, **kwargs):
        if args and args[0] == "auditctl":
            return CommandResult(stdout, True, stderr)
        return CommandResult("", False, "")

    with (
        patch.object(mod, "run_result", side_effect=fake_run_result),
        patch.object(mod, "_command_exists", return_value=True),
        patch.object(mod, "unit_active_state", return_value="active"),
        patch.object(mod, "_run", return_value=""),
    ):
        return mod.AuditdSnapshot.from_system()


class TestDisabledIsNotUnreadable:
    """Both look like an empty stdout; only stderr tells them apart."""

    def test_a_switched_off_subsystem_is_named_as_such(self):
        snap = _snapshot("", "The audit system is disabled")
        assert snap.audit_disabled is True

    def test_a_refusal_is_still_a_gap(self):
        snap = _snapshot("", "Error - you must be root to run this program.")
        assert snap.audit_disabled is False
        assert snap.rules_readable is False

    def test_real_rules_are_read_normally(self):
        snap = _snapshot("-w /etc/passwd -p wa -k identity\n", "")
        assert snap.audit_disabled is False
        assert snap.rules_readable is True

    def test_the_literal_no_rules_answer_is_readable(self):
        """A reachable system holding none prints "No rules"."""
        snap = _snapshot("No rules\n", "")
        assert snap.rules_readable is True
        assert snap.audit_disabled is False

    @pytest.mark.parametrize("wording", [
        "The audit system is disabled",
        "the AUDIT SYSTEM IS DISABLED",
        "auditctl: The audit system is disabled\n",
    ])
    def test_the_marker_is_matched_case_insensitively(self, wording):
        assert _snapshot("", wording).audit_disabled is True


class TestTheVerdictsDiffer:
    def _keys(self, stdout, stderr):
        from bob.checks.auditd import check_auditd
        return {f.key for f in check_auditd(_snapshot(stdout, stderr)).findings}

    def test_disabled_says_disabled(self):
        keys = self._keys("", "The audit system is disabled")
        assert "auditd.subsystem_disabled" in keys
        assert "auditd.rules_unreadable" not in keys

    def test_refused_says_unreadable(self):
        keys = self._keys("", "you must be root")
        assert "auditd.rules_unreadable" in keys
        assert "auditd.subsystem_disabled" not in keys


class TestStderrIsNeverRendered:
    """Untrusted text matched, not repeated.

    A tool's stderr carries paths, hostnames and whatever the tool chose to
    say. SECURITY.md treats subprocess output as untrusted; putting it in a
    finding would hand that straight to every renderer.
    """

    def test_no_tool_wording_reaches_the_finding(self):
        from bob.checks.auditd import check_auditd
        marker = "SENSITIVE-/root/secret-PATH"
        snap = _snapshot("", f"The audit system is disabled ({marker})")
        for finding in check_auditd(snap).findings:
            for text in (finding.message, finding.detail or "", finding.key):
                assert marker not in text, f"stderr leaked into {finding.key}"

    def test_the_snapshot_stores_a_flag_not_the_text(self):
        snap = _snapshot("", "The audit system is disabled (/root/secret)")
        assert snap.audit_disabled is True
        assert not any(
            isinstance(v, str) and "/root/secret" in v
            for v in vars(snap).values()
        ), "the raw stderr was kept on the snapshot"
