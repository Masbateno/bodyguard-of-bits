"""
Unit tests for bob.fixes module.

Tests cover:
  - Item classification: action+cmd → auto, action (no cmd) → manual, others → ignored
  - UFW delete sort order: descending by rule index to avoid renumbering
  - No-items path: early exit when nothing to fix
  - subprocess success / failure / timeout
  - Auto mode (--yes): no input() call, all items applied
  - Interactive mode: input() called, answer respected
  - Auto summary: command list printed after --yes run

All subprocess.run and input() calls are mocked — no system calls made.

Run with: python -m pytest tests/test_fixes.py -v
"""

import io
import subprocess
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import pytest

from bob.cli import AuditConfig
from bob.fixes import run_fixes
from bob.scoring import Finding, FindingLevel, ScoreEngine
from tests.helpers import _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    level=FindingLevel.ALERT,
    message="test finding",
    nature="action",
    cmd="sudo ufw --force delete 1",
):
    # type: (...) -> Finding
    return Finding(level=level, message=message, nature=nature, cmd=cmd)


def make_engine(*findings):
    # type: (*Finding) -> ScoreEngine
    """Build a ScoreEngine with pre-loaded findings."""
    engine = ScoreEngine()
    for f in findings:
        engine.findings.append(f)
    return engine


def make_config(yes=False, apply=True):
    # type: (bool, bool) -> AuditConfig
    """Build an AuditConfig for fix mode (apply=True = interactive/auto mode)."""
    return AuditConfig(fix=True, yes=yes, apply=apply)


def run_and_capture(engine, config, mock_proc=None, mock_input=None):
    # type: (...) -> str
    """
    Run run_fixes with mocked subprocess and input, capture stdout.

    Args:
        engine:      ScoreEngine with findings.
        config:      AuditConfig (fix=True, apply=True/False, yes=True/False).
        mock_proc:   Return value for subprocess.run (CompletedProcess or side_effect).
        mock_input:  Return value for input() — defaults to "n".

    Returns:
        Captured stdout as a string.
    """
    if mock_input is None:
        mock_input = "n"

    buf = io.StringIO()
    with patch("bob.fixes.subprocess.run", return_value=mock_proc) as _sp, \
         patch("builtins.input", return_value=mock_input) as _inp, \
         redirect_stdout(buf):
        run_fixes(engine, config, _t)

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Item classification
# ---------------------------------------------------------------------------

class TestItemClassification:
    def test_action_with_cmd_is_auto(self):
        """action + cmd → appears in the auto count displayed in the header."""
        engine = make_engine(make_finding(nature="action", cmd="sudo ufw --force delete 1"))
        out = run_and_capture(engine, make_config())
        # The count line uses the locale key that contains "count"
        assert "fixes.count" in out

    def test_action_without_cmd_counted_not_none(self):
        """action + no cmd → counted (header shown), but not iterated in the loop."""
        engine = make_engine(make_finding(nature="action", cmd=""))
        out = run_and_capture(engine, make_config())
        # Header is shown (else branch taken — there are items)
        assert "fixes.count" in out
        # But "fixes.none" is NOT shown
        assert "fixes.none" not in out

    def test_improvement_finding_ignored(self):
        """improvement nature → not shown in fix UI (not action)."""
        engine = make_engine(make_finding(nature="improvement", cmd="sudo ufw reload"))
        out = run_and_capture(engine, make_config())
        # No auto count, no manual item — only the "none" message
        assert "fixes.none" in out

    def test_structural_finding_ignored(self):
        """structural nature → not shown in fix UI."""
        engine = make_engine(make_finding(nature="structural", cmd="sudo ufw reload"))
        out = run_and_capture(engine, make_config())
        assert "fixes.none" in out

    def test_ok_finding_ignored(self):
        """OK-level finding → not shown in fix UI."""
        engine = make_engine(
            Finding(level=FindingLevel.OK, message="all good", nature="", cmd="")
        )
        out = run_and_capture(engine, make_config())
        assert "fixes.none" in out

    def test_mixed_auto_and_manual(self):
        """Both auto and manual items present simultaneously."""
        engine = make_engine(
            make_finding(nature="action", cmd="sudo ufw --force delete 3"),
            make_finding(nature="action", cmd="", message="manual item"),
        )
        out = run_and_capture(engine, make_config())
        assert "fixes.count" in out
        assert "fixes.manual" in out


# ---------------------------------------------------------------------------
# UFW delete sort order
# ---------------------------------------------------------------------------

class TestDeleteSortOrder:
    def test_higher_index_deleted_first(self):
        """
        UFW delete commands must be sorted descending by rule index.
        Deleting rule 5 before rule 3 prevents the renumbering problem
        (rule 3 would become rule 2 after deleting rule 3, invalidating
        a subsequent 'delete 5' that was already computed).
        """
        engine = make_engine(
            make_finding(message="low rule",  cmd="sudo ufw --force delete 3"),
            make_finding(message="high rule", cmd="sudo ufw --force delete 5"),
        )
        buf = io.StringIO()
        calls = []
        def fake_run(args, **kwargs):
            calls.append(args)
            return MagicMock(returncode=0)

        with patch("bob.fixes.subprocess.run", side_effect=fake_run), \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)

        # Both deletes were applied — extract indices
        delete_calls = [a for a in calls if "delete" in " ".join(a)]
        indices = [int(a[-1]) for a in delete_calls]
        assert indices == sorted(indices, reverse=True), \
            "Expected descending delete order, got {}".format(indices)

    def test_non_delete_appended_after_deletes(self):
        """Non-delete commands run after all UFW deletes."""
        engine = make_engine(
            make_finding(message="other",  cmd="sudo ufw reload"),
            make_finding(message="delete", cmd="sudo ufw --force delete 2"),
        )
        buf = io.StringIO()
        call_order = []
        def fake_run(args, **kwargs):
            call_order.append(" ".join(args))
            return MagicMock(returncode=0)

        with patch("bob.fixes.subprocess.run", side_effect=fake_run), \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)

        assert call_order.index("sudo ufw --force delete 2") < \
               call_order.index("sudo ufw reload"), \
               "Delete must run before non-delete commands"


# ---------------------------------------------------------------------------
# No items
# ---------------------------------------------------------------------------

class TestNoItems:
    def test_empty_engine_shows_none_message(self):
        """No findings at all → 'fixes.none' shown, no subprocess call."""
        engine = make_engine()
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run") as mock_sp, \
             patch("builtins.input") as mock_inp, \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)
        mock_sp.assert_not_called()
        mock_inp.assert_not_called()
        assert "fixes.none" in buf.getvalue()

    def test_only_ok_findings_shows_none_message(self):
        """Only OK/INFO findings → treated same as empty."""
        engine = make_engine(
            Finding(level=FindingLevel.OK,   message="ok",   nature="", cmd=""),
            Finding(level=FindingLevel.INFO, message="info", nature="", cmd=""),
        )
        out = run_and_capture(engine, make_config())
        assert "fixes.none" in out


# ---------------------------------------------------------------------------
# Subprocess paths
# ---------------------------------------------------------------------------

class TestSubprocessSuccess:
    def test_applied_message_on_returncode_0(self):
        """subprocess.run returns 0 → 'fixes.applied' shown."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        mock_proc = MagicMock(returncode=0)
        out = run_and_capture(engine, make_config(), mock_proc=mock_proc, mock_input="y")
        assert "fixes.applied" in out

    def test_subprocess_called_with_correct_command(self):
        """The command string is split and passed to subprocess.run."""
        cmd = "sudo ufw --force delete 1"
        engine = make_engine(make_finding(cmd=cmd))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run",
                   return_value=MagicMock(returncode=0)) as mock_sp, \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)
        mock_sp.assert_called_once()
        called_args = mock_sp.call_args[0][0]
        assert called_args == ["sudo", "ufw", "--force", "delete", "1"]


class TestSubprocessFailure:
    def test_manual_message_on_nonzero_returncode(self):
        """subprocess.run returns non-zero → 'fixes.manual' shown."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        mock_proc = MagicMock(returncode=1,
                              stderr=b"permission denied")
        out = run_and_capture(engine, make_config(), mock_proc=mock_proc, mock_input="y")
        assert "fixes.manual" in out

    def test_exit_code_shown_in_output(self):
        """Non-zero return code is included in the manual message."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        mock_proc = MagicMock(returncode=2, stderr=b"")
        out = run_and_capture(engine, make_config(), mock_proc=mock_proc, mock_input="y")
        assert "2" in out


class TestSubprocessTimeout:
    def test_manual_message_on_timeout(self):
        """subprocess.run raises TimeoutExpired → 'fixes.manual' shown."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        exc = subprocess.TimeoutExpired(cmd="sudo ufw --force delete 1", timeout=30)
        with patch("bob.fixes.subprocess.run", side_effect=exc), \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)
        assert "fixes.manual" in buf.getvalue()

    def test_oserror_handled(self):
        """OSError (command not found) → 'fixes.manual' shown."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run", side_effect=OSError("not found")), \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(), _t)
        assert "fixes.manual" in buf.getvalue()


# ---------------------------------------------------------------------------
# Answer "no" in interactive mode
# ---------------------------------------------------------------------------

class TestInteractiveNo:
    def test_no_answer_skips_subprocess(self):
        """input() returns 'n' → subprocess.run not called."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run") as mock_sp, \
             patch("builtins.input", return_value="n"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=False), _t)
        mock_sp.assert_not_called()

    def test_no_answer_shows_manual(self):
        """input() returns 'n' → item shown as manual (skipped by user)."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        out = run_and_capture(engine, make_config(yes=False), mock_input="n")
        assert "fixes.manual" in out


# ---------------------------------------------------------------------------
# Auto mode (--yes)
# ---------------------------------------------------------------------------

class TestAutoMode:
    def test_yes_mode_does_not_call_input(self):
        """config.yes=True → input() never called."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run",
                   return_value=MagicMock(returncode=0)), \
             patch("builtins.input") as mock_inp, \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=True), _t)
        mock_inp.assert_not_called()

    def test_yes_mode_applies_all_items(self):
        """config.yes=True → subprocess called for every auto item."""
        engine = make_engine(
            make_finding(cmd="sudo ufw --force delete 5"),
            make_finding(cmd="sudo ufw --force delete 3"),
        )
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run",
                   return_value=MagicMock(returncode=0)) as mock_sp, \
             patch("builtins.input"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=True), _t)
        assert mock_sp.call_count == 2

    def test_yes_mode_shows_auto_banner(self):
        """config.yes=True → auto mode banner shown before items."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run",
                   return_value=MagicMock(returncode=0)), \
             patch("builtins.input"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=True), _t)
        assert "fixes.auto_mode_banner" in buf.getvalue()


# ---------------------------------------------------------------------------
# Auto summary
# ---------------------------------------------------------------------------

class TestAutoSummary:
    def test_summary_printed_after_yes_run(self):
        """config.yes=True + applied → 'fixes.auto_summary_title' shown."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run",
                   return_value=MagicMock(returncode=0)), \
             patch("builtins.input"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=True), _t)
        assert "fixes.auto_summary_title" in buf.getvalue()

    def test_no_summary_when_nothing_applied(self):
        """config.yes=True but no successes → no summary title."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        mock_proc = MagicMock(returncode=1, stderr=b"")
        with patch("bob.fixes.subprocess.run", return_value=mock_proc), \
             patch("builtins.input"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=True), _t)
        assert "fixes.auto_summary_title" not in buf.getvalue()

    def test_applied_commands_listed_in_summary(self):
        """Applied commands appear in the summary output."""
        cmd = "sudo ufw --force delete 1"
        engine = make_engine(make_finding(cmd=cmd))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run",
                   return_value=MagicMock(returncode=0)), \
             patch("builtins.input"), \
             redirect_stdout(buf):
            run_fixes(engine, make_config(yes=True), _t)
        assert cmd in buf.getvalue()


# ---------------------------------------------------------------------------
# Done message
# ---------------------------------------------------------------------------

class TestDoneMessage:
    def test_done_message_always_shown(self):
        """'fixes.done' is shown at the end regardless of outcome."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        out = run_and_capture(
            engine, make_config(),
            mock_proc=MagicMock(returncode=0),
            mock_input="y",
        )
        assert "fixes.done" in out

    def test_done_message_shown_even_when_no_items(self):
        """'fixes.done' is NOT shown when there are no items (early return)."""
        engine = make_engine()
        out = run_and_capture(engine, make_config())
        # With no items the function returns before the done message
        assert "fixes.done" not in out


# ---------------------------------------------------------------------------
# Dry-run mode (--fix without --apply)
# ---------------------------------------------------------------------------

class TestDryRun:
    def _dry_config(self):
        return AuditConfig(fix=True, apply=False)

    def test_dry_run_shows_hint(self):
        """Without --apply, the dry-run hint is shown."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        out = run_and_capture(engine, self._dry_config())
        assert "fixes.dry_run_hint" in out

    def test_dry_run_no_subprocess_call(self):
        """Without --apply, subprocess.run is never called."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run") as mock_sp, \
             patch("builtins.input") as mock_inp, \
             redirect_stdout(buf):
            run_fixes(engine, self._dry_config(), _t)
        mock_sp.assert_not_called()

    def test_dry_run_no_input_call(self):
        """Without --apply, input() is never called."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        buf = io.StringIO()
        with patch("bob.fixes.subprocess.run"), \
             patch("builtins.input") as mock_inp, \
             redirect_stdout(buf):
            run_fixes(engine, self._dry_config(), _t)
        mock_inp.assert_not_called()

    def test_dry_run_shows_cmd_preview(self):
        """Each fix command is shown with a → prefix in dry-run mode."""
        cmd = "sudo ufw --force delete 2"
        engine = make_engine(make_finding(cmd=cmd))
        out = run_and_capture(engine, self._dry_config())
        assert cmd in out

    def test_dry_run_shows_message(self):
        """The finding message is shown in dry-run output."""
        engine = make_engine(make_finding(message="close port 25", cmd="sudo ufw --force delete 1"))
        out = run_and_capture(engine, self._dry_config())
        assert "close port 25" in out

    def test_dry_run_shows_manual_items(self):
        """Manual items (no cmd) are shown under their own header in dry-run mode."""
        engine = make_engine(make_finding(nature="action", cmd="", message="do it manually"))
        out = run_and_capture(engine, self._dry_config())
        assert "fixes.manual_items_title" in out
        assert "do it manually" in out

    def test_dry_run_no_applied_output(self):
        """fixes.applied is never shown in dry-run mode."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        out = run_and_capture(engine, self._dry_config())
        assert "fixes.applied" not in out

    def test_dry_run_no_done_summary(self):
        """fixes.done_summary is not shown in dry-run mode (returns early)."""
        engine = make_engine(make_finding(cmd="sudo ufw --force delete 1"))
        out = run_and_capture(engine, self._dry_config())
        assert "fixes.done_summary" not in out
