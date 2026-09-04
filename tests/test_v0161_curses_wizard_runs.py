"""v0.16.1 — the interactive --install-cron crashed for 40 released versions.

``_curses_schedule_wizard`` reads ``entry.time_simple`` unconditionally. That
field was added to ``CronEntry`` in v0.7.0 (M-1) and never added to
``_WizardEntry``, the stand-in the install flow passes, so ``sudo bob
--install-cron`` died with an AttributeError the moment a schedule was picked
— on every release from v0.7.0 to v0.16.0.

Nothing caught it because every existing test drives the *plain-text* wizard:
``run_install_cron`` dispatches on ``sys.stdout.isatty()``, and a pipe is not a
TTY, so feeding the wizard through a pipe silently exercises the other code
path. Two layers are needed, and both live here:

  * a static check that the wizard never reads a field its entry type lacks —
    cheap, deterministic, and it generalises to the next field someone adds;
  * an end-to-end run on a real pty — the only thing that proves the code path
    a human actually gets still works at all.
"""

from __future__ import annotations

import ast
import os
import select
import sys
import time
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parent.parent / "bob" / "tui" / "cron.py"
REPO = str(Path(__file__).resolve().parent.parent)


# ---------------------------------------------------------------------------
# Layer 1 — the wizard may not read a field its entry type does not have
# ---------------------------------------------------------------------------

class TestWizardEntryCoversEveryFieldTheWizardReads:

    @staticmethod
    def _attrs_read_off_entry() -> set[str]:
        """Every ``entry.<name>`` read inside the schedule wizard."""
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_curses_schedule_wizard")
        return {
            node.attr
            for node in ast.walk(fn)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "entry"
        }

    def test_every_field_exists_on_the_install_time_entry(self):
        from bob.tui.cron import _WizardEntry

        read = self._attrs_read_off_entry()
        assert read, "the AST sweep found no entry.* access — the guard has gone blind"

        missing = sorted(a for a in read if a not in _WizardEntry._fields)
        assert not missing, (
            f"_curses_schedule_wizard reads {missing} but _WizardEntry does not "
            "define it — every interactive --install-cron will raise "
            "AttributeError as soon as a schedule is picked"
        )

    def test_the_same_fields_exist_on_the_parsed_entry(self):
        """The wizard also serves the edit flow, which passes a real CronEntry."""
        from bob.cron._parse import CronEntry

        fields = set(getattr(CronEntry, "_fields", ()) or
                     {f.name for f in __import__("dataclasses").fields(CronEntry)})
        missing = sorted(a for a in self._attrs_read_off_entry() if a not in fields)
        assert not missing, f"CronEntry lacks {missing}"


# ---------------------------------------------------------------------------
# Layer 2 — actually run it, on a terminal
# ---------------------------------------------------------------------------

_CHILD = r"""
import curses, sys
sys.path.insert(0, {repo!r})
from bob.i18n import init as i18n_init, t as _t
i18n_init("en")
from bob.tui.cron import _curses_schedule_wizard, _WizardEntry

class _C:
    lang = "en"
    no_color = True

def main(scr):
    return _curses_schedule_wizard(scr, _WizardEntry("nightly"), _C(), _t)

try:
    sys.stderr.write("\n@@RESULT OK %s\n" % (curses.wrapper(main),))
except BaseException as exc:
    sys.stderr.write("\n@@RESULT CRASH %s: %s\n" % (type(exc).__name__, exc))
"""


def _run_wizard_on_a_pty(keys: list[bytes], timeout: float = 20.0) -> str:
    """Fork a pty, run the schedule wizard in it, feed keys, return its marker."""
    import pty

    pid, fd = pty.fork()
    if pid == 0:                                    # child — never returns
        os.environ["TERM"] = "xterm"
        os.environ.pop("BOB_DEBUG", None)
        os.execv(sys.executable, [sys.executable, "-c", _CHILD.format(repo=REPO)])

    buf, sent, deadline = b"", 0, time.time() + timeout
    try:
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.3)
            if ready:
                try:
                    buf += os.read(fd, 65536)
                except OSError:
                    break
            if b"@@RESULT" in buf:
                break
            if sent < len(keys):
                time.sleep(0.5)
                os.write(fd, keys[sent])
                sent += 1
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        os.waitpid(pid, 0)
        os.close(fd)

    text = buf.decode("utf-8", "replace")
    for line in text.splitlines():
        if "@@RESULT" in line:
            return line.split("@@RESULT", 1)[1].strip()
    return ""


class TestTheInteractiveWizardActuallyRuns:

    def test_picking_a_daily_schedule_returns_a_cron_expression(self):
        """Enter (daily) → Enter (03:00 default) → y (confirm)."""
        pytest.importorskip("curses")
        if not hasattr(__import__("pty"), "fork"):
            pytest.skip("no pty.fork on this platform")

        marker = _run_wizard_on_a_pty([b"\n", b"\n", b"y"])

        if not marker:
            # No terminfo, no pty allocation, a hostile CI tty — genuinely
            # inconclusive, and a skip is honest. A CRASH marker is NOT
            # inconclusive and must never reach here as a skip.
            pytest.skip("the pty run produced no verdict (no terminal available?)")

        assert not marker.startswith("CRASH"), (
            f"the interactive --install-cron wizard crashed: {marker}"
        )
        assert marker == "OK 0 3 * * *", marker
