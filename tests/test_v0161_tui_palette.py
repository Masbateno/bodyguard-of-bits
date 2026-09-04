"""v0.16.1 — one colour chart, and the cursor no longer looks like the banner.

The selected row and the top banner both sat on `COLOR_CYAN`, in all three
curses screens, because the chart was written out three times and the three
copies agreed. The cursor row therefore read as a second banner. Selection is
now orange, which nothing else claims.

These guards protect two distinct things: that the chart exists in exactly one
place, and that the two elements the defect confused stay visually apart.
"""

from __future__ import annotations

import ast
import os
import re
import select
import sys
import time
from pathlib import Path

import pytest

from bob.tui._palette import (
    ACCENT,
    BANNER,
    NORMAL,
    NOTICE,
    ORANGE_256,
    SELECTION,
    init_palette,
    selection_background,
)

REPO = Path(__file__).resolve().parent.parent
SCREENS = ("bob/explain.py", "bob/manage_logs.py", "bob/tui/cron.py")


class _FakeCurses:
    """Records init_pair calls. Stands in for a terminal that has colour."""

    COLOR_BLACK, COLOR_RED, COLOR_YELLOW, COLOR_WHITE, COLOR_CYAN = 0, 1, 3, 7, 6
    error = RuntimeError

    def __init__(self, colors: int = 256, has: bool = True):
        self.COLORS = colors
        self._has = has
        self.pairs: dict[int, tuple[int, int]] = {}
        self.started = False

    def has_colors(self):
        return self._has

    def start_color(self):
        self.started = True

    def use_default_colors(self):
        pass

    def init_pair(self, n, fg, bg):
        self.pairs[n] = (fg, bg)


# ---------------------------------------------------------------------------
# The chart lives in one place
# ---------------------------------------------------------------------------

class TestOneSourceOfTruth:

    @pytest.mark.parametrize("rel", SCREENS)
    def test_no_screen_defines_its_own_pairs(self, rel):
        """Three copies is how the three screens stayed identically wrong."""
        tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "init_pair"
        ]
        assert not calls, (
            f"{rel} calls init_pair directly — the chart must come from "
            "bob/tui/_palette.py so the screens cannot drift apart again"
        )

    @pytest.mark.parametrize("rel", SCREENS)
    def test_every_screen_initialises_through_the_palette(self, rel):
        src = (REPO / rel).read_text(encoding="utf-8")
        assert "init_palette" in src, f"{rel} never initialises the shared chart"


# ---------------------------------------------------------------------------
# The defect itself: cursor row vs banner
# ---------------------------------------------------------------------------

class TestTheCursorIsNotTheBanner:

    @pytest.mark.parametrize("colors", [8, 16, 88, 256])
    def test_selection_background_is_never_the_banner_background(self, colors):
        fake = _FakeCurses(colors=colors)
        assert init_palette(fake) is True
        assert fake.pairs[SELECTION][1] != fake.pairs[BANNER][1], (
            f"with COLORS={colors} the cursor row and the banner share a "
            "background — the defect v0.16.1 fixed"
        )

    def test_a_256_colour_terminal_gets_real_orange(self):
        fake = _FakeCurses(colors=256)
        init_palette(fake)
        assert fake.pairs[SELECTION][1] == ORANGE_256

    def test_an_8_colour_terminal_falls_back_to_the_nearest_colour(self):
        fake = _FakeCurses(colors=8)
        init_palette(fake)
        assert fake.pairs[SELECTION][1] == fake.COLOR_YELLOW

    def test_a_terminal_that_lies_about_COLORS_does_not_crash(self):
        class _Liar(_FakeCurses):
            @property
            def COLORS(self):
                raise RuntimeError("no such capability")

            @COLORS.setter
            def COLORS(self, _v):
                pass

        assert selection_background(_Liar()) == _Liar.COLOR_YELLOW


class TestThePerScreenSlot:

    def test_notice_defaults_to_red(self):
        fake = _FakeCurses()
        init_palette(fake)
        assert fake.pairs[NOTICE][0] == fake.COLOR_RED

    def test_notice_can_be_overridden(self):
        """--explain uses pair 4 as a detail heading, not as a warning."""
        fake = _FakeCurses()
        init_palette(fake, notice=fake.COLOR_CYAN)
        assert fake.pairs[NOTICE][0] == fake.COLOR_CYAN

    def test_the_other_four_pairs_are_not_negotiable(self):
        a, b = _FakeCurses(), _FakeCurses()
        init_palette(a)
        init_palette(b, notice=b.COLOR_CYAN)
        for pair in (SELECTION, ACCENT, NORMAL, BANNER):
            assert a.pairs[pair] == b.pairs[pair]


class TestNoColourTerminal:

    def test_reports_failure_and_defines_nothing(self):
        fake = _FakeCurses(has=False)
        assert init_palette(fake) is False
        assert not fake.pairs
        assert not fake.started


# ---------------------------------------------------------------------------
# And on a real terminal
# ---------------------------------------------------------------------------

_CHILD = r"""
import curses, sys
sys.path.insert(0, {repo!r})
from bob.i18n import init as i18n_init, t as _t
i18n_init("en")
from bob.tui.cron import _curses_schedule_wizard, _WizardEntry, _init_colors_cron

class _C:
    lang = "en"
    no_color = True

def main(scr):
    _init_colors_cron()
    return _curses_schedule_wizard(scr, _WizardEntry("n"), _C(), _t)

try:
    curses.wrapper(main)
except BaseException as exc:
    sys.stderr.write("\n@@ERR %s\n" % exc)
"""


def _capture_screen(term: str, timeout: float = 8.0) -> str:
    import pty

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = term
        os.execv(sys.executable, [sys.executable, "-c", _CHILD.format(repo=str(REPO))])
    buf, deadline = b"", time.time() + timeout
    try:
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.3)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 4096:
                break
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        os.waitpid(pid, 0)
        os.close(fd)
    return buf.decode("utf-8", "replace")


class TestOnARealTerminal:

    def test_a_256_colour_terminal_actually_emits_orange(self):
        pytest.importorskip("curses")
        if not hasattr(__import__("pty"), "fork"):
            pytest.skip("no pty.fork on this platform")

        out = _capture_screen("xterm-256color")
        if "@@ERR" in out or not out.strip():
            pytest.skip("no usable terminfo for xterm-256color here")

        assert f"48;5;{ORANGE_256}" in out, (
            "the selected row did not reach the terminal as orange"
        )

    def test_the_banner_stays_cyan_beside_it(self):
        pytest.importorskip("curses")
        if not hasattr(__import__("pty"), "fork"):
            pytest.skip("no pty.fork on this platform")

        out = _capture_screen("xterm-256color")
        if "@@ERR" in out or not out.strip():
            pytest.skip("no usable terminfo for xterm-256color here")

        assert re.search(r"\[[0-9;]*46m", out), "the banner is no longer cyan"
        assert f"48;5;{ORANGE_256}" in out, "the cursor row is no longer orange"
