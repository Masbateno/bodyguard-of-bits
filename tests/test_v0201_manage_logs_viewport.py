"""The last report in --manage-logs must actually be visible, not hidden.

`_browse_dir` is the one list screen with *two* header rows — the title bar
(row 0) and the dim directory path (row 1) — so its body starts at row 2. It
sized the body with `h - 1 - chrome_height` (one header row, like every other
screen) and compensated by drawing `range(body_h - 1)`, but the scroll math
still used the full `body_h`. When the cursor reached the last report the scroll
believed it was on screen while the draw loop never painted it: the bottom entry
sat behind the footer, selectable by cursor but never shown. Reported from a
real terminal — 152 reports, `[152]` hidden under the key bar.

This drives the real render (a recording screen, last-write-per-row wins, so the
footer painting over a body row is modelled) rather than a geometry helper, so a
regression that draws the row *into* the footer — where it is immediately
overwritten — fails here too, not only the one that never draws it.
"""

from __future__ import annotations

import sys
import time

import pytest


class _FakeCurses:
    A_BOLD = 1 << 0
    A_REVERSE = 1 << 1
    A_NORMAL = 0
    A_DIM = 1 << 2
    KEY_UP, KEY_DOWN, KEY_PPAGE, KEY_NPAGE, KEY_ENTER = 1001, 1002, 1003, 1004, 1005
    COLOR_BLACK, COLOR_RED, COLOR_GREEN, COLOR_YELLOW = 0, 1, 2, 3
    COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE = 4, 5, 6, 7

    class error(Exception):
        pass

    @staticmethod
    def curs_set(_n):  # noqa: D401 - no-op
        return 0

    @staticmethod
    def color_pair(n: int) -> int:
        return n << 8

    @staticmethod
    def has_colors() -> bool:
        # False → _init_colors_ml short-circuits, the screen renders monochrome,
        # and the palette's init_pair calls are never reached.
        return False


class _RecordingScreen:
    """Keeps the final text of each row: the last addstr to a row wins, exactly
    as a terminal cell shows whatever was painted last."""

    def __init__(self, h: int, w: int, keys):
        self._h, self._w = h, w
        self._keys = list(keys)
        self.rows: "dict[int, str]" = {}

    def getmaxyx(self):
        return self._h, self._w

    def erase(self):
        self.rows.clear()

    def addstr(self, row, col, text, attr=0):
        if row < 0 or row >= self._h:
            raise _FakeCurses.error("out of bounds")
        # col is 0 for every full-width row that matters here; later writes to a
        # row (the footer over a body row) replace it, which is the point.
        self.rows[row] = text

    def refresh(self):
        pass

    def getch(self):
        return self._keys.pop(0) if self._keys else 27  # 27 = Esc → exit


def _make_logs(tmp_path, n):
    base = 1_700_000_000
    for i in range(n):
        f = tmp_path / f"bob_2026{i:04d}_120000.log"
        f.write_text("score 7/10\n", encoding="utf-8")
        import os
        os.utime(f, (base - i * 3600, base - i * 3600))  # newest first, stable order


def _drive(tmp_path, keys, h=24, w=100):
    from bob import i18n
    i18n.init("en")
    real = sys.modules.get("curses")
    sys.modules["curses"] = _FakeCurses
    try:
        import bob.manage_logs as ml
        scr = _RecordingScreen(h, w, keys)
        ml._browse_dir(scr, tmp_path, {}, _cfg(), i18n.t)
        return scr
    finally:
        if real is not None:
            sys.modules["curses"] = real
        else:
            sys.modules.pop("curses", None)


class _cfg:
    no_color = True
    lang = "en"


def test_the_last_report_is_visible_after_jumping_to_the_bottom(tmp_path):
    """G jumps to the last report; the frame after must actually paint it."""
    n = 60
    _make_logs(tmp_path, n)
    scr = _drive(tmp_path, keys=[ord("G"), 27])  # bottom, then Esc
    marker = f"[{n:2}]"  # the number column, e.g. "[60]"
    final = "\n".join(scr.rows.values())
    assert marker in final, (
        f"the last report ({marker}) was not on screen after jumping to the "
        f"bottom — it is hidden behind the footer"
    )


def test_a_short_list_shows_every_report(tmp_path):
    """A list that fits leaves no entry unpainted."""
    n = 5
    _make_logs(tmp_path, n)
    scr = _drive(tmp_path, keys=[27])
    final = "\n".join(scr.rows.values())
    for i in range(1, n + 1):
        assert f"[{i:2}]" in final, f"[{i:2}] missing from a list that fits"


def test_no_body_row_is_painted_onto_the_footer(tmp_path):
    """The footer's rows must carry footer text, never a report line that the
    scroll math pushed one row too far down."""
    from bob.tui import _chrome as _ch
    from bob import i18n
    i18n.init("en")
    _make_logs(tmp_path, 60)
    scr = _drive(tmp_path, keys=[ord("G"), 27])
    h = 24
    chrome = _ch.chrome_height(i18n.t, _list_keys(), 100)
    for r in range(h - chrome, h):
        assert "  .log" not in scr.rows.get(r, "") and "] bob_" not in scr.rows.get(r, ""), (
            f"row {r} is a footer row but carries a report line"
        )


def _list_keys():
    import bob.manage_logs as ml
    return ml._LIST_KEYS
