"""The one colour chart every BOB curses screen uses.

Until v0.16.1 the chart existed three times — `bob/explain.py`,
`bob/manage_logs.py` and `bob/tui/cron.py` each called `init_pair` themselves
with the same five pairs. They agreed, which is why the readability defect
below was uniform rather than random, but nothing kept them agreeing.

**The defect.** The selected row and the top banner were both black-or-white on
`COLOR_CYAN`. On a screen where the banner sits two lines above the list, the
cursor row read as a second banner rather than as a cursor, and on a narrow
terminal the eye lost which line was selected. The selection now uses orange,
which no other element claims.

Orange is not one of the eight base curses colours. On a 256-colour terminal
this uses xterm index 208, a true orange; on an 8-colour terminal it falls back
to `COLOR_YELLOW`, the nearest thing available and still clearly distinct from
the cyan banner. Terminals with no colour at all keep the `A_REVERSE`
highlighting each screen already applies as its fallback.
"""

from __future__ import annotations

#: Semantic names for the five pairs. Screens should use these rather than
#: bare integers, so a future re-numbering stays a one-line change here.
SELECTION = 1   #: the row under the cursor
ACCENT    = 2   #: group headers, prompts, footer hints
NORMAL    = 3   #: ordinary rows
NOTICE    = 4   #: per-screen: warnings (red) or detail headings (cyan)
BANNER    = 5   #: the top title bar

#: xterm-256 index for orange. Used only when the terminal advertises 256
#: colours; see the module docstring for the fallback.
ORANGE_256 = 208


def selection_background(curses) -> int:
    """The selected row's background: true orange, or the closest available."""
    try:
        if getattr(curses, "COLORS", 0) >= 256:
            return ORANGE_256
    except Exception:          # a terminal that lies about its capabilities
        pass
    return curses.COLOR_YELLOW


def init_palette(curses, *, notice: "int | None" = None) -> bool:
    """Initialise the shared chart. Returns whether colour is available.

    Args:
        curses:  the module itself, passed in so this file never imports it —
            `bob.tui` may be absent in a headless `bob-core` build.
        notice:  colour for pair :data:`NOTICE`, whose meaning is per-screen
            (red for a warning list, cyan for a detail heading). Defaults to
            red. Every other pair is fixed: they are the chart.

    Callers must already be inside a `curses.wrapper` session.
    """
    if not curses.has_colors():
        return False
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(SELECTION, curses.COLOR_BLACK, selection_background(curses))
        curses.init_pair(ACCENT,    curses.COLOR_YELLOW, -1)
        curses.init_pair(NORMAL,    curses.COLOR_WHITE,  -1)
        curses.init_pair(NOTICE,    curses.COLOR_RED if notice is None else notice, -1)
        curses.init_pair(BANNER,    curses.COLOR_WHITE,  curses.COLOR_CYAN)
    except curses.error:
        return False
    return True
