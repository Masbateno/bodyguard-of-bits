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

This module never imports curses: the constants are resolved against a
module handed in by the caller. ``bob-core`` ships without ``bob-tui``
and must still import, and two non-TUI modules import this one at top
level on the strength of that. tests/test_v0164_headless_import.py
holds it.
"""

from __future__ import annotations

#: Semantic names for the five pairs. Screens should use these rather than
#: bare integers, so a future re-numbering stays a one-line change here.
SELECTION = 1   #: the row under the cursor
ACCENT    = 2   #: group headers, prompts, footer hints
NORMAL    = 3   #: ordinary rows
NOTICE    = 4   #: per-screen: warnings (red) or detail headings (cyan)
BANNER    = 5   #: the top title bar
PROFILE   = 6   #: a [ profile ] section header in --explain
FOOTER    = 7   #: the bottom key banner — white on orange
CONTEXT   = 8   #: the line above it — prompts and status, on black

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
        # Same orange-or-yellow choice as the selected row, so the two
        # never disagree about which orange this tool uses.
        curses.init_pair(PROFILE,   selection_background(curses), -1)
        # The bottom chrome: a key banner mirroring the cyan header,
        # and one line above it reserved for prompts and status so a
        # confirmation no longer paints over the keys it asks about.
        curses.init_pair(FOOTER,    curses.COLOR_WHITE, selection_background(curses))
        curses.init_pair(CONTEXT,   curses.COLOR_WHITE, curses.COLOR_BLACK)
    except curses.error:
        return False
    return True

def marked_attr(curses, has_color: bool) -> int:
    """How a row the operator has toggled with Space is drawn.

    v0.16.3 — one answer, because there were four. ``--manage-logs`` drew a
    marked file in red bold; ``--manage-cron`` drew it yellow, which is the
    accent colour used for headers; and the two e-mail screens drew it in no
    colour at all, leaving only a ✔ to carry the state. A mark is a pending
    destructive selection on three of those four screens, so it reads red
    everywhere now.

    ``NOTICE`` is red on every screen except ``--explain``'s detail heading,
    and ``--explain`` has nothing to toggle. Where a screen also colours a
    property with the same pair — ``--manage-cron`` marks legacy entries — the
    mark stays bold and the property plain, so the two remain distinct.

    Without colour the row is underlined, which is what ``--manage-logs`` has
    always done and the only distinction a monochrome terminal has left once
    reverse video is spent on the cursor.
    """
    return (curses.color_pair(NOTICE) | curses.A_BOLD) if has_color else curses.A_UNDERLINE
