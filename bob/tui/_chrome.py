"""The bottom chrome every wizard shares: a context line over a key banner.

v0.16.3 gave the five wizards one key contract; the hints were still drawn as
plain accent-coloured text, and two screens painted over them:

* ``--manage-logs`` replaced the whole key line with its delete confirmation,
  so the operator was asked to confirm a destructive action on a screen that
  had just hidden every key including the one to cancel;
* ``--install-cron`` drew each text prompt at ``h - 1``, directly on top of the
  footer it had just drawn.

Both were the same shape: one row at the bottom doing two jobs. The bottom is
two bands now — a reserved line for prompts and status, and under it the key
banner, which nothing overwrites.

The banner mirrors the cyan header: white on the tool's orange, padded to the
full width. It takes a second row rather than truncating when the hints do not
fit: on an 80-column terminal five screens overflow in French (the
``--manage-cron`` manager runs to 105 columns), and a ``[:w]`` slice would cut
from the right, which is where the exit hint sits.

Like :mod:`bob.tui._palette`, this module never imports curses: the
constants are resolved against a module handed in by the caller. ``bob-core``
ships without ``bob-tui`` and must still import, and the caller is already
inside a ``curses.wrapper`` session. tests/test_v0164_headless_import.py
holds it.
"""

from __future__ import annotations

from bob.tui import _keys
from bob.tui._palette import BANNER, CONTEXT, FOOTER


def banner_lines(t, actions: "tuple[str, ...]", width: int) -> "list[str]":
    """The key-hint rows for *actions* at *width*. One row, or two."""
    return _keys.footer_lines(t, actions, max(1, width - 2))


def chrome_height(t, actions: "tuple[str, ...]", width: int) -> int:
    """Rows the bottom chrome occupies: the banner plus its context line.

    A screen sizes its body with this. Every wizard used a hard ``h - 2``,
    which was already one short whenever the hints wrapped — the second banner
    row then landed on the last row of the body and hid an entry.
    """
    return len(banner_lines(t, actions, width)) + 1


def context_row(t, actions: "tuple[str, ...]", height: int, width: int) -> int:
    """The row reserved for a prompt or a status message."""
    return height - chrome_height(t, actions, width)


def draw(stdscr, curses, t, actions: "tuple[str, ...]", has_color: bool,
         *, context: str = "") -> None:
    """Paint the context line and the key banner at the bottom of *stdscr*.

    *context* is the prompt or status for this frame, or "" to leave the
    reserved line blank. It is reserved either way: a line that appears and
    disappears would move the banner under the operator's eyes.
    """
    h, w = stdscr.getmaxyx()
    draw_text(stdscr, curses, has_color, banner_lines(t, actions, w), context=context)


def draw_text(stdscr, curses, has_color: bool, lines: "list[str]",
              *, context: str = "") -> None:
    """Paint arbitrary banner rows, for a screen with no declared actions.

    ``_curses_status_flash`` waits for any key at all; its banner says exactly
    that rather than listing bindings it does not have. It goes through here so
    it cannot drift from the chrome the other screens use.
    """
    h, w = stdscr.getmaxyx()

    banner_attr = ((curses.color_pair(FOOTER) | curses.A_BOLD) if has_color
                   else curses.A_REVERSE)
    ctx_attr = curses.color_pair(CONTEXT) if has_color else curses.A_NORMAL

    for i, line in enumerate(reversed(lines)):
        _safe(stdscr, curses, h - 1 - i, line.ljust(w - 1)[:w - 1], banner_attr)
    _safe(stdscr, curses, h - 1 - len(lines),
          context.ljust(w - 1)[:w - 1], ctx_attr)


def draw_header(stdscr, curses, title: str, has_color: bool) -> None:
    """The cyan title bar, with the running version pinned to its right.

    Sixteen places across three modules wrote row 0 themselves, each composing
    its own title and each padding it its own way. Adding the version to all
    sixteen would have been sixteen chances to write it differently, which is
    how the key hints and the colour chart both drifted before they were
    centralised. It is written once, here.

    The version is right-aligned and dropped rather than truncated when the
    terminal is too narrow for both: a title cut in half to make room for a
    version number tells the operator less than a title alone.
    """
    from bob import __version__

    h, w = stdscr.getmaxyx()
    width = max(1, w - 1)
    attr = ((curses.color_pair(BANNER) | curses.A_BOLD) if has_color
            else curses.A_REVERSE)

    stamp = f"v{__version__}  "
    left = title[:width]
    if len(left) + len(stamp) + 2 <= width:
        line = left.ljust(width - len(stamp)) + stamp
    else:
        line = left.ljust(width)
    _safe(stdscr, curses, 0, line[:width], attr)


def _safe(stdscr, curses, row: int, text: str, attr: int) -> None:
    """addstr that tolerates a terminal too small for the row it is given."""
    if row < 0:
        return
    try:
        stdscr.addstr(row, 0, text, attr)
    except curses.error:
        pass
