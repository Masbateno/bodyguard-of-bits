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
from bob.tui._palette import (BANNER, CONTEXT, CONTEXT_ERROR, CONTEXT_INFO, CONTEXT_OK,
                               CONTEXT_PROMPT, FOOTER, KEYCAP)

#: v0.39.0 — what a context line says, and its colour (see _palette). A status
#: carries its meaning in its first glyph, as in the text output: ✔ done,
#: ✖ refused or failed, ℹ information. A prompt is declared as one.
PROMPT, OK, ERROR, INFO = "prompt", "ok", "error", "info"
_TONE_PAIR = {PROMPT: CONTEXT_PROMPT, OK: CONTEXT_OK, ERROR: CONTEXT_ERROR, INFO: CONTEXT_INFO}
_GLYPH_TONE = {"✔": OK, "✖": ERROR, "ℹ": INFO}


def tone_of(text: str) -> str:
    """The tone a status line's first glyph gives it; "" for none."""
    head = text.lstrip()[:1]
    return _GLYPH_TONE.get(head, "")


def done(text: str) -> str:
    """A status saying an action took effect."""
    return f"✔ {text}"


def refused(text: str) -> str:
    """A status saying an action was refused or failed: nothing was changed."""
    return f"✖ {text}"


def info(text: str) -> str:
    """A status that only informs (an action cancelled by the operator)."""
    return f"ℹ {text}"


def confirm_text(t, question: str) -> str:
    """The one wording of a confirmation in a wizard: the question, then how to
    answer it (decided with the user, 19 November 2026: every deletion asks it
    this way, as --manage-logs did — --manage-cron's address book deleted
    without asking, and its job list asked without saying how to answer)."""
    return f"{question}  {t('tui.confirm_suffix')}"


#: The banner under a confirmation: ``y``; the question says that any other
#: key cancels. The screen's own banner stayed under it, announcing keys that
#: only cancelled (v0.39.0: a screen announces exactly the keys it answers to).
CONFIRM_ACTIONS = (_keys.CONFIRM,)


def ask_confirm(stdscr, curses, t, question: str) -> bool:
    """Ask *question* on the context line, in the prompts' colour, over the
    confirmation's banner: ``y`` confirms, any other key cancels."""
    draw(stdscr, curses, t, CONFIRM_ACTIONS, curses.has_colors(),
         context=f"  {confirm_text(t, question)}", tone=PROMPT)
    stdscr.refresh()
    return stdscr.getch() in (ord("y"), ord("Y"))


def context_attr(curses, has_color: bool, tone: str) -> int:
    """How the context line is drawn for *tone*."""
    if not has_color:
        return curses.A_BOLD if tone else curses.A_NORMAL
    pair = curses.color_pair(_TONE_PAIR.get(tone, CONTEXT))
    return pair | curses.A_BOLD if tone else pair


def banner_lines(t, actions: "tuple[str, ...]", width: int) -> "list[str]":
    """The key-hint rows for *actions* at *width*. One row, or two."""
    return _keys.footer_lines(t, actions, max(1, width - 2))


def banner_caps(t, actions: "tuple[str, ...]", width: int) -> "list[list[tuple[int, int]]]":
    """The key caps of :func:`banner_lines`, row by row (v0.40.0)."""
    return [caps for _line, caps in _keys.footer_layout(t, actions, max(1, width - 2))]


def keycap_attr(curses, has_color: bool) -> int:
    """A key's cap in the banner: black on white; without colours, plain video
    on the banner's reverse video, so the key still stands apart."""
    return curses.color_pair(KEYCAP) if has_color else curses.A_NORMAL


def chrome_height(t, actions: "tuple[str, ...]", width: int) -> int:
    """Rows the bottom chrome occupies: the banner plus its context line.

    A screen sizes its body with this. Every wizard used a hard ``h - 2``,
    which was already one short whenever the hints wrapped — the second banner
    row then landed on the last row of the body and hid an entry.
    """
    return len(banner_lines(t, actions, width)) + 1


def text_height(lines: "list[str]") -> int:
    """Rows :func:`draw_text` occupies: the given rows plus the context line.

    The sibling of :func:`chrome_height` for a screen with no declared actions.
    It exists so ``_curses_status_flash`` can size its body by asking rather
    than by assuming: it first asked ``chrome_height()`` with no arguments,
    which raises, and the screen it was sizing is the one that reports what
    just went wrong.
    """
    return len(lines) + 1


def context_row(t, actions: "tuple[str, ...]", height: int, width: int) -> int:
    """The row reserved for a prompt or a status message."""
    return height - chrome_height(t, actions, width)


def draw(stdscr, curses, t, actions: "tuple[str, ...]", has_color: bool,
         *, context: str = "", tone: "str | None" = None) -> None:
    """Paint the context line and the key banner at the bottom of *stdscr*.

    *context* is the prompt or status for this frame, or "" to leave the
    reserved line blank. It is reserved either way: a line that appears and
    disappears would move the banner under the operator's eyes.
    """
    h, w = stdscr.getmaxyx()
    draw_text(stdscr, curses, has_color, banner_lines(t, actions, w), context=context, tone=tone,
              caps=banner_caps(t, actions, w))


def draw_text(stdscr, curses, has_color: bool, lines: "list[str]",
              *, context: str = "", tone: "str | None" = None,
              caps: "list[list[tuple[int, int]]] | None" = None) -> None:
    """Paint arbitrary banner rows, for a screen with no declared actions.

    ``_curses_status_flash`` waits for any key at all; its banner says exactly
    that rather than listing bindings it does not have. It goes through here so
    it cannot drift from the chrome the other screens use.
    """
    h, w = stdscr.getmaxyx()

    banner_attr = ((curses.color_pair(FOOTER) | curses.A_BOLD) if has_color
                   else curses.A_REVERSE)
    # v0.39.0 — *tone* given (a prompt), or read from the status's glyph.
    ctx_attr = context_attr(curses, has_color, tone if tone is not None else tone_of(context))

    for i, line in enumerate(reversed(lines)):
        _safe(stdscr, curses, h - 1 - i, line.ljust(w - 1)[:w - 1], banner_attr)
    # v0.40.0 — each key in its cap, over the line just drawn.
    cap_attr = keycap_attr(curses, has_color)
    for i, row_caps in enumerate(reversed(caps or [])):
        line = lines[len(lines) - 1 - i]
        for start, end in row_caps:
            end = min(end, w - 1)
            if 0 <= start < end:
                _safe_at(stdscr, curses, h - 1 - i, start, line.ljust(w - 1)[start:end], cap_attr)
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

    stamp = f"{__version__}  "
    left = title[:width]
    if len(left) + len(stamp) + 2 <= width:
        line = left.ljust(width - len(stamp)) + stamp
    else:
        line = left.ljust(width)
    _safe(stdscr, curses, 0, line[:width], attr)


def _safe_at(stdscr, curses, row: int, col: int, text: str, attr: int) -> None:
    """addstr at a column, tolerating a terminal too small for it."""
    if row < 0:
        return
    try:
        stdscr.addstr(row, col, text, attr)
    except curses.error:
        pass


def _safe(stdscr, curses, row: int, text: str, attr: int) -> None:
    """addstr that tolerates a terminal too small for the row it is given."""
    if row < 0:
        return
    try:
        stdscr.addstr(row, 0, text, attr)
    except curses.error:
        pass
