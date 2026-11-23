"""v0.43.0 (B-045) — the journals of what was done with BOB in ``--manage-logs``.

The landing screen's third choice: the three journals (team, cron, admin —
bob/journals.py), each with its chain's state; Enter opens one, read-only,
day by day as written. The same text as ``bob --journals show NAME``.

Like every module under bob/tui, this one never imports curses at top level.
"""

from __future__ import annotations

from bob.tui import _keys

#: The list of journals: Enter opens one.
_LIST_KEYS = _keys.NAVIGATION + (_keys.SELECT,) + _keys.NESTED_EXIT
#: One journal, read-only.
_READ_KEYS = _keys.NAVIGATION + _keys.NESTED_EXIT


def rows(t) -> "list[tuple[str, str]]":
    """One line per journal: its chain's state and its size (bob/journals.state_rows)."""
    from bob import journals as J
    return J.state_rows(t)


def run(stdscr, curses, t, has_color: bool) -> None:
    """The list of journals, until Esc."""
    from bob import journals as J
    from bob.tui import _chrome
    from bob.tui import fixlog as _fl
    names = list(J.CHANNELS)
    cursor, scroll = 0, 0
    title = "  bob --manage-logs    " + t("manage_logs.journals_title")
    while True:
        h, w = stdscr.getmaxyx()
        body = [("  " + text, kind) for text, kind in rows(t)]
        selectable = list(range(0, len(body)))
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, _LIST_KEYS, w))
        _fl._draw(stdscr, curses, t, title, body, _LIST_KEYS, has_color, scroll, cursor, "")
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _LIST_KEYS)
        if act == _keys.BACK:
            return
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, selectable, body_h)
        elif act == _keys.SELECT:
            name = names[selectable.index(cursor)]
            lines, code = J.journal_lines(name, t)
            kind = {0: "ok", 2: "alert"}.get(code, "warn")
            text = [(lines[0], kind)] + [(line, "body") for line in lines[1:]]
            _fl._read(stdscr, curses, t, title + " › " + name, _fl._wrap(text, w), _READ_KEYS, has_color)
