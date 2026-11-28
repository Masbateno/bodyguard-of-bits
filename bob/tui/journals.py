"""v0.43.0 (B-045) — the journals of what was done with BOB in ``--manage-logs``.

The landing screen's third choice: the three journals (team, cron, admin —
bob/journals.py), each with its chain's state; Enter opens one, read-only,
day by day as written. The same text as ``bob --journals show NAME``.

Like every module under bob/tui, this one never imports curses at top level.
"""

from __future__ import annotations

from bob.tui import _keys

#: The list of journals: Enter opens one; p sets their ceiling (v0.44.0, B-050).
_LIST_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.CEILING) + _keys.NESTED_EXIT
#: One journal, read-only.
_READ_KEYS = _keys.NAVIGATION + _keys.NESTED_EXIT


def rows(t) -> "list[tuple[str, str]]":
    """One line per journal: its chain's state and its size (bob/journals.state_rows)."""
    from bob import journals as J
    return J.state_rows(t)


def ceiling_text(t) -> str:
    """The journals' ceiling and what happens past it (bob/journals.show)."""
    from bob import fix_journal as FJ
    from bob.manage_logs import _format_size
    return t("journals.ceiling_line", ceiling=_format_size(FJ.ceiling(), t),
             default=_format_size(FJ.CEILING_DEFAULT, t), max=_format_size(FJ.CEILING_MAX, t))


def _ceiling_action(stdscr, t) -> str:
    """``p``: the ceiling typed on the context line, warned and confirmed there
    (v0.44.0, B-050 — decided with the user: 8 MiB by default, up to 16 MiB)."""
    from bob import journals as J
    from bob import manage_logs as ml
    from bob import team
    from bob.tui import _chrome as _ch
    text = ml._context_input(stdscr, t, None, t("journals.max_size_prompt"))
    if not text or not text.strip():
        return _ch.info(t("manage_logs.cancelled"))
    said: "list[str]" = []
    try:
        tone, lines = J.set_max_size(text, t, say=said.append,
                                     ask=lambda q: ml._context_confirm(stdscr, t, None, q))
    except team.TeamError as exc:
        return _ch.refused(t(f"team.err.{exc.key}", **exc.vars))
    message = " — ".join(lines + [m.strip(" ⚠") for m in said if m.strip()])
    return _ch.done(message) if tone == "done" else _ch.info(message)


def run(stdscr, curses, t, has_color: bool) -> None:
    """The list of journals, until Esc."""
    from bob import journals as J
    from bob.tui import _chrome
    from bob.tui import fixlog as _fl
    names = list(J.CHANNELS)
    cursor, scroll, status = 0, 0, ""
    title = "  bob --manage-logs    " + t("manage_logs.journals_title")
    while True:
        h, w = stdscr.getmaxyx()
        body = [("  " + text, kind) for text, kind in rows(t)]
        selectable = list(range(0, len(body)))
        # The ceiling under the list, wrapped on its own: the rows above keep
        # one line each, the cursor's index stays the journal's.
        body += [("", "body")] + _fl._wrap([("  " + ceiling_text(t), "info")], w)
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, _LIST_KEYS, w))
        _fl._draw(stdscr, curses, t, title, body, _LIST_KEYS, has_color, scroll, cursor, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _LIST_KEYS)
        if act == _keys.BACK:
            return
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, selectable, body_h)
        elif act == _keys.CEILING:
            status = _ceiling_action(stdscr, t)
        elif act == _keys.SELECT:
            name = names[selectable.index(cursor)]
            lines, code = J.journal_lines(name, t)
            kind = {0: "ok", 2: "alert"}.get(code, "warn")
            text = [(lines[0], kind)] + [(line, "body") for line in lines[1:]]
            _fl._read(stdscr, curses, t, title + " › " + name, _fl._wrap(text, w), _READ_KEYS, has_color)
