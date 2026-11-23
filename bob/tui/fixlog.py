"""v0.40.0 — the journal of ``--fix --apply`` in ``--manage-logs`` (B-031).

Decided with the user (20 November 2026): reached from the landing screen's
second choice, kept apart from the audit reports; one line per day, the most
recent first; Enter opens a day — its commands in the order they ran — and a
command — its detail and its notes, added, never edited. The verdict on the
journal (bob/fix_witness.py) heads the list of days, in its own colour: "the
moment the log has been falsified, it must be shown explicitly, or at least be
easy to demonstrate". The lines the system log holds and the journal no longer
does have their own screen, the proof of a cut.

Like every module under bob/tui, this one never imports curses at top level.
"""

from __future__ import annotations

import os

from bob.tui import _keys

#: The list of days: Enter opens one; r shows the lines cut from the journal,
#: announced only when there are some.
_FIXDAYS_KEYS = _keys.NAVIGATION + (_keys.SELECT,) + _keys.NESTED_EXIT
_FIXDAYS_CUT_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.REMOVED) + _keys.NESTED_EXIT
#: One day's commands: Enter opens one.
_FIXDAY_KEYS = _keys.NAVIGATION + (_keys.SELECT,) + _keys.NESTED_EXIT
#: One command: a adds a note — root only, announced only to root.
_FIXENTRY_KEYS = _keys.NAVIGATION + (_keys.NOTE_ADD,) + _keys.NESTED_EXIT
_FIXENTRY_RO_KEYS = _keys.NAVIGATION + _keys.NESTED_EXIT
#: The lines cut from the journal, as the system log holds them.
_FIXCUT_KEYS = _keys.NAVIGATION + _keys.NESTED_EXIT
_NOTE_INPUT_KEYS = (_keys.SUBMIT,) + _keys.NESTED_EXIT


def _is_root() -> bool:
    """Whether this account writes the journal, a note included: the account
    the journal belongs to — root (fix_journal._JOURNAL_UID), and in a test or
    the demonstration the account running it."""
    from bob import fix_journal as FJ
    return os.geteuid() == FJ._JOURNAL_UID


def _attrs(curses, has_color: bool) -> dict:
    from bob.tui._palette import ACCENT, CONTEXT_ERROR, CONTEXT_OK, VERBATIM
    if not has_color:
        return {"alert": curses.A_BOLD, "warn": curses.A_BOLD, "ok": curses.A_NORMAL,
                "verbatim": curses.A_NORMAL, "body": curses.A_NORMAL, "title": curses.A_BOLD}
    return {"alert": curses.color_pair(CONTEXT_ERROR) | curses.A_BOLD,
            "warn": curses.color_pair(ACCENT) | curses.A_BOLD,
            "ok": curses.color_pair(CONTEXT_OK) | curses.A_BOLD,
            "verbatim": curses.color_pair(VERBATIM),
            "body": curses.A_NORMAL,
            "title": curses.color_pair(ACCENT) | curses.A_BOLD}


def put_marked(stdscr, curses, row: int, col: int, text: str, attr: int, has_color: bool,
               width: int) -> None:
    """Draw *text* at (*row*, *col*), its account names (bob/_names.py) in the
    accounts' colour, the rest in *attr*, never past *width*. v0.43.0 — every
    screen that draws a line goes through here, so no mark ever reaches the
    terminal (one screen that did not, the report preview, showed ^N…^O)."""
    from bob import _names
    from bob.tui._palette import ACCENT, ACCOUNT, NEGATIVE, POSITIVE, VERBATIM
    pair = {"name": ACCOUNT, "good": POSITIVE, "bad": NEGATIVE, "neutral": ACCENT, "verbatim": VERBATIM}
    for piece, kind in _names.segments(text):
        piece = piece[:max(0, width - 1 - col)]
        if not piece:
            break
        if kind is None:
            piece_attr = attr
        elif has_color:
            piece_attr = curses.color_pair(pair[kind]) | curses.A_BOLD
        else:
            piece_attr = curses.A_BOLD
        try:
            stdscr.addstr(row, col, piece, piece_attr)
        except curses.error:
            pass
        col += len(piece)


def _draw(stdscr, curses, t, title: str, body: "list[tuple[str, str]]", keys, has_color: bool,
          scroll: int, cursor: "int | None", status: str) -> int:
    """One screen: the header, *body* from *scroll* with the row *cursor*
    highlighted, the chrome. Returns the body's height."""
    from bob import _names
    from bob.tui import _chrome
    from bob.tui._palette import SELECTION
    h, w = stdscr.getmaxyx()
    body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, keys, w))
    attrs = _attrs(curses, has_color)
    stdscr.erase()
    _chrome.draw_header(stdscr, curses, title, has_color)
    for row in range(body_h):
        i = scroll + row
        if i >= len(body):
            break
        text, kind = body[i]
        if i == cursor:
            attr = (curses.color_pair(SELECTION) | curses.A_BOLD) if has_color else curses.A_REVERSE
            text = _names.plain(text)[:w - 1].ljust(w - 1)
        else:
            attr = attrs.get(kind, curses.A_NORMAL)
        if i != cursor and any(c in text for c in (_names.OPEN, _names.GOOD, _names.BAD, _names.NEUTRAL,
                                                   _names.VERBATIM)):
            # v0.43.0 — account names in their colour (bob/_names.py).
            put_marked(stdscr, curses, row + _chrome.BODY_TOP, 0, text, attr, has_color, w)
            continue
        try:
            stdscr.addstr(row + _chrome.BODY_TOP, 0, _names.plain(text)[:w - 1], attr)
        except curses.error:
            pass
    _chrome.draw(stdscr, curses, t, keys, has_color, context=status)
    stdscr.refresh()
    return body_h


def _wrap(lines: "list[tuple[str, str]]", width: int) -> "list[tuple[str, str]]":
    """Long lines wrapped, never cut: a proof cut at the screen's edge proves
    nothing."""
    import re
    import textwrap
    from bob import _names
    out = []
    room = max(20, width - 2)
    for text, kind in lines:
        # v0.43.0 (user, 23 November 2026) — a line laid out in columns goes
        # on under its last column (after its last run of two spaces or more)
        # rather than six spaces in, which broke the alignment; plain prose
        # keeps the six. Measured on the visible text, the colour marks out.
        visible = _names.plain(text)
        cols = [m.end() for m in re.finditer(r"\S {2,}", visible[:room])]
        hang = cols[-1] if cols and cols[-1] <= room - 20 else 6
        pieces = textwrap.wrap(text, room, subsequent_indent=" " * hang,
                               replace_whitespace=False, drop_whitespace=False) or [""]
        out.extend((p, kind) for p in pieces)
    return out


def _follow(cursor: int, scroll: int, body_h: int) -> int:
    if cursor - scroll >= body_h:
        scroll = cursor - body_h + 1
    return max(0, min(scroll, cursor))


def _move(curses, act: str, ch: int, cursor: int, rows: "list[int]", body_h: int) -> int:
    """The next selectable row for a navigation key."""
    if not rows:
        return cursor
    pos = rows.index(cursor) if cursor in rows else 0
    if act == _keys.MOVE:
        pos += _keys.direction(curses, ch)
    elif act == _keys.PAGE:
        pos += body_h * _keys.direction(curses, ch)
    elif act == _keys.EDGE:
        pos = 0 if _keys.is_top(ch) else len(rows) - 1
    return rows[max(0, min(len(rows) - 1, pos))]


def _read(stdscr, curses, t, title, body, keys, has_color, status: str = ""):
    """A text screen, scrolled until a key other than navigation; returns
    that key's action. *status* shows on the first draw."""
    from bob.tui import _chrome
    scroll = 0
    while True:
        h, w = stdscr.getmaxyx()
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, keys, w))
        _draw(stdscr, curses, t, title, body, keys, has_color, scroll, None, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, keys)
        top = max(0, len(body) - body_h)
        if act == _keys.MOVE:
            scroll = max(0, min(top, scroll + _keys.direction(curses, ch)))
        elif act == _keys.PAGE:
            scroll = max(0, min(top, scroll + body_h * _keys.direction(curses, ch)))
        elif act == _keys.EDGE:
            scroll = 0 if _keys.is_top(ch) else top
        elif act is not None:
            return act


def _load():
    from bob import fix_journal as FJ
    from bob import fix_witness as W
    journal = FJ.load()
    return journal, W.verify(journal)


def run(stdscr, curses, t, has_color: bool) -> None:
    """The journal's list of days, until Esc."""
    from bob import fix_journal as FJ
    from bob import fixlog as L
    from bob.tui import _chrome
    journal, verdict = _load()
    cursor, scroll, status = None, 0, ""
    while True:
        h, w = stdscr.getmaxyx()
        head = _wrap(L.verdict_lines(verdict, journal, t), w)
        days = FJ.days(journal)
        body = head + [("", "body")] + [L.day_row(day, entries, verdict, t) for day, entries in days]
        rows = list(range(len(head) + 1, len(body)))
        if cursor not in rows:
            cursor = rows[0] if rows else None
        keys = _FIXDAYS_CUT_KEYS if verdict.removed else _FIXDAYS_KEYS
        title = "  bob --manage-logs    " + t("manage_logs.fix_journal_title")
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, keys, w))
        scroll = _follow(cursor, scroll, body_h) if cursor is not None else scroll
        if cursor is not None and cursor == rows[0]:
            scroll = 0                       # the verdict stays in view at the top
        _draw(stdscr, curses, t, title, body, keys, has_color, scroll, cursor, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, keys)
        if act == _keys.BACK:
            return
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE) and cursor is not None:
            cursor = _move(curses, act, ch, cursor, rows, body_h)
        elif act == _keys.SELECT and cursor is not None:
            day, entries = days[rows.index(cursor)]
            _day(stdscr, curses, t, has_color, day)
            journal, verdict = _load()
        elif act == _keys.REMOVED and verdict.removed:
            body = _wrap([(t("fixlog.removed_title", count=len(verdict.removed)), "alert"), ("", "body")]
                         + L.removed_lines(verdict, t), w)
            _read(stdscr, curses, t, title + " › " + t("manage_logs.fix_cut_title"), body, _FIXCUT_KEYS,
                  has_color)


def _day(stdscr, curses, t, has_color: bool, day: str) -> None:
    """One day's commands, in the order they ran, until Esc."""
    from bob import fix_journal as FJ
    from bob import fixlog as L
    from bob.tui import _chrome
    cursor, scroll = 0, 0
    while True:
        journal, verdict = _load()
        entries = dict(FJ.days(journal)).get(day, [])
        if not entries:
            return
        h, w = stdscr.getmaxyx()
        body = [L.entry_row(e, verdict, t, w - 1) for e in entries]
        cursor = max(0, min(cursor, len(body) - 1))
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, _FIXDAY_KEYS, w))
        scroll = _follow(cursor, scroll, body_h)
        title = "  bob --manage-logs    " + t("manage_logs.fix_journal_title") + " › " + L.day_label(day, t)
        _draw(stdscr, curses, t, title, body, _FIXDAY_KEYS, has_color, scroll, cursor, "")
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _FIXDAY_KEYS)
        if act == _keys.BACK:
            return
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _move(curses, act, ch, cursor, list(range(len(body))), body_h)
        elif act == _keys.SELECT:
            _entry(stdscr, curses, t, has_color, entries[cursor].id, title)


def _entry(stdscr, curses, t, has_color: bool, entry_id: str, parent_title: str) -> None:
    """One command: its detail, what its witness says, its notes."""
    from bob import fix_journal as FJ
    from bob import fixlog as L
    from bob.tui import _chrome
    keys = _FIXENTRY_KEYS if _is_root() else _FIXENTRY_RO_KEYS
    status = ""
    while True:
        journal, verdict = _load()
        entry = next((e for e in journal.entries if e.id == entry_id), None)
        if entry is None:
            return
        _h, w = stdscr.getmaxyx()
        detail = L.entry_detail(entry, verdict, t)
        if keys is _FIXENTRY_RO_KEYS:
            # The user (20 November 2026): with a not announced, nothing said
            # a note could be added at all — say who can, and how.
            detail.append((t("manage_logs.fix_note_needs_root", cmd="sudo bob --manage-logs"), "warn"))
        body = _wrap(detail, w)
        title = parent_title + " › " + L.clock(entry.at)
        act = _read(stdscr, curses, t, title, body, keys, has_color, status)
        status = ""
        if act == _keys.BACK:
            return
        if act == _keys.NOTE_ADD:
            from bob.manage_logs import _context_input
            text = _context_input(stdscr, t, _NOTE_INPUT_KEYS, t("manage_logs.fix_note_prompt"))
            if text is None or not text.strip():
                status = _chrome.info(t("manage_logs.fix_note_cancelled"))
                continue
            try:
                FJ.add_note(entry.id, text)
                status = _chrome.done(t("manage_logs.fix_note_added"))
            except (FJ.FixJournalError, OSError) as exc:
                from bob.fixes import _journal_reason
                status = _chrome.refused(t("manage_logs.fix_note_failed", reason=_journal_reason(exc, t)))
