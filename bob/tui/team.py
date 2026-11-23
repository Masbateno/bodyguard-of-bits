"""v0.43.0 (B-045) — ``bob --manage-team``: the team on a full screen.

Asked by the user (22 November 2026, evening): a real wizard, like
``--manage-logs`` — not a list of choices in the terminal the audit writes to.
Two choices on the landing screen: the team (master, members and their
attributes) and what is recorded (``--journals``); the journals themselves
are read in ``--manage-logs``.

Every change goes through the very code of the commands (``team.command``,
``journals.set_categories``): the same checks, the same traces, and the same
question outside a declared perimeter — asked here on the screen's context
row, what it has to say kept for the status line. Without a terminal,
``--manage-team`` falls back to the numbered menu (bob/team_wizard.py).

Like every module under bob/tui, this one never imports curses at top level.
"""

from __future__ import annotations

from bob import _names
from bob.tui import _keys

#: The landing screen: three choices; q exits, l switches language.
_HOME_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.pick(2)) + _keys.LANDING_EXIT
#: The team, like the report list of --manage-logs (the convention of every
#: list, asked by the user): Enter opens a member, Space marks one, a marks
#: all, d removes (the marked ones, else a selection — 2, 1,3, 2-4, all), n
#: adds an account. Once something is marked: Space, d, u (unmark).
_TEAM_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.TOGGLE, _keys.ALL, _keys.DELETE,
                                 _keys.NEW) + _keys.NESTED_EXIT
_TEAM_MARKED_KEYS = _keys.NAVIGATION + (_keys.TOGGLE, _keys.DELETE, _keys.UNMARK) + _keys.NESTED_EXIT
#: Adding accounts: Space marks, a marks all, Enter takes the marked ones (else
#: the current one); once something is marked, u unmarks.
_PICK_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.TOGGLE, _keys.ALL) + _keys.NESTED_EXIT
_PICK_MARKED_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.TOGGLE, _keys.UNMARK) + _keys.NESTED_EXIT
#: No team yet: Enter on "create the team".
_NOTEAM_KEYS = _keys.NAVIGATION + (_keys.SELECT,) + _keys.NESTED_EXIT
#: A list of boxes (a member's attributes, what is recorded): Space ticks, Enter applies.
_CHECK_KEYS = _keys.NAVIGATION + (_keys.TOGGLE, _keys.SUBMIT) + _keys.NESTED_EXIT

_TEAM_ICON = "\U0001f465"
_RECORD_ICON = "⚙"


class _Context:
    """The question and the messages of the team code, kept on the screen."""

    def __init__(self, stdscr, curses, t):
        from bob.tui import _chrome
        self.said: "list[str]" = []
        self.ask = lambda q: _chrome.ask_confirm(stdscr, curses, t, q)
        self.say = self.said.append

    def status(self, lines: "list[str]", fallback: str) -> str:
        """The status line: what was done, then anything the code had to say."""
        from bob.tui import _chrome
        extra = [m.strip(" ⚠") for m in self.said if m.strip()]
        if lines:
            return _chrome.done(" — ".join([" ".join(lines)] + extra))
        return _chrome.info(" — ".join([fallback] + extra))


def _command(stdscr, curses, t, args: "list[str]") -> str:
    """One ``--team`` command; the status line it leaves."""
    from bob import team
    from bob.tui import _chrome
    ctx = _Context(stdscr, curses, t)
    try:
        lines = team.command(args, t, ask=ctx.ask, say=ctx.say)
    except team.TeamError as exc:
        return _chrome.refused(t(f"team.err.{exc.key}", **exc.vars))
    return ctx.status(lines, t("team_wizard.cancelled"))


def _input(stdscr, t, prompt: str) -> "str | None":
    from bob import manage_logs as ml
    return ml._context_input(stdscr, t, None, prompt)


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

def _home_rows(t) -> "list[tuple[str, str]]":
    from bob import journals as J
    from bob import team
    try:
        decl = team.load()
    except team.TeamError as exc:
        decl, kind = None, "warn"
        first = t(f"team.err.{exc.key}", **exc.vars)
    else:
        kind = "body"
        first = (t("team_tui.home_team", master=decl.master, count=len(decl.members)) if decl
                 else t("team_tui.home_no_team"))
    off = J.load_settings().off
    recorded = t("team_tui.home_recorded", on=len(J.CATEGORIES) - len(off), total=len(J.CATEGORIES))
    # v0.43.0 (user, 23 November 2026) — the journals live in --manage-logs
    # only: a second door here was a duplicate.
    return [(f"1  {_TEAM_ICON} {first}", kind), (f"2  {_RECORD_ICON} {recorded}", "body")]


def _home(stdscr, curses, t, config, has_color, status: str = "", cursor: int = 0) -> str:
    """The landing screen; *cursor* is the choice just left (v0.43.0: coming
    back, the selection stays on it — CONVENTIONS.md)."""
    from bob.tui import fixlog as _fl
    title = "  bob --manage-team    " + t("team_wizard.title")
    while True:
        body = [("  " + text, kind) for text, kind in _home_rows(t)]
        _fl._draw(stdscr, curses, t, title, body, _HOME_KEYS, has_color, 0, cursor, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _HOME_KEYS)
        if act == _keys.QUIT:
            return "quit"
        if act == _keys.LANG:
            _keys.toggle_language(config)
        elif act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, [0, 1], 2)
        elif act == _keys.SELECT or (act and act.startswith("pick:")):
            choice = cursor if act == _keys.SELECT else ch - ord("1")
            return ("team", "recorded")[choice]


def _checks(stdscr, curses, t, has_color, title: str, items: "list[tuple[str, str]]",
            load, apply, status: str = "", all_label: "str | None" = None) -> None:
    """A list of boxes: Space ticks, Enter applies — and the screen stays, the
    boxes read again from what is now declared, the outcome on the status line
    (asked by the user: only the keys the banner offers act; nothing leaves the
    screen but Esc). *load* gives the ticked set, *apply* applies one and
    returns the status line. *all_label*: a first row that ticks every box —
    or unticks them all when all are ticked (v0.43.0, asked by the user)."""
    from bob.tui import _chrome
    from bob.tui import fixlog as _fl
    ticked = set(load())
    keys = [key for key, _label in items]
    top = 1 if all_label else 0
    cursor = 0
    rows = list(range(0, len(items) + top))
    while True:
        h, w = stdscr.getmaxyx()
        body = []
        if all_label:
            body.append((f"  [{'x' if set(keys) <= ticked else ' '}] {all_label}", "body"))
        body += [(f"  [{'x' if key in ticked else ' '}] {label}", "body") for key, label in items]
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, _CHECK_KEYS, w))
        _fl._draw(stdscr, curses, t, title, body, _CHECK_KEYS, has_color,
                  _fl._follow(cursor, 0, body_h), cursor, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _CHECK_KEYS)
        if act == _keys.BACK:
            return
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, rows, body_h)
        elif act == _keys.TOGGLE:
            if all_label and cursor == 0:
                ticked = set() if set(keys) <= ticked else set(keys)
            else:
                key = items[cursor - top][0]
                ticked.symmetric_difference_update({key})
        elif act == _keys.SUBMIT:
            status = apply(set(ticked))
            ticked = set(load())


def _attr_label(t, attr: str) -> str:
    from bob.domain_scores import LABELS
    if attr.startswith("fix:") and attr != "fix:*":
        return f"{attr:<22} {t('team_tui.attr.fix', domain=LABELS.get(attr[4:], attr[4:]))}"
    key = {"fix:*": "fix_all", "note-autres": "note_autres"}.get(attr, attr)
    return f"{attr:<22} {t(f'team_tui.attr.{key}')}"


def _member(stdscr, curses, t, has_color, accounts: "str | list[str]") -> str:
    """The attributes of one account — or of several, picked together: Enter
    applies through --team grant/revoke and the screen stays (Esc goes back).
    For several, the boxes start from what they all hold; an attribute is
    revoked only when its box was ticked and is unticked — one held by some
    of them only is never taken away unasked."""
    from bob import team
    from bob.tui import _chrome
    names = [accounts] if isinstance(accounts, str) else list(accounts)

    def held(account):
        decl = team.load()
        return set(decl.members.get(account, [])) if decl else set()

    def load():
        sets = [held(a) for a in names]
        return set.intersection(*sets) if sets else set()

    def apply(chosen):
        common = load()
        status = []
        for account in names:
            current = held(account)
            grant = [a for a in team.ATTRIBUTES if a in chosen - current]
            revoke = [a for a in team.ATTRIBUTES if a in (common - chosen) & current]
            if grant:
                status.append(_command(stdscr, curses, t, ["grant", account, ",".join(grant)]))
            if revoke:
                status.append(_command(stdscr, curses, t, ["revoke", account, ",".join(revoke)]))
        if not status:
            return _chrome.info(t("team_wizard.cancelled"))
        return " — ".join(status)

    items = [(a, _attr_label(t, a)) for a in team.ATTRIBUTES]
    title = "  bob --manage-team    " + t("team_tui.member_title", account=", ".join(names))
    _checks(stdscr, curses, t, has_color, title, items, load, apply,
            all_label=t("team_tui.all_attributes"))
    return ""


def _pick_accounts(stdscr, curses, t, has_color, decl) -> "list[str]":
    """The host's login accounts not yet declared: Space marks one, a marks
    them all, u unmarks; Enter takes the marked ones (else the current one).
    The last row lets one type another name (a system account, say)."""
    from bob import team
    from bob.tui import _chrome
    from bob.tui import fixlog as _fl
    names = team.candidate_accounts(decl)
    lo, hi = team.uid_range()
    head = t("team_tui.pick_head", low=lo, high=hi) if names else t("team_tui.no_candidates", low=lo, high=hi)
    rows = list(range(2, 2 + len(names) + 1))
    cursor = rows[0]
    marked: "set[str]" = set()
    title = "  bob --manage-team    " + t("team_tui.pick_title")
    while True:
        h, w = stdscr.getmaxyx()
        keys = _PICK_MARKED_KEYS if marked else _PICK_KEYS
        body = [("  " + head, "body"), ("", "body")]
        body += [(f"{' ✓' if n in marked else '  '}{i:>2}  {_names.mark(n)}", "body") for i, n in enumerate(names, 1)]
        body += [("  " + t("team_tui.other_account"), "ok")]
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, keys, w))
        _fl._draw(stdscr, curses, t, title, body, keys, has_color, 0, cursor, "")
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, keys)
        i = rows.index(cursor)
        if act == _keys.BACK:
            return []
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, rows, body_h)
        elif act == _keys.TOGGLE and i < len(names):
            marked.symmetric_difference_update({names[i]})
        elif act == _keys.ALL:
            marked = set(names)
        elif act == _keys.UNMARK:
            marked.clear()
        elif act == _keys.SELECT:
            if marked:
                return [n for n in names if n in marked]
            if i < len(names):
                return [names[i]]
            typed = _input(stdscr, t, t("team_tui.account_prompt"))
            return [typed.strip()] if typed and typed.strip() else []


def _remove(stdscr, curses, t, chosen: "list[str]") -> str:
    """Remove *chosen* after one confirmation naming them."""
    from bob.tui import _chrome
    if not _chrome.ask_confirm(stdscr, curses, t, t("team_tui.confirm_remove_many", accounts=", ".join(chosen))):
        return _chrome.info(t("team_wizard.cancelled"))
    return " — ".join(_command(stdscr, curses, t, ["remove", a]) for a in chosen)


def _team(stdscr, curses, t, has_color) -> None:
    from bob import team
    from bob.selection import SelectionError, parse_selection
    from bob.tui import _chrome
    from bob.tui import fixlog as _fl
    cursor, status = None, ""
    anchor: "str | None" = None
    marked: "set[str]" = set()
    title = "  bob --manage-team    " + t("team_tui.team_title")
    while True:
        h, w = stdscr.getmaxyx()
        try:
            decl = team.load()
        except team.TeamError as exc:
            decl, status = None, _chrome.refused(t(f"team.err.{exc.key}", **exc.vars))
        if decl is None:
            body = [("  " + t("team_tui.no_team"), "body"), ("", "body"),
                    ("  " + t("team_wizard.opt.init"), "ok")]
            _fl._draw(stdscr, curses, t, title, body, _NOTEAM_KEYS, has_color, 0, 2, status)
            status = ""
            ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
            act = _keys.resolve(curses, ch, _NOTEAM_KEYS)
            if act == _keys.BACK:
                return
            if act == _keys.SELECT and _chrome.ask_confirm(stdscr, curses, t, t("team_tui.confirm_init")):
                status = _command(stdscr, curses, t, ["init"])
            continue
        members = sorted(decl.members)
        marked &= set(members)
        keys = _TEAM_MARKED_KEYS if marked else _TEAM_KEYS
        body = [(f"  ★ {_names.cell(decl.master, 16)} {t('team_tui.master_all')}", "ok"), ("", "body")]
        # Numbered, a mark before the number: the convention of every list.
        body += [(f"{' ✓' if m in marked else '  '}{i:>2}  {_names.cell(m, 18)} "
                  f"{', '.join(team.perimeter(decl, m)) or t('team.no_attributes')}", "body")
                 for i, m in enumerate(members, 1)]
        if not members:
            body.append(("  " + t("team_wizard.no_members"), "body"))
        rows = list(range(2, 2 + len(members)))
        # v0.43.0 — the selection stays on the member just left (by name, the
        # list may have changed); a member removed leaves it at the same rank.
        if anchor in members:
            cursor = rows[members.index(anchor)]
        elif rows:
            cursor = min(cursor if cursor in rows or (cursor or 0) > rows[-1] else rows[0], rows[-1])
        else:
            cursor = None
        body_h = max(1, h - _chrome.BODY_TOP - _chrome.chrome_height(t, keys, w))
        _fl._draw(stdscr, curses, t, title, body, keys, has_color, 0, cursor, status)
        status = ""
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, keys)
        current = members[rows.index(cursor)] if cursor is not None else None
        if act == _keys.BACK:
            return
        if act in (_keys.MOVE, _keys.PAGE, _keys.EDGE) and cursor is not None:
            cursor = _fl._move(curses, act, ch, cursor, rows, body_h)
            anchor = members[rows.index(cursor)]
        elif act == _keys.TOGGLE and current:
            marked.symmetric_difference_update({current})
        elif act == _keys.ALL:
            marked = set(members)
        elif act == _keys.UNMARK:
            marked.clear()
        elif act == _keys.SELECT and current:
            anchor = current
            status = _member(stdscr, curses, t, has_color, current)
        elif act == _keys.NEW:
            picked = _pick_accounts(stdscr, curses, t, has_color, decl)
            if picked:
                anchor = picked[0]
                status = _member(stdscr, curses, t, has_color, picked)
        elif act == _keys.DELETE and members:
            if marked:
                status = _remove(stdscr, curses, t, sorted(marked))
                marked.clear()
                continue
            from bob import manage_logs as ml
            raw = ml._context_input(stdscr, t, None, t("team_tui.remove_prompt"))
            if not raw or not raw.strip():
                continue
            try:
                chosen = [members[n - 1] for n in parse_selection(raw, range(1, len(members) + 1))]
            except SelectionError as exc:
                status = _chrome.refused(t("selection." + exc.kind, **exc.vars))
                continue
            status = _remove(stdscr, curses, t, chosen)

def _recorded(stdscr, curses, t, has_color) -> str:
    """What is recorded; Enter applies through --journals on/off and the
    screen stays (Esc goes back)."""
    from bob import journals as J
    from bob import team
    from bob.tui import _chrome

    def load():
        return set(J.CATEGORIES) - J.load_settings().off

    def apply(chosen):
        off = J.load_settings().off
        turn_on = sorted(c for c in chosen if c in off)
        turn_off = sorted(c for c in J.CATEGORIES if c not in chosen and c not in off)
        if not turn_on and not turn_off:
            return _chrome.info(t("team_wizard.cancelled"))
        ctx = _Context(stdscr, curses, t)
        lines: "list[str]" = []
        try:
            for cats, on in ((turn_on, True), (turn_off, False)):
                if cats:
                    lines += J.set_categories(cats, on, t, ask=ctx.ask, say=ctx.say)
        except team.TeamError as exc:
            return _chrome.refused(t(f"team.err.{exc.key}", **exc.vars))
        return ctx.status(lines, t("team_wizard.cancelled"))

    items = [(c, f"{c:<10} {t(f'team_tui.category.{c}')} → {J.path(J.CATEGORIES[c])}") for c in J.CATEGORIES]
    title = "  bob --manage-team    " + t("team_wizard.opt.journals")
    _checks(stdscr, curses, t, has_color, title, items, load, apply,
            _chrome.info(t("team_tui.recorded_hint")), all_label=t("team_tui.all_categories"))
    return ""


def run(stdscr, config, t) -> int:
    """The landing screen and its two choices, until q."""
    import curses
    from bob import manage_logs as ml
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    has_color = ml._init_colors_ml()
    status = ""
    last = 0
    while True:
        choice = _home(stdscr, curses, t, config, has_color, status, cursor=last)
        status = ""
        if choice == "quit":
            return 0
        last = ("team", "recorded").index(choice)
        if choice == "team":
            _team(stdscr, curses, t, has_color)
        elif choice == "recorded":
            status = _recorded(stdscr, curses, t, has_color)
