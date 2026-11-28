"""v0.44.0 (B-051) — from any wizard to any other, without leaving BOB.

Asked by the user (23 November 2026): "from any wizard, switch to any other
with shortcut keys". Decided with the user (27 November 2026):

- F2 ``--manage-logs``, F3 ``--manage-cron``, F4 ``--manage-team``, F5
  ``--explain``; Ctrl+G opens the menu of the four (see below). Measured by the
  user: all five reach curses in a local terminal, over ``ssh -t``, in tmux,
  and in tmux over ssh.
- Switching *replaces* the current wizard: Esc then climbs back to the new
  wizard's landing screen, as it always does; to go back, switch again.
- (27 November 2026) ``bob --bob-tui`` is the menu of every wizard: arrows and
  Enter, the digits, or F2-F5. Ctrl+G opens it, and so does Esc on any
  wizard's landing screen, wherever the wizard was opened from — an exception
  to "Esc goes back one step", written down in CONVENTIONS.md. ``q`` on a
  landing screen still leaves BOB, and so does ``q`` in the menu, where Esc
  does nothing: quitting already had its key (the user, 27 November 2026).

Every wizard screen announces the keys through the exit groups of
``bob/tui/_keys.py``; :func:`bob.tui._keys.resolve` raises ``SwitchScreen``
from whatever depth the key is pressed, and :func:`run` — the one curses
session every wizard now runs in — opens the next. A wizard refused to this
session (``--manage-logs`` and ``--manage-cron`` need root, as their own
commands do; ``--manage-logs`` has nothing to show before a first audit) is
said on a screen of its own, and Esc returns to the wizard it was asked from.

Like every module under bob/tui, this one never imports curses at top level.
"""

from __future__ import annotations

import os

from bob.tui import _keys

#: The wizards, in the order of their keys (F2 to F5).
TARGETS = ("logs", "cron", "team", "explain")
_FKEY = {"logs": "F2", "cron": "F3", "team": "F4", "explain": "F5"}
_COMMAND = {"logs": "bob --manage-logs", "cron": "bob --manage-cron",
            "team": "bob --manage-team", "explain": "bob --explain"}
#: As their own commands: these two pass the audit's root gate (bob/__main__.py).
NEEDS_ROOT = frozenset({"logs", "cron"})
_HUB_KEYS = _keys.NAVIGATION + (_keys.SELECT, _keys.pick(len(TARGETS)),
                                 _keys.SCREENS, _keys.LANG, _keys.QUIT)
_SAID_KEYS = (_keys.BACK,)


def refusal(target: str, user_config, t) -> "str | None":
    """Why *target* cannot open in this session, or None."""
    from bob._privilege import with_privilege
    if user_config is None:
        from bob.config import UserConfig
        user_config = UserConfig.load()
    if target in NEEDS_ROOT and os.geteuid() != 0:
        return t("switch.needs_root", cmd=with_privilege("sudo " + _COMMAND[target]))
    if target == "logs" and not _logs_to_show(user_config):
        return t("manage_logs.no_dir", cmd=with_privilege("sudo bob -d"))
    return None


def _logs_to_show(user_config) -> bool:
    """What ``--manage-logs`` itself checks before opening its screen."""
    from bob import fix_journal as _FJ
    from bob import journals as _J
    return bool(user_config.get("log_dir") or _FJ.path().exists()
                or any(_J.path(n).exists() for n in _J.CHANNELS))


def _launch(target: str, stdscr, user_config, config, t) -> int:
    if config is None:
        from bob.cli import AuditConfig
        config = AuditConfig()
    if target == "install":
        # --install-cron: --manage-cron's list, a new job begun (v0.44.0,
        # merged with the user's agreement on 27 November 2026).
        from bob.cron._install import _CronQuit
        from bob.tui.cron import _run_manage_cron_curses
        try:
            return _run_manage_cron_curses(stdscr, config, t, start_create=True)
        except _CronQuit:
            return 0
    if target == "logs":
        from bob import manage_logs
        if user_config is None:
            from bob.config import UserConfig
            user_config = UserConfig.load()
        return manage_logs._run_manage_logs_curses(stdscr, user_config, config, t)
    if target == "cron":
        from bob.cron._install import _CronQuit
        from bob.tui.cron import _run_manage_cron_curses
        try:
            return _run_manage_cron_curses(stdscr, config, t)
        except _CronQuit:
            return 0
    if target == "team":
        from bob.tui import team as team_tui
        return team_tui.run(stdscr, config, t)
    from bob import explain
    explain._explain_wizard(stdscr, explain._host_texts(t))
    return 0


def fresh(stdscr) -> bool:
    """Before each screen the switcher opens: the shared colours, and the
    terminal as a wizard expects to find it. Returns whether colour is on.

    Found by the user (27 November 2026): the menu, drawn first, came out in
    two greys — no wizard had set the colours yet (measured in a pty: no cyan
    background for its banner) — and switching left glitches behind, each
    wizard finding the screen as the last one had left it. So: the palette is
    initialised, the cursor hidden, the reads blocking, the keypad on, and the
    whole screen cleared (a full repaint, not a diff of the last frame)."""
    import curses
    from bob.tui import _palette
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    for name, arg in (("nodelay", False), ("keypad", True)):
        call = getattr(stdscr, name, None)
        if call is not None:
            try:
                call(arg)
            except curses.error:
                pass
    clear = getattr(stdscr, "clear", None)
    if clear is not None:
        clear()
    return _palette.init_palette(curses)


def run(stdscr, first: str, user_config, config, t, launch=None) -> int:
    """Run *first* — a wizard, or ``"hub"`` for the menu — then whatever a
    switch key, Ctrl+G or Esc on a landing screen asks for, until a wizard ends
    on its own (its landing screen's ``q``) or the menu is left. *launch* is a
    seam for the tests."""
    launch = launch or _launch
    current, came_from = first, None
    while True:
        fresh(stdscr)
        try:
            if current == "hub":
                target = hub(stdscr, t, came_from, config)
                if target is None:
                    return 0                # the menu left: BOB ends
            else:
                return launch(current, stdscr, user_config, config, t)
        except _keys.SwitchScreen as asked:
            target = asked.target or "hub"  # Ctrl+G (None) and Esc on a landing: the menu
        if target != "hub":
            why = refusal(target, user_config, t)
            if why:
                said(stdscr, t, target, why)
                continue                    # back to the wizard, or the menu, it was asked from
        if current != "hub":
            came_from = current
        current = target


def _entries(t, came_from: "str | None") -> "list[tuple[str, str]]":
    rows = []
    for i, target in enumerate(TARGETS, 1):
        here = "  ◂ " + t("switch.here") if target == came_from else ""
        rows.append((f"  {i}  {_FKEY[target]}  {t('switch.' + target)}{here}", "body"))
    return rows


def hub(stdscr, t, came_from: "str | None", config=None) -> "str | None":
    """``bob --bob-tui``: every wizard, numbered with its function key. Arrows
    and Enter, a digit, or F2-F5 (which ``resolve`` raises from here as from
    anywhere) open one; the wizard just left is marked and selected (coming
    back, the selection stays on it — CONVENTIONS.md). ``q`` leaves BOB:
    returns None. Esc is not announced here and does nothing — it quit BOB
    too until the user found it a duplicate of ``q`` (27 November 2026)."""
    import curses
    from bob.tui import fixlog as _fl
    from bob.tui import _palette
    has_color = _palette.init_palette(curses)
    title = "  bob --bob-tui    " + t("switch.title")
    cursor = TARGETS.index(came_from) if came_from in TARGETS else 0
    while True:
        body = _entries(t, came_from)
        _fl._draw(stdscr, curses, t, title, body, _HUB_KEYS, has_color, 0, cursor, "")
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        act = _keys.resolve(curses, ch, _HUB_KEYS)
        if act == _keys.QUIT:
            return None
        if act == _keys.LANG:
            _keys.toggle_language(config)
        elif act in (_keys.MOVE, _keys.PAGE, _keys.EDGE):
            cursor = _fl._move(curses, act, ch, cursor, list(range(len(TARGETS))), len(TARGETS))
        elif act == _keys.SELECT:
            return TARGETS[cursor]
        elif act and act.startswith("pick:"):
            return TARGETS[ch - ord("1")]


def said(stdscr, t, target: str, why: str) -> None:
    """A wizard this session cannot open: its name and why, until Esc."""
    import curses
    from bob.tui import fixlog as _fl
    from bob.tui import _palette
    has_color = _palette.init_palette(curses)
    title = "  bob    " + t("switch." + target)
    body = [("  " + why, "warn")]
    while True:
        _fl._draw(stdscr, curses, t, title, body, _SAID_KEYS, has_color, 0, None, "")
        ch = _keys.complete_escape(stdscr, curses, stdscr.getch())
        if _keys.resolve(curses, ch, _SAID_KEYS) == _keys.BACK:
            return
