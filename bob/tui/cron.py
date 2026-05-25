"""
Curses TUI components for BOB cron management.

Contains all curses-based UI code for --install-cron and --manage-cron:
- _run_install_cron_curses: full curses install wizard
- _run_manage_cron_curses:  full curses management TUI
- All helper sub-screens and primitives (_curses_*)

Plain-text flows and core data types live in bob.cron.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import IntEnum
from typing import NamedTuple


class _Schedule(IntEnum):
    """M-5 (v0.5.8): schedule choices for the install/edit wizard.

    Values are the 1-based menu indices the user sees ("1. Daily…").
    Promoted from a local `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS,
    _SCHEDULE_CUSTOM = 1, 2, 3, 4` tuple unpack inside the wizard.
    """
    DAILY = 1
    WEEKDAYS = 2
    MONTHDAYS = 3
    CUSTOM = 4

from bob.cron import (
    _EMAIL_RE,
    _CronQuit,
    CRON_DIR,
    SCRIPT_DIR,
    list_installed_crons,
    cron_to_human,
    build_schedule_expr,
    build_script_content,
    make_slug,
    suggest_name,
    _validate_custom_cron,
    _detect_mta,
    # File-patching helpers — single source of truth, see v0.4.8 cleanup pass
    # that merged the duplicated implementations.
    apply_cron_schedule,
    apply_cron_email,
)


class _WizardEntry(NamedTuple):
    """Minimal entry context passed to the schedule wizard during installation."""
    name: str
    hour: int = 3
    minute: int = 0


def _draw(stdscr, row: int, col: int, text: str, attr: int = 0) -> None:
    """Safe stdscr.addstr — silently ignores terminal size errors."""
    try:
        stdscr.addstr(row, col, text, attr)
    except Exception:
        pass


def _read_key(stdscr) -> int:
    """Read one keypress and return it as int. Returns -1 on error or unrecognized input."""
    try:
        ch = stdscr.get_wch()
    except Exception:
        return -1
    if isinstance(ch, int):
        return ch
    if isinstance(ch, str) and len(ch) == 1:
        return ord(ch)
    return -1


def _is_printable_input_char(ch_i: int) -> bool:
    """I-1 (v0.5.7): True for chars safe to append to a readline buffer.

    Excludes curses KEY_* codes (>= 256) which previously leaked through
    `chr(ch_i)` as Greek/Unicode glyphs (KEY_UP=259, KEY_F1=265 etc.) when
    `_read_key` collapsed keypad ints and printable strs into a single int.
    Bound to printable Latin-1 only.
    """
    return 32 <= ch_i < 256 and chr(ch_i).isprintable()


# ---------------------------------------------------------------------------
# Low-level curses primitives
# ---------------------------------------------------------------------------

def _curses_readline(stdscr, row: int, w: int, prompt: str, default: str = "") -> "str | None":
    """Single-line text input drawn on *row* in yellow. Esc → None, Enter → str."""
    import curses as _c
    _c.curs_set(1)
    buf = list(default)
    has_color = _c.has_colors()
    attr = _c.color_pair(2) if has_color else _c.A_REVERSE
    while True:
        text = "".join(buf)
        display = f"  {prompt}: {text}"
        try:
            stdscr.addstr(row, 0, " " * (w - 1), attr)
            stdscr.addstr(row, 0, display[:w - 1], attr)
            stdscr.move(row, min(len(display), w - 2))
        except _c.error:
            pass
        stdscr.refresh()
        ch_i = _read_key(stdscr)
        if ch_i == 27:
            _c.curs_set(0)
            return None
        elif ch_i in (10, 13) or ch_i == _c.KEY_ENTER:
            _c.curs_set(0)
            return text
        elif ch_i in (127, 8) or ch_i == _c.KEY_BACKSPACE:
            if buf:
                buf.pop()
        elif _is_printable_input_char(ch_i):
            buf.append(chr(ch_i))


def _curses_status_flash(stdscr, msg: str) -> None:
    """Display *msg* on the body area and wait for a keypress."""
    import curses as _c
    has_color = _c.has_colors()
    hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
    ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    _draw(stdscr, 0, 0, " " * (w - 1), hdr_attr)
    _draw(stdscr, 2, 2, msg[:w - 3])
    _draw(stdscr, 4, 2, "Press any key to continue…")
    _draw(stdscr, h - 1, 0, " " * (w - 1), ftr_attr)
    stdscr.refresh()
    try:
        stdscr.get_wch()
    except _c.error:
        pass


def _init_colors_cron() -> None:
    """Initialize curses color pairs for --manage-cron TUI."""
    import curses
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK,  curses.COLOR_CYAN)  # cursor row
    curses.init_pair(2, curses.COLOR_YELLOW, -1)                  # interactive / input
    curses.init_pair(3, curses.COLOR_WHITE,  -1)                  # normal row
    curses.init_pair(4, curses.COLOR_RED,    -1)                  # warning / legacy
    curses.init_pair(5, curses.COLOR_WHITE,  curses.COLOR_CYAN)  # top banner


# ---------------------------------------------------------------------------
# File-patching wrappers — delegated to bob.cron (see import block above).
# ---------------------------------------------------------------------------

def _apply_cron_schedule(entry, schedule_expr: str) -> str:
    """Thin wrapper kept for the existing curses call site (line ~601)."""
    return apply_cron_schedule(entry, schedule_expr)


def _apply_cron_email_str(entry, new_email: str) -> str:
    """Thin wrapper kept for the existing curses call site (line ~607).

    Drops the substitution count returned by the underlying helper —
    the curses TUI displays a generic "updated" toast regardless.
    """
    err, _ = apply_cron_email(entry, new_email)
    return err


# ---------------------------------------------------------------------------
# Schedule wizard (shared by install and edit flows)
# ---------------------------------------------------------------------------

def _curses_schedule_wizard(stdscr, entry, config, t, title_prefix: str = "Edit schedule") -> "str | None":
    """Full schedule wizard inside curses. Returns new cron expression or None."""
    import curses as _c
    has_color = _c.has_colors()
    hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
    ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE

    def _hdr(suffix=""):
        h2, w2 = stdscr.getmaxyx()
        label = f"  {title_prefix}: {entry.name}  {suffix}" if entry else f"  {title_prefix}  {suffix}"
        _draw(stdscr, 0, 0, label[:w2 - 1].ljust(w2 - 1), hdr_attr)

    def _ftr(msg="  Esc: back   q: quit"):
        h2, w2 = stdscr.getmaxyx()
        _draw(stdscr, h2 - 1, 0, msg[:w2 - 1].ljust(w2 - 1), ftr_attr)

    # Step 1 — schedule type
    options = [
        t("install_cron.schedule_daily"),
        t("install_cron.schedule_weekdays"),
        t("install_cron.schedule_monthdays"),
        t("install_cron.schedule_custom"),
    ]
    sel = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        _draw(stdscr, 2, 2, t("install_cron.prompt_schedule"))
        for i, opt in enumerate(options):
            is_cur = (i == sel)
            attr = (_c.color_pair(1) | _c.A_BOLD) if (is_cur and has_color) else (_c.A_REVERSE if is_cur else _c.A_NORMAL)
            _draw(stdscr, 4 + i, 2, f"  {i + 1}. {opt}  "[:w - 3], attr)
        _ftr("  ↑↓: move   Enter: select   Esc: back   q: quit")
        stdscr.refresh()
        ch_i = _read_key(stdscr)
        if ch_i == 27:
            return None
        elif ch_i in (ord("q"), ord("Q")):
            raise _CronQuit()
        elif ch_i in (_c.KEY_UP, ord("k")):
            sel = max(0, sel - 1)
        elif ch_i in (_c.KEY_DOWN, ord("j")):
            sel = min(3, sel + 1)
        elif ch_i in (10, 13, _c.KEY_ENTER):
            choice = sel + 1
            break
        elif ch_i in (ord("1"), ord("2"), ord("3"), ord("4")):
            choice = ch_i - ord("0")
            break

    # Step 2 — extra input depending on choice
    week_days = None
    month_days = None
    custom_expr = None
    hour = entry.hour if entry else 3
    minute = entry.minute if entry else 0

    if choice == _Schedule.WEEKDAYS:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        _draw(stdscr, 2, 2, t("install_cron.prompt_weekdays"))
        _draw(stdscr, 3, 4, "(1=Mon 2=Tue 3=Wed 4=Thu 5=Fri 6=Sat 7=Sun)")
        _ftr()
        raw = _curses_readline(stdscr, h - 1, w, "Days (e.g. 1,5)")
        if raw is None:
            return None
        parts = re.split(r"[\s,]+", raw)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            return None

    elif choice == _Schedule.MONTHDAYS:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        _draw(stdscr, 2, 2, t("install_cron.prompt_monthdays"))
        _draw(stdscr, 3, 4, "(e.g. 1,15)")
        _ftr()
        raw = _curses_readline(stdscr, h - 1, w, "Days (e.g. 1,15)")
        if raw is None:
            return None
        parts = re.split(r"[\s,]+", raw)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            return None

    elif choice == _Schedule.CUSTOM:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        _draw(stdscr, 2, 2, t("install_cron.prompt_custom"))
        _draw(stdscr, 3, 4, "(minute hour dom month dow)")
        _ftr()
        raw = _curses_readline(stdscr, h - 1, w, "Expression")
        if raw is None:
            return None
        err = _validate_custom_cron(raw)
        if err:
            stdscr.erase()
            _draw(stdscr, 2, 2, f"✖ {err}")
            _draw(stdscr, 4, 2, "Press any key to cancel…")
            stdscr.refresh()
            try:
                stdscr.get_wch()
            except _c.error:
                pass
            return None
        custom_expr = raw

    # Step 3 — time (not for custom)
    if choice != _Schedule.CUSTOM:
        default_time = f"{hour:02d}:{minute:02d}"
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        _draw(stdscr, 2, 2, t("install_cron.prompt_time") + f"  (default: {default_time})")
        _ftr()
        raw_time = _curses_readline(stdscr, h - 1, w, "Time (HH:MM)", default=default_time)
        if raw_time is None:
            return None
        if not raw_time:
            raw_time = default_time
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            return None
        hh, mm = raw_time.split(":")
        hour, minute = int(hh), int(mm)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            return None

    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)

    # Step 4 — confirm
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        _draw(stdscr, 2, 2, t("install_cron.preview", schedule=human))
        _draw(stdscr, 4, 2, t("manage_cron.confirm_update"))
        _ftr("  y: confirm   Esc: back   q: quit")
        stdscr.refresh()
        ch_i = _read_key(stdscr)
        if ch_i in (ord("q"), ord("Q")):
            raise _CronQuit()
        if ch_i in (ord("y"), ord("Y"), 10, 13) or ch_i == _c.KEY_ENTER:
            return schedule_expr
        return None


# ---------------------------------------------------------------------------
# Email sub-screens
# ---------------------------------------------------------------------------

def _curses_email_list_sub(stdscr, current_email: str, t) -> "str | None":
    """Select notification emails for a cron entry. Returns comma-sep str or None."""
    import curses as _c
    from bob.config import EmailStore

    has_color = _c.has_colors()

    store = EmailStore.load()
    # Pre-populate: current saved emails + any in entry not in store
    saved = list(store.all())
    current_set = {e.strip() for e in current_email.split(",") if e.strip()}
    for addr in current_set:
        if addr not in saved:
            saved.append(addr)

    selected: set[str] = set(current_set)
    cursor = 0
    scroll = 0
    status = ""

    while True:
        n = len(saved)
        if n == 0:
            cursor = 0
        elif cursor >= n:
            cursor = n - 1

        stdscr.erase()
        h, w = stdscr.getmaxyx()
        body_h = max(1, h - 2)

        hdr = ("  Select notification emails    "
               "Spc: toggle   n: new   Enter: confirm   Esc: back   q: quit")
        hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
        ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
        _draw(stdscr, 0, 0, hdr[:w - 1].ljust(w - 1), hdr_attr)

        if not saved:
            _draw(stdscr, 2, 2, "No saved emails.")
            _draw(stdscr, 3, 2, "→ Press  n  to add an email address.")
            _draw(stdscr, 4, 2, "→ Press  Enter  to skip (no email notification).")
        else:
            for row in range(body_h):
                idx = scroll + row
                if idx >= n:
                    break
                addr = saved[idx]
                mark = "✔ " if addr in selected else "  "
                line = f"  {mark}{addr}"
                is_cur = (idx == cursor)
                attr = (_c.color_pair(1) | _c.A_BOLD) if (is_cur and has_color) else (
                    _c.A_REVERSE if is_cur else _c.A_NORMAL)
                _draw(stdscr, row + 1, 0, line[:w - 1].ljust(w - 1), attr)

        if status:
            footer = f"  {status}"
            status = ""
        elif selected:
            footer = f"  {len(selected)} selected — Enter: confirm"
        else:
            footer = "  0 selected — n: add email   Enter: no email"
        _draw(stdscr, h - 1, 0, footer[:w - 1].ljust(w - 1), ftr_attr)

        stdscr.refresh()
        ch_i = _read_key(stdscr)

        if ch_i == 27:
            return None
        elif ch_i in (ord("q"), ord("Q")):
            raise _CronQuit()
        elif ch_i in (_c.KEY_UP, ord("k")):
            if cursor > 0:
                cursor -= 1
            if cursor < scroll:
                scroll = cursor
        elif ch_i in (_c.KEY_DOWN, ord("j")):
            if cursor < n - 1:
                cursor += 1
            if cursor >= scroll + body_h:
                scroll = cursor - body_h + 1
        elif ch_i == ord(" "):
            if 0 <= cursor < n:
                addr = saved[cursor]
                if addr in selected:
                    selected.discard(addr)
                else:
                    selected.add(addr)
        elif ch_i in (ord("n"), ord("N")):
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            _draw(stdscr, 0, 0, "  Add email address".ljust(w - 1), hdr_attr)
            _draw(stdscr, h - 2, 0, "  Esc: back".ljust(w - 1), ftr_attr)
            raw = _curses_readline(stdscr, h - 1, w, "Email")
            if raw and _EMAIL_RE.match(raw.strip()):
                addr = raw.strip()
                if addr not in saved:
                    store.add(addr)
                    saved.append(addr)
                selected.add(addr)
                status = f"✔ {addr} added"
            elif raw:
                status = "✖ Invalid email address"
        elif ch_i in (_c.KEY_ENTER, 10, 13):
            return ",".join(sorted(selected))


def _curses_email_store_sub(stdscr, t) -> None:
    """Address book management sub-screen (add / delete emails)."""
    import curses as _c
    from bob.config import EmailStore

    has_color = _c.has_colors()
    cursor = 0
    scroll = 0
    marked: set[int] = set()
    status = ""

    while True:
        store = EmailStore.load()
        emails = store.all()
        n = len(emails)
        if n == 0:
            cursor = 0
        elif cursor >= n:
            cursor = n - 1

        stdscr.erase()
        h, w = stdscr.getmaxyx()
        body_h = max(1, h - 2)

        hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
        ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
        n_sel = len(marked)
        if n_sel:
            hdr = (f"  Email address book    ↑↓: move   Spc: toggle   "
                   f"d: delete ({n_sel})   u: unmark all   Esc: back")
        else:
            hdr = ("  Email address book    ↑↓: move   Spc: mark   "
                   "a: all   d: delete   n: add   Esc: back")
        _draw(stdscr, 0, 0, hdr[:w - 1].ljust(w - 1), hdr_attr)

        if not emails:
            _draw(stdscr, 2, 2, t("manage_cron.email_store_empty"))
            _draw(stdscr, 4, 2, "n: " + t("manage_cron.email_store_ex_add"))
        else:
            for row in range(body_h):
                idx = scroll + row
                if idx >= n:
                    break
                addr = emails[idx]
                mark = "✔ " if idx in marked else "  "
                line = f"  {mark}{addr}"
                is_cur = (idx == cursor)
                attr = (_c.color_pair(1) | _c.A_BOLD) if (is_cur and has_color) else (
                    _c.A_REVERSE if is_cur else _c.A_NORMAL)
                _draw(stdscr, row + 1, 0, line[:w - 1].ljust(w - 1), attr)

        if status:
            footer = f"  {status}"
            status = ""
        else:
            footer = f"  {n} email(s)"
        _draw(stdscr, h - 1, 0, footer[:w - 1].ljust(w - 1), ftr_attr)

        stdscr.refresh()
        ch_i = _read_key(stdscr)

        if ch_i in (27, ):
            return
        elif ch_i in (_c.KEY_UP, ord("k")):
            if cursor > 0:
                cursor -= 1
            if cursor < scroll:
                scroll = cursor
        elif ch_i in (_c.KEY_DOWN, ord("j")):
            if cursor < n - 1:
                cursor += 1
            if cursor >= scroll + body_h:
                scroll = cursor - body_h + 1
        elif ch_i == ord(" "):
            if 0 <= cursor < n:
                if cursor in marked:
                    marked.discard(cursor)
                else:
                    marked.add(cursor)
        elif ch_i in (ord("a"), ord("A")):
            marked = set(range(n))
        elif ch_i in (ord("u"), ord("U")):
            marked.clear()
        elif ch_i in (ord("d"), ord("D")):
            targets = sorted(marked) if marked else ([cursor] if 0 <= cursor < n else [])
            if targets:
                for idx in sorted(targets, reverse=True):
                    if 0 <= idx < len(emails):
                        store.remove(emails[idx])
                status = f"✔ {len(targets)} email(s) deleted"
                marked.clear()
                cursor = max(0, cursor - len([i for i in targets if i <= cursor]))
        elif ch_i in (ord("n"), ord("N")):
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            _draw(stdscr, 0, 0, "  Add email address".ljust(w - 1), hdr_attr)
            _draw(stdscr, 2, 2, t("manage_cron.email_store_enter"))
            raw = _curses_readline(stdscr, h - 1, w, "Email")
            if raw and _EMAIL_RE.match(raw.strip()):
                store.add(raw.strip())
                status = t("manage_cron.email_store_added", email=raw.strip())
            elif raw:
                status = t("manage_cron.email_store_invalid_email")


# ---------------------------------------------------------------------------
# Edit sub-screen (schedule or email choice)
# ---------------------------------------------------------------------------

def _curses_edit_sub(stdscr, entry, config, t) -> None:
    """Sub-screen: choose to edit schedule or notification email for *entry*."""
    import curses as _c
    has_color = _c.has_colors()
    options = [t("manage_cron.edit_schedule_option"), t("manage_cron.edit_email_option")]
    sel = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
        ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
        hdr = f"  Edit: {entry.name}    ↑↓: move   Enter: select   Esc: back   q: quit"
        _draw(stdscr, 0, 0, hdr[:w - 1].ljust(w - 1), hdr_attr)
        for i, opt in enumerate(options):
            is_cur = (i == sel)
            attr = (_c.color_pair(1) | _c.A_BOLD) if (is_cur and has_color) else (
                _c.A_REVERSE if is_cur else _c.A_NORMAL)
            _draw(stdscr, 2 + i, 2, f"  {i + 1}. {opt}  "[:w - 3], attr)
        _draw(stdscr, h - 1, 0, "  Esc: back   q: quit"[:w - 1].ljust(w - 1), ftr_attr)
        stdscr.refresh()
        ch_i = _read_key(stdscr)

        if ch_i == 27:
            return
        elif ch_i in (ord("q"), ord("Q")):
            raise _CronQuit()
        elif ch_i in (_c.KEY_UP, ord("k")):
            sel = max(0, sel - 1)
        elif ch_i in (_c.KEY_DOWN, ord("j")):
            sel = min(1, sel + 1)
        elif (
            ch_i in (_c.KEY_ENTER, 10, 13)
            or (ch_i == ord("1") and sel == 0)
            or (ch_i == ord("2") and sel == 1)
        ):
            # M-3 (v0.5.7): the guard already constrains "1"→sel==0 and "2"→sel==1,
            # so chosen == sel holds for all entry paths; previous explicit override
            # was dead code.
            chosen = sel
            if chosen == 0:
                new_expr = _curses_schedule_wizard(stdscr, entry, config, t)
                if new_expr:
                    err = _apply_cron_schedule(entry, new_expr)
                    if err:
                        _curses_status_flash(stdscr, f"✖ {err}")
            else:
                new_email = _curses_email_list_sub(stdscr, entry.email, t)
                if new_email is not None:
                    _apply_cron_email_str(entry, new_email)
            # continue → back to the 1/2 choice menu; Esc from that menu returns to main list


# ---------------------------------------------------------------------------
# Curses install wizard
# ---------------------------------------------------------------------------

def _run_install_cron_curses(stdscr, user_config, config, t) -> int:
    """Curses TUI for --install-cron."""
    import curses as _c
    import os as _os
    from pathlib import Path as _Path

    try:
        _init_colors_cron()
    except _c.error:
        pass
    has_color = _c.has_colors()
    hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
    ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE

    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        _curses_status_flash(stdscr, f"✖ {t('install_cron.no_log_dir')}")
        return 1
    log_dir = _Path(log_dir_str)

    # State machine constants
    LANDING, STEP_NAME, STEP_SCHEDULE, STEP_EMAIL, STEP_OVERWRITE, STEP_WRITE = range(6)

    # Outer loop: one full landing→create cycle per iteration; continues back to LANDING after success
    while True:
        existing_names = [e.name for e in list_installed_crons()]
        suggestion = suggest_name(existing_names)
        step = LANDING
        raw_name = ""
        slug = ""
        schedule_expr = ""
        notify_email = ""

        # Inner state machine
        while True:
            if step == LANDING:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                _draw(stdscr, 0, 0, "  bob --install-cron".ljust(w - 1), hdr_attr)
                _draw(stdscr, 2, 2, t("install_cron.landing_prompt"))
                _draw(stdscr, h - 1, 0, "  Enter: create   q: quit".ljust(w - 1), ftr_attr)
                stdscr.refresh()
                ch_i = _read_key(stdscr)
                if ch_i in (ord("q"), ord("Q")):
                    raise _CronQuit()
                if ch_i in (10, 13) or ch_i == _c.KEY_ENTER:
                    step = STEP_NAME

            elif step == STEP_NAME:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                _draw(stdscr, 0, 0, "  bob --install-cron".ljust(w - 1), hdr_attr)
                _draw(stdscr, 2, 2, t("install_cron.prompt_name", suggestion=suggestion))
                entered = _curses_readline(stdscr, h - 1, w, "Name", default=raw_name or suggestion)
                if entered is None:       # Esc → back to landing
                    step = LANDING
                    continue
                raw_name = entered if entered else (raw_name or suggestion)
                slug = make_slug(raw_name)
                if not slug:
                    _curses_status_flash(stdscr, f"✖ {t('install_cron.invalid_name')}")
                    continue
                step = STEP_SCHEDULE

            elif step == STEP_SCHEDULE:
                result = _curses_schedule_wizard(
                    stdscr, _WizardEntry(raw_name), config, t, title_prefix="Install cron"
                )
                if result is None:        # Esc → back to name
                    step = STEP_NAME
                    continue
                schedule_expr = result
                step = STEP_EMAIL

            elif step == STEP_EMAIL:
                result = _curses_email_list_sub(stdscr, notify_email, t)
                if result is None:        # Esc → back to schedule
                    step = STEP_SCHEDULE
                    continue
                notify_email = result
                if notify_email:
                    _mta_ok, _mta_name = _detect_mta()
                    if _mta_ok:
                        _curses_status_flash(stdscr, f"✔ {t('install_cron.mta_found', mta=_mta_name or 'sendmail')}")
                    else:
                        _curses_status_flash(stdscr, f"⚠ {t('install_cron.mta_missing')}")
                step = STEP_OVERWRITE

            elif step == STEP_OVERWRITE:
                cron_path = CRON_DIR / f"bob-{slug}"
                if not cron_path.exists():
                    step = STEP_WRITE
                    continue
                while True:
                    stdscr.erase()
                    h, w = stdscr.getmaxyx()
                    _draw(stdscr, 0, 0, "  bob --install-cron".ljust(w - 1), hdr_attr)
                    _draw(stdscr, 2, 2, t("install_cron.overwrite", path=str(cron_path)))
                    _draw(stdscr, h - 1, 0, "  y: overwrite   Esc: back   q: quit".ljust(w - 1), ftr_attr)
                    stdscr.refresh()
                    ch_i = _read_key(stdscr)
                    if ch_i in (ord("q"), ord("Q")):
                        raise _CronQuit()
                    if ch_i == 27:        # Esc → back to email
                        step = STEP_EMAIL
                        break
                    if ch_i in (ord("y"), ord("Y")):
                        step = STEP_WRITE
                        break
                continue

            elif step == STEP_WRITE:
                break   # exit inner loop → write files

        # ── Write files ──────────────────────────────────────────────────────
        cron_path   = CRON_DIR / f"bob-{slug}"
        script_path = SCRIPT_DIR / f"bob-{slug}"

        script_content = build_script_content(notify_email, log_dir)

        try:
            fd = _os.open(str(script_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o755)
            with _os.fdopen(fd, "w") as fh:
                fh.write(script_content)
        except OSError as exc:
            _curses_status_flash(stdscr, f"✖ Cannot write {script_path}: {exc}")
            return 1

        now_str = datetime.now().strftime("%Y-%m-%d")
        human = cron_to_human(schedule_expr, lang=config.lang)
        cron_content = (
            f"# BOB cron — generated {now_str} by bob --install-cron\n"
            f"# name: {raw_name}\n"
            f"# email: {notify_email}\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            f"{schedule_expr}  root  {script_path}\n"
        )
        try:
            fd = _os.open(str(cron_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o640)
            with _os.fdopen(fd, "w") as fh:
                fh.write(cron_content)
        except OSError as exc:
            _curses_status_flash(stdscr, f"✖ Cannot write {cron_path}: {exc}")
            return 1

        root_config_path = _Path("/root/.config/bob/config.conf")
        try:
            from bob.config import UserConfig as _UC
            root_cfg = _UC.load(path=root_config_path)
            if not root_cfg.get("log_dir"):
                root_cfg.set("log_dir", str(log_dir))
        except OSError:
            pass

        _curses_status_flash(stdscr, f"✔ {t('install_cron.done_schedule', name=raw_name, schedule=human)}")
        # Continue outer loop → refresh suggestion and return to LANDING


# ---------------------------------------------------------------------------
# Curses management TUI
# ---------------------------------------------------------------------------

def _run_manage_cron_curses(stdscr, config, t) -> int:
    """Curses TUI for --manage-cron."""
    import curses as _c

    try:
        _init_colors_cron()
        has_color = _c.has_colors()
    except _c.error:
        has_color = False

    _c.curs_set(0)
    cursor = 0
    scroll = 0
    status = ""
    confirm_delete = False
    pending_delete: list = []
    marked: set = set()   # set of cron_path strings for selected entries

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        body_h = max(1, h - 2)

        crons = list_installed_crons()
        lang = config.lang
        n = len(crons)
        if n == 0:
            cursor = 0
        elif cursor >= n:
            cursor = n - 1

        # Remove stale marked paths after a deletion
        valid_paths = {str(e.cron_path) for e in crons}
        marked &= valid_paths

        n_sel = len(marked)

        # ── Header ──────────────────────────────────────────────────────────
        hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
        ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
        if confirm_delete:
            header = "  bob --manage-cron    Confirm deletion below  "
        elif n_sel:
            header = (f"  bob --manage-cron    "
                      f"↑↓: move   Spc: toggle   a: all   u: unmark   "
                      f"d: delete ({n_sel})   q: quit")
        else:
            header = ("  bob --manage-cron    "
                      "↑↓: move   Spc: toggle   Enter: edit   d: delete   "
                      "m: email book   q: quit")
        _draw(stdscr, 0, 0, header[:w - 1].ljust(w - 1), hdr_attr)

        # ── Body ─────────────────────────────────────────────────────────────
        if not crons:
            _draw(stdscr, 2, 2, t("manage_cron.no_crons"))
            _draw(stdscr, 4, 2, "m: " + t("manage_cron.prompt_ex_email_book"))
        else:
            for row in range(body_h):
                idx = scroll + row
                if idx >= n:
                    break
                entry = crons[idx]
                is_marked = str(entry.cron_path) in marked
                human = cron_to_human(entry.schedule_expr, lang)
                legacy_tag = f"  [{t('manage_cron.legacy_tag')}]" if entry.legacy else ""
                email_hint = ""
                if entry.email:
                    addrs = " ; ".join(a.strip() for a in entry.email.split(",") if a.strip())
                    email_hint = f"   {addrs}"
                mark = "✔ " if is_marked else "  "
                line = f"{mark}{entry.name:<20} {human:<30}{legacy_tag}{email_hint}"

                is_cur = (idx == cursor)
                if is_cur and has_color:
                    attr = _c.color_pair(1) | _c.A_BOLD
                elif is_cur:
                    attr = _c.A_REVERSE
                elif is_marked and has_color:
                    attr = _c.color_pair(2)
                elif entry.legacy and has_color:
                    attr = _c.color_pair(4)
                else:
                    attr = _c.A_NORMAL
                _draw(stdscr, row + 1, 0, line[:w - 1].ljust(w - 1), attr)

        # ── Footer ───────────────────────────────────────────────────────────
        if confirm_delete:
            names = ", ".join(e.name for e in pending_delete)
            footer = f"  Delete {names[:w - 30]}?   y: confirm   any key: cancel"
        elif status:
            footer = f"  {status}"
            status = ""
        elif n_sel:
            footer = f"  {n_sel} selected — d: delete selected   u: unmark all"
        else:
            footer = f"  {n} cron job(s)"
        _draw(stdscr, h - 1, 0, footer[:w - 1].ljust(w - 1), ftr_attr)

        stdscr.refresh()

        ch = _read_key(stdscr)

        # ── Confirm-delete mode ──────────────────────────────────────────────
        if confirm_delete:
            if ch in (ord("y"), ord("Y")):
                for entry in pending_delete:
                    try:
                        entry.cron_path.unlink()
                    except OSError:
                        pass
                    if entry.script_path.exists():
                        try:
                            entry.script_path.unlink()
                        except OSError:
                            pass
                if len(pending_delete) == 1:
                    status = t("manage_cron.deleted", name=pending_delete[0].name)
                else:
                    status = t("manage_cron.deleted_count", count=len(pending_delete))
                marked.clear()
            confirm_delete = False
            pending_delete = []
            continue

        # ── Navigation ───────────────────────────────────────────────────────
        if ch in (_c.KEY_UP, ord("k"), ord("K")):
            if cursor > 0:
                cursor -= 1
            if cursor < scroll:
                scroll = cursor

        elif ch in (_c.KEY_DOWN, ord("j"), ord("J")):
            if cursor < n - 1:
                cursor += 1
            if cursor >= scroll + body_h:
                scroll = cursor - body_h + 1

        # ── Selection ────────────────────────────────────────────────────────
        elif ch == ord(" "):
            if crons and 0 <= cursor < n:
                key = str(crons[cursor].cron_path)
                if key in marked:
                    marked.discard(key)
                else:
                    marked.add(key)

        elif ch in (ord("a"), ord("A")):
            marked = {str(e.cron_path) for e in crons}

        elif ch in (ord("u"), ord("U")):
            marked.clear()

        # ── Actions ──────────────────────────────────────────────────────────
        elif ch in (_c.KEY_ENTER, 10, 13):
            if crons and 0 <= cursor < n and not n_sel:
                _curses_edit_sub(stdscr, crons[cursor], config, t)

        elif ch in (ord("d"), ord("D")):
            if crons:
                if marked:
                    pending_delete = [e for e in crons if str(e.cron_path) in marked]
                elif 0 <= cursor < n:
                    pending_delete = [crons[cursor]]
                if pending_delete:
                    confirm_delete = True

        elif ch in (ord("m"), ord("M")):
            if not n_sel:
                _curses_email_store_sub(stdscr, t)

        elif ch in (ord("q"), ord("Q")):
            return 0

    return 0
