"""Cron management UI (plain text) — list, edit schedule/email, delete.

Extracted from bob/cron.py in v0.6.0 (#14 split). Includes the email-store
sub-menu (``_manage_email_store``) and the edit helpers
(``edit_cron_schedule``, ``edit_cron_email``) that the install wizard's
edit branch calls back into.
"""

from __future__ import annotations

import re

from bob._tty import prompt_wizard, read_line as _rl
from bob.config import _EMAIL_RE  # M-1 (v0.5.5): single source of truth

from ._install import _CronQuit, prompt_emails  # noqa: F401 — _CronQuit re-exported
from ._io import apply_cron_email, apply_cron_schedule
from ._parse import (
    _validate_custom_cron,
    build_schedule_expr,
    cron_to_human,
    list_installed_crons,
)


def _manage_email_store(t) -> None:
    """Interactive sub-menu to manage the EmailStore (add / delete emails).

    Loops until the user explicitly quits with Enter or 'q'.
    The list is refreshed from disk before each iteration.
    """
    from bob import output
    from bob.config import EmailStore

    title = t("manage_cron.email_store_title")

    while True:
        store = EmailStore.load()
        emails = store.all()

        print()
        output.print_titled_box(title)
        print()

        if not emails:
            print(f"  ℹ {t('manage_cron.email_store_empty')}")
        else:
            for i, addr in enumerate(emails, 1):
                print(f"  {i}. {addr}")

        print()
        print(f"  {t('manage_cron.email_store_intro')}")
        print()
        print(f"    {'1':<8} {t('manage_cron.email_store_ex_delete')}")
        print(f"    {'1,3':<8} {t('manage_cron.email_store_ex_delete_list')}")
        print(f"    {'1-3':<8} {t('manage_cron.email_store_ex_delete_range')}")
        print(f"    {'all':<8} {t('manage_cron.email_store_ex_delete_all')}")
        print(f"    {'a':<8} {t('manage_cron.email_store_ex_add')}")
        print()
        print(f"  {t('manage_cron.email_store_quit')}")
        _raw = _rl("  > ")
        if _raw is None:
            return
        answer = _raw.strip().lower()

        if not answer or answer in ("q", "quit"):
            return

        if answer == "a":
            raw = input(f"  {t('manage_cron.email_store_enter')} : ").strip()
            if not _EMAIL_RE.match(raw):  # M-1 (v0.5.5): use bob.config._EMAIL_RE
                print(f"  ✖ {t('manage_cron.email_store_invalid_email')}")
            else:
                store.add(raw)
                print(f"  ✔ {t('manage_cron.email_store_added', email=raw)}")
            continue

        if answer == "all":
            if not emails:
                print(f"  ℹ {t('manage_cron.email_store_empty')}")
            else:
                count = len(emails)
                for addr in emails:
                    store.remove(addr)
                print(f"  ✔ {t('manage_cron.email_store_cleared', count=count)}")
            continue

        # Parse individual number, comma list, or range
        indices = set()  # type: set[int]
        valid = True
        try:
            if re.match(r"^\d+$", answer):
                indices.add(int(answer))
            elif re.match(r"^\d+(?:,\d+)+$", answer):
                for part in answer.split(","):
                    indices.add(int(part))
            elif re.match(r"^\d+-\d+$", answer):
                start_s, end_s = answer.split("-")
                # Cap the range to prevent memory exhaustion on absurd input
                end_n = min(int(end_s), int(start_s) + 999)
                for n in range(int(start_s), end_n + 1):
                    indices.add(n)
            else:
                print(f"  ✖ {t('manage_cron.invalid')}")
                valid = False
        except ValueError:
            print(f"  ✖ {t('manage_cron.invalid')}")
            valid = False

        if not valid:
            continue

        if not indices:
            print(f"  ✖ {t('manage_cron.email_store_invalid_sel')}")
            continue

        to_delete = []
        for idx in sorted(indices):
            if not (1 <= idx <= len(emails)):
                print(f"  ✖ {t('manage_cron.email_store_invalid_sel')}")
                to_delete = []
                break
            to_delete.append(emails[idx - 1])

        for addr in to_delete:
            store.remove(addr)
            print(f"  ✔ {t('manage_cron.email_store_removed', email=addr)}")

def edit_cron_email(entry, t) -> None:
    """Change the notification email of an existing cron entry.

    Pressing 'q' at the email prompt cancels without modifying anything.
    Pressing Enter / 0 with no selection clears the notification email.
    """
    new_emails = prompt_emails(t)

    if new_emails is None:
        # User cancelled with 'q'
        print(f"  {t('manage_cron.cancelled')}")
        return

    new_email = ",".join(new_emails)

    err, subst = apply_cron_email(entry, new_email)
    if err:
        print(f"  ✖ Cannot update: {err}")
        return
    if entry.script_path.exists() and subst == 0:
        print(f"  ⚠ {t('manage_cron.email_not_found_in_script')}")

    label = new_email if new_email else t("manage_cron.no_email")
    print(f"  ✔ {t('manage_cron.email_updated', name=entry.name, email=label)}")

def edit_cron_schedule(entry, config, t) -> None:
    """Re-run the schedule wizard for an existing cron entry and patch its cron file."""
    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    _rc = _rl("  > ")
    if _rc is None or _rc.strip().lower() in ("q", "quit"):
        print(f"  {t('manage_cron.cancelled')}")
        return
    raw_choice = _rc.strip()
    if not raw_choice:
        raw_choice = "1"
    if raw_choice not in ("1", "2", "3", "4"):
        print(f"  ✖ {t('install_cron.invalid_schedule')}")
        return
    choice = int(raw_choice)

    week_days   = None
    month_days  = None
    custom_expr = None
    hour   = entry.hour
    minute = entry.minute

    if choice == 2:
        print()
        print(f"  {t('install_cron.prompt_weekdays')}")
        raw_days = prompt_wizard("  > ")
        if raw_days is None:
            print(f"  {t('manage_cron.cancelled')}")
            return
        parts = re.split(r"[\s,]+", raw_days)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return

    elif choice == 3:
        print()
        print(f"  {t('install_cron.prompt_monthdays')}")
        raw_days = prompt_wizard("  > ")
        if raw_days is None:
            print(f"  {t('manage_cron.cancelled')}")
            return
        parts = re.split(r"[\s,]+", raw_days)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return

    elif choice == 4:
        print()
        print(f"  {t('install_cron.prompt_custom')}")
        custom_expr = prompt_wizard("  > ")
        if custom_expr is None:
            print(f"  {t('manage_cron.cancelled')}")
            return
        err = _validate_custom_cron(custom_expr)
        if err:
            print(f"  ✖ {t('install_cron.invalid_schedule')} ({err})")
            return

    if choice != 4:
        print()
        raw_time = prompt_wizard(
            f"  {t('install_cron.prompt_time')} : ",
            default=f"{entry.hour:02d}:{entry.minute:02d}",
        )
        if raw_time is None:
            print(f"  {t('manage_cron.cancelled')}")
            return
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return
        h, m = raw_time.split(":")
        hour, minute = int(h), int(m)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return

    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)
    print()
    print(f"  {t('install_cron.preview', schedule=human)}")
    print()

    ans = input(f"  {t('manage_cron.confirm_update')} ").strip().lower()
    if ans != "y":
        return

    err = apply_cron_schedule(entry, schedule_expr)
    if err:
        print(f"  ✖ Cannot update {entry.cron_path}: {err}")
        return

    print(f"  ✔ {t('manage_cron.updated', name=entry.name, schedule=human)}")

def _run_manage_cron_plain(config, t) -> int:
    """Manage installed cron jobs — list, edit schedule/email, delete.

    Loops until the user explicitly quits (Enter / 'q').
    The cron list is refreshed from disk at the start of each iteration.
    """
    from bob import output
    output.init(no_color=config.no_color)

    title = t("manage_cron.title")

    while True:
        output.print_titled_box(title)
        print()

        crons = list_installed_crons()

        if not crons:
            print(f"  ℹ {t('manage_cron.no_crons')}")
            print()
            print(f"    {'m':<8} {t('manage_cron.prompt_ex_email_book')}")
            print()
            print(f"  {t('manage_cron.prompt_quit')}")
            _raw = _rl("  > ")
            if _raw is None or not _raw.strip() or _raw.strip().lower() in ("q", "quit"):
                return 0
            if _raw.strip().lower() == "m":
                _manage_email_store(t)
            continue

        lang = config.lang
        for i, entry in enumerate(crons, 1):
            human = cron_to_human(entry.schedule_expr, lang)
            legacy_tag = f"  [{t('manage_cron.legacy_tag')}]" if entry.legacy else ""
            print(f"  {i}. {entry.name:<20} {human}{legacy_tag}")
            if entry.email:
                for addr in entry.email.split(","):
                    addr = addr.strip()
                    if addr:
                        print(f"     → {t('manage_cron.email_label')}: {addr}")

        print()
        print(f"  {t('manage_cron.prompt_intro')}")
        print()
        print(f"    {'1':<8} {t('manage_cron.prompt_ex_edit')}")
        print(f"    {'e:1':<8} {t('manage_cron.prompt_ex_email')}")
        print(f"    {'d:1':<8} {t('manage_cron.prompt_ex_delete_one')}")
        print(f"    {'d:1,3':<8} {t('manage_cron.prompt_ex_delete_list')}")
        print(f"    {'d:1-3':<8} {t('manage_cron.prompt_ex_delete_range')}")
        print(f"    {'d:all':<8} {t('manage_cron.prompt_ex_delete_all')}")
        print(f"    {'m':<8} {t('manage_cron.prompt_ex_email_book')}")
        print()
        print(f"  {t('manage_cron.prompt_quit')}")
        _raw = _rl("  > ")
        if _raw is None:
            return 0
        answer = _raw.strip().lower()

        if not answer or answer in ("q", "quit"):
            return 0

        if answer == "m":
            _manage_email_store(t)
            continue

        delete_match = re.match(r"^d:?(.+)$", answer)
        email_match  = re.match(r"^e:(\d+)$", answer)
        edit_match   = re.match(r"^(\d+)$", answer)

        if delete_match:
            raw_del = delete_match.group(1).strip()

            # Resolve indices: single / comma list / range / all
            if raw_del == "all":
                to_delete = list(crons)
            else:
                indices: set[int] = set()
                valid = True
                try:
                    if re.match(r"^\d+$", raw_del):
                        indices.add(int(raw_del))
                    elif re.match(r"^\d+(?:,\d+)+$", raw_del):
                        for part in raw_del.split(","):
                            indices.add(int(part))
                    elif re.match(r"^\d+-\d+$", raw_del):
                        start_s, end_s = raw_del.split("-")
                        end_n = min(int(end_s), int(start_s) + 999)
                        for n in range(int(start_s), end_n + 1):
                            indices.add(n)
                    else:
                        valid = False
                except ValueError:
                    valid = False

                if not valid:
                    print(f"  ✖ {t('manage_cron.invalid')}")
                    continue

                to_delete = []
                for idx in sorted(indices):
                    if not (1 <= idx <= len(crons)):
                        print(f"  ✖ {t('manage_cron.invalid')}")
                        to_delete = []
                        break
                    to_delete.append(crons[idx - 1])

            if not to_delete:
                continue

            # Confirm
            if len(to_delete) == 1:
                ans = input(
                    f"  {t('manage_cron.confirm_delete', name=to_delete[0].name)} "
                ).strip().lower()
            elif raw_del == "all":
                ans = input(
                    f"  {t('manage_cron.confirm_delete_all', count=len(to_delete))} "
                ).strip().lower()
            else:
                names = ", ".join(e.name for e in to_delete)
                ans = input(
                    f"  {t('manage_cron.confirm_delete_multi', count=len(to_delete), names=names)} "
                ).strip().lower()

            if ans == "y":
                for entry in to_delete:
                    try:
                        entry.cron_path.unlink()
                    except OSError:
                        pass
                    if entry.script_path.exists():
                        try:
                            entry.script_path.unlink()
                        except OSError:
                            pass
                if len(to_delete) == 1:
                    print(f"  ✔ {t('manage_cron.deleted', name=to_delete[0].name)}")
                else:
                    print(f"  ✔ {t('manage_cron.deleted_count', count=len(to_delete))}")

        elif email_match:
            idx = int(email_match.group(1)) - 1
            if not (0 <= idx < len(crons)):
                print(f"  ✖ {t('manage_cron.invalid')}")
                continue
            entry = crons[idx]
            print()
            print(f"  {t('manage_cron.edit_email', name=entry.name)}")
            edit_cron_email(entry, t)

        elif edit_match:
            idx = int(edit_match.group(1)) - 1
            if not (0 <= idx < len(crons)):
                print(f"  ✖ {t('manage_cron.invalid')}")
                continue
            entry = crons[idx]
            print()
            print(f"  {t('manage_cron.edit_what', name=entry.name)}")
            print(f"    1. {t('manage_cron.edit_schedule_option')}")
            print(f"    2. {t('manage_cron.edit_email_option')}")
            _sub = _rl("  > ")
            if _sub is None:  # Esc = back to root
                continue
            sub = _sub.strip()
            if sub == "1":
                edit_cron_schedule(entry, config, t)
            elif sub == "2":
                edit_cron_email(entry, t)
            else:
                print(f"  ✖ {t('manage_cron.invalid')}")

        else:
            print(f"  ✖ {t('manage_cron.invalid')}")

def run_manage_cron(config, t) -> int:
    """Dispatcher: curses TUI in a TTY, plain text fallback otherwise."""
    import sys as _sys
    if not _sys.stdout.isatty():
        return _run_manage_cron_plain(config, t)
    import curses as _curses
    import os as _os
    from bob.tui.cron import _run_manage_cron_curses
    _os.environ.setdefault("ESCDELAY", "25")
    try:
        return _curses.wrapper(lambda scr: _run_manage_cron_curses(scr, config, t))
    except _CronQuit:
        return 0
    except (_curses.error, OSError):
        return _run_manage_cron_plain(config, t)
