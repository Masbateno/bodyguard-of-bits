"""Cron install wizard (plain text) + shared email prompts + _CronQuit signal.

Extracted from bob/cron.py in v0.6.0 (#14 split). ``prompt_emails`` and
``prompt_email`` live here because they're shared between the install flow
and the management flow (``_manage.py`` imports them).

The ``_CronQuit`` exception is raised by the curses TUI (``bob/tui/cron.py``)
to escape any sub-screen back to the dispatcher, and is caught here in
``run_install_cron`` plus in ``run_manage_cron`` (defined in ``_manage.py``).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from bob._atomic import atomic_write
from bob._tty import prompt_wizard, safe_input
from bob.config import _EMAIL_RE  # M-1 (v0.5.5): single source of truth

from ._io import build_script_content
from ._options import CRON_LANGS, CRON_PROFILES, build_audit_options, default_dimensions
from ._parse import (
    CRON_DIR,
    SCRIPT_DIR,
    _detect_mta,
    _validate_custom_cron,
    build_schedule_expr,
    cron_to_human,
    list_installed_crons,
    make_slug,
    suggest_name,
)


def prompt_emails(t) -> list[str] | None:
    """
    Interactive multi-email selection prompt.

    Shows saved addresses from EmailStore with numeric shortcuts.
    After each selection the user is asked whether to add another address.
    Press Enter or choose 0 to finish (or to skip on first prompt).

    New valid addresses are offered for saving before being accepted.

    Returns:
        List of selected email strings (may be empty).
    """
    from bob.config import EmailStore

    store  = EmailStore.load()
    selected: list[str] = []

    while True:
        saved = store.all()

        print()
        print(f"  {t('email_prompt.title')}")
        if selected:
            print(f"    → {t('email_prompt.selected', emails=', '.join(selected))}")
        print(f"    0. {t('email_prompt.none')}")
        for i, addr in enumerate(saved, 1):
            marker = " ✔" if addr in selected else ""
            print(f"    {i}. {addr}{marker}")
        print(f"    {len(saved) + 1}. {t('email_prompt.new')}")
        print(f"    q. {t('email_prompt.cancel')}")
        print()

        answer = safe_input("  > ").strip()

        if answer.lower() in ("q", "quit"):
            return None   # cancelled — caller must not modify anything

        if not answer or answer == "0":
            break

        resolved = ""
        if answer.isdigit():
            idx = int(answer)
            if 1 <= idx <= len(saved):
                resolved = saved[idx - 1]
            elif idx == len(saved) + 1:
                resolved = safe_input(f"  {t('email_prompt.enter_new')} : ").strip()
        else:
            resolved = answer

        if not _EMAIL_RE.match(resolved):
            print(f"  ⚠ {t('email_prompt.invalid')}")
            continue

        if resolved in selected:
            # already chosen — silently skip
            pass
        else:
            selected.append(resolved)
            if resolved not in saved:
                save_ans = safe_input(f"  {t('email_prompt.save', email=resolved)} ").strip().lower()
                if save_ans == "y":
                    store.add(resolved)

        add_ans = safe_input(f"  {t('email_prompt.add_another')} ").strip().lower()
        if add_ans not in ("y", "o"):
            break

    return selected

def prompt_email(t) -> str:
    """Backward-compatible single-email wrapper around prompt_emails.

    Returns "" when the user cancels (q) or selects no email.
    """
    emails = prompt_emails(t)
    if emails is None or not emails:
        return ""
    return emails[0]

def _prompt_choice(t, prompt_key: str, option_keys: "list[str]",
                   default_index: int, hint_key: str = "") -> "int | None":
    """One screen, one closed question. Returns the chosen index, or None.

    ``None`` means the operator cancelled (``q`` or EOF); the caller must then
    leave the system untouched. Pressing Enter accepts ``default_index``,
    which the wizard seeds from the installing session — so the common case
    is one keystroke per screen.
    """
    print()
    print(f"  {t(prompt_key)}")
    for i, key in enumerate(option_keys, 1):
        marker = " ←" if i - 1 == default_index else ""
        print(f"    {i}. {t(key)}{marker}")
    if hint_key:
        print()
        print(f"  {t(hint_key)}")
    print()
    raw = prompt_wizard("  > ", default=str(default_index + 1))
    if raw is None:
        return None
    if not (raw.isdigit() and 1 <= int(raw) <= len(option_keys)):
        return -1        # caller reports the per-question error message
    return int(raw) - 1


def _run_install_cron_plain(user_config, config, t) -> int:
    """Install a cron job for automated audits using the schedule wizard."""
    from bob import output
    output.init(no_color=config.no_color)

    output.print_titled_box(t("install_cron.title"))
    print()

    log_dir_str = user_config.get("log_dir")
    if not log_dir_str:
        print(f"  ✖ {t('install_cron.no_log_dir')}")
        return 1
    log_dir = Path(log_dir_str)

    print(f"  {t('install_cron.quit_hint')}")
    print()

    # --- Step 1: Name ---
    existing_names = [e.name for e in list_installed_crons()]
    suggestion = suggest_name(existing_names)
    raw_name = prompt_wizard(
        f"  {t('install_cron.prompt_name', suggestion=suggestion)} : ",
        default=suggestion,
    )
    if raw_name is None:
        print(f"  {t('install_cron.cancelled')}")
        return 0
    slug = make_slug(raw_name)
    if not slug:
        print(f"  ✖ {t('install_cron.invalid_name')}")
        return 1
    # Defense-in-depth (v0.12.2): the name is sanitised to a slug for the file
    # path, but is also written verbatim into the "# name:" comment of the root
    # cron file. input() is line-based, so an interactively-entered name cannot
    # contain a newline today — but a hardening tool must not rely on that as
    # the SOLE guard for a root /etc/cron.d write. Strip control characters so
    # a name can never inject a second line into the cron file regardless of
    # how it was obtained.
    raw_name = re.sub(r"[\x00-\x1f\x7f]+", " ", raw_name).strip() or slug

    # --- Step 2: Schedule type ---
    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    raw_choice = prompt_wizard("  > ", default="1")
    if raw_choice is None:
        print(f"  {t('install_cron.cancelled')}")
        return 0
    if raw_choice not in ("1", "2", "3", "4"):
        print(f"  ✖ {t('install_cron.invalid_schedule')}")
        return 1
    choice = int(raw_choice)

    week_days = None
    month_days = None
    custom_expr = None
    hour = 3
    minute = 0

    if choice == 2:
        print()
        print(f"  {t('install_cron.prompt_weekdays')}")
        raw_days = prompt_wizard("  > ")
        if raw_days is None:
            print(f"  {t('install_cron.cancelled')}")
            return 0
        parts = re.split(r"[\s,]+", raw_days)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return 1

    elif choice == 3:
        print()
        print(f"  {t('install_cron.prompt_monthdays')}")
        raw_days = prompt_wizard("  > ")
        if raw_days is None:
            print(f"  {t('install_cron.cancelled')}")
            return 0
        parts = re.split(r"[\s,]+", raw_days)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            print(f"  ✖ {t('install_cron.invalid_days')}")
            return 1

    elif choice == 4:
        print()
        print(f"  {t('install_cron.prompt_custom')}")
        custom_expr = prompt_wizard("  > ")
        if custom_expr is None:
            print(f"  {t('install_cron.cancelled')}")
            return 0
        err = _validate_custom_cron(custom_expr)
        if err:
            print(f"  ✖ {t('install_cron.invalid_schedule')} ({err})")
            return 1

    # --- Step 3: Time ---
    if choice != 4:
        print()
        raw_time = prompt_wizard(
            f"  {t('install_cron.prompt_time')} : ",
            default="03:00",
        )
        if raw_time is None:
            print(f"  {t('install_cron.cancelled')}")
            return 0
        if not re.match(r"^\d{1,2}:\d{2}$", raw_time):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return 1
        h, m = raw_time.split(":")
        hour, minute = int(h), int(m)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            print(f"  ✖ {t('install_cron.invalid_time')}")
            return 1

    schedule_expr = build_schedule_expr(
        choice, hour, minute,
        week_days=week_days, month_days=month_days, custom_expr=custom_expr,
    )
    human = cron_to_human(schedule_expr, lang=config.lang)
    print()
    print(f"  {t('install_cron.preview', schedule=human)}")
    print()

    # --- Step 4: Notification email(s) ---
    notify_emails_raw = prompt_emails(t)
    notify_emails = notify_emails_raw or []   # None (cancelled) → no email
    notify_email  = ",".join(notify_emails)   # comma-separated for storage
    if notify_emails:
        _mta_ok, _mta_name = _detect_mta()
        if _mta_ok:
            print(f"  ✔ {t('install_cron.mta_found', mta=_mta_name or 'sendmail')}")
        else:
            print(f"  ⚠ {t('install_cron.mta_missing')}")

    # --- Steps 5-7: what the scheduled audit actually runs (v0.16.1) ---
    # Before v0.16.1 the generated script hardcoded ``--quiet --detailed`` and
    # nothing else, so a cron running as root picked up root's saved profile
    # and cron's bare $LANG — a different audit from the operator's, on the
    # same host. Each dimension is a closed set, pre-selected from the
    # installing session.
    def_profile, def_lang, def_offline = default_dimensions(config)

    idx = _prompt_choice(
        t, "install_cron.prompt_profile",
        [f"install_cron.profile.{p}" for p in CRON_PROFILES],
        CRON_PROFILES.index(def_profile),
        hint_key="install_cron.profile_hint",
    )
    if idx is None:
        print(f"  {t('install_cron.cancelled')}")
        return 0
    if idx < 0:
        print(f"  ✖ {t('install_cron.invalid_profile')}")
        return 1
    sel_profile = CRON_PROFILES[idx]

    idx = _prompt_choice(
        t, "install_cron.prompt_lang",
        [f"install_cron.lang.{lang}" for lang in CRON_LANGS],
        CRON_LANGS.index(def_lang),
        hint_key="install_cron.lang_hint",
    )
    if idx is None:
        print(f"  {t('install_cron.cancelled')}")
        return 0
    if idx < 0:
        print(f"  ✖ {t('install_cron.invalid_lang')}")
        return 1
    sel_lang = CRON_LANGS[idx]

    idx = _prompt_choice(
        t, "install_cron.prompt_network",
        ["install_cron.network_online", "install_cron.network_offline"],
        1 if def_offline else 0,
    )
    if idx is None:
        print(f"  {t('install_cron.cancelled')}")
        return 0
    if idx < 0:
        print(f"  ✖ {t('install_cron.invalid_network')}")
        return 1
    sel_offline = (idx == 1)

    audit_options = build_audit_options(sel_profile, sel_lang, sel_offline)

    cron_path   = CRON_DIR / f"bob-{slug}"
    script_path = SCRIPT_DIR / f"bob-{slug}"

    if cron_path.exists():
        ans = safe_input(f"\n  {t('install_cron.overwrite', path=str(cron_path))} ").strip().lower()
        if ans != "y":
            return 0

    now_str      = datetime.now().strftime("%Y-%m-%d")
    script_content = build_script_content(notify_email, log_dir, audit_options)

    print()
    print(f"  {t('install_cron.audit_command', command=f'bob --quiet --detailed {audit_options}')}")

    # I-1 (v0.6.1): atomic_write on creation paths. v0.5.7 #I-3 closed the
    # mutation path (apply_cron_schedule) but the install paths kept raw
    # os.open(O_TRUNC). Power-loss between truncate and write would leave
    # the script/cron file empty, breaking the installed cron silently.
    try:
        atomic_write(script_path, script_content, mode=0o755)
    except OSError as exc:
        print(f"  ✖ Cannot write {script_path}: {exc}")
        return 1

    print(f"  ✔ {t('install_cron.script_written', path=str(script_path))}")

    cron_content = (
        f"# BOB cron — generated {now_str} by bob --install-cron\n"
        f"# name: {raw_name}\n"
        f"# email: {notify_email}\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        f"{schedule_expr}  root  {script_path}\n"
    )

    try:
        atomic_write(cron_path, cron_content, mode=0o640)
    except OSError as exc:
        print(f"  ✖ Cannot write {cron_path}: {exc}")
        return 1

    print(f"  ✔ {t('install_cron.cron_written', path=str(cron_path))}")

    root_config_path = Path("/root/.config/bob/config.conf")
    try:
        from bob.config import UserConfig as _UC
        root_cfg = _UC.load(path=root_config_path)
        if not root_cfg.get("log_dir"):
            root_cfg.set("log_dir", str(log_dir))
    except OSError:
        pass

    print()
    print(f"  ✔ {t('install_cron.done_schedule', name=raw_name, schedule=human)}")
    return 0

class _CronQuit(Exception):
    """Raised from any curses sub-screen when the user presses q to quit entirely."""

def run_install_cron(user_config, config, t) -> int:
    """Dispatcher: curses TUI in a TTY, plain text fallback otherwise."""
    import sys as _sys
    if not _sys.stdout.isatty():
        return _run_install_cron_plain(user_config, config, t)
    import curses as _curses
    import os as _os
    from bob.tui.cron import _run_install_cron_curses
    _os.environ.setdefault("ESCDELAY", "25")
    try:
        return _curses.wrapper(lambda scr: _run_install_cron_curses(scr, user_config, config, t))
    except _CronQuit:
        return 0
    except (_curses.error, OSError):
        return _run_install_cron_plain(user_config, config, t)
