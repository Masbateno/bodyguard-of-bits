"""
Cron management utilities for BOB.

Handles:
- CronEntry dataclass representing an installed cron job
- Listing installed cron jobs (/etc/cron.d/bob-*)
- Parsing generated cron files to extract metadata
- Converting cron expressions to human-readable descriptions (EN/FR)
- Building cron expressions from wizard answers
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from bob._tty import read_line as _rl

CRON_DIR = Path("/etc/cron.d")
SCRIPT_DIR = Path("/usr/local/bin")

# Legacy paths created by v0.12 --install-cron
LEGACY_CRON_PATH = CRON_DIR / "bob"
LEGACY_SCRIPT_PATH = SCRIPT_DIR / "bob-nightly"

_DAYS_EN = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
_DAYS_FR = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]


@dataclass
class CronEntry:
    """Represents an installed BOB cron job."""

    name: str
    schedule_expr: str  # e.g. "0 3 * * *"
    hour: int
    minute: int
    script_path: Path
    cron_path: Path
    email: str = ""
    legacy: bool = False  # True if this is a pre-v0.13 cron


def list_installed_crons() -> list[CronEntry]:
    """Return all installed BOB cron entries."""
    entries: list[CronEntry] = []
    seen: set[Path] = set()

    # v0.13+ named crons: /etc/cron.d/bob-*
    for cron_path in sorted(CRON_DIR.glob("bob-*")):
        entry = parse_cron_file(cron_path)
        if entry:
            entries.append(entry)
            seen.add(cron_path)

    # Legacy v0.12 cron: /etc/cron.d/bob (no suffix)
    if LEGACY_CRON_PATH.exists() and LEGACY_CRON_PATH not in seen:
        entry = parse_cron_file(LEGACY_CRON_PATH, legacy=True)
        if entry:
            entries.append(entry)

    return entries


def parse_cron_file(path: Path, legacy: bool = False) -> Optional[CronEntry]:
    """Parse a BOB cron file and return a CronEntry, or None if unrecognised."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    # Extract name from metadata comment (v0.13+) or derive from filename
    name_match = re.search(r"^# name: (.+)$", text, re.MULTILINE)
    if name_match:
        name = name_match.group(1).strip()
    elif legacy:
        name = "nightly"
    else:
        stem = path.name
        if stem.startswith("bob-"):
            stem = stem[len("bob-"):]
        name = stem or path.name

    # Extract email from metadata comment
    email_match = re.search(r"^# email: (.*)$", text, re.MULTILINE)
    email = email_match.group(1).strip() if email_match else ""

    # Extract cron expression line (format: "M H DOM MON DOW  root  /path/script")
    cron_match = re.search(
        r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+root\s+(.+)$",
        text,
        re.MULTILINE,
    )
    if not cron_match:
        return None

    minute_s, hour_s, dom, month, dow, script = cron_match.groups()
    script = script.strip()
    schedule_expr = f"{minute_s} {hour_s} {dom} {month} {dow}"

    try:
        hour = int(hour_s)
        minute = int(minute_s)
    except ValueError:
        hour, minute = 0, 0

    return CronEntry(
        name=name,
        schedule_expr=schedule_expr,
        hour=hour,
        minute=minute,
        script_path=Path(script),
        cron_path=path,
        email=email,
        legacy=legacy,
    )


def cron_to_human(expr: str, lang: str = "en") -> str:
    """Convert a 5-field cron expression to a human-readable description."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return expr

    minute, hour, dom, month, dow = parts
    days_list = _DAYS_EN if lang == "en" else _DAYS_FR

    try:
        time_str = f"{int(hour):02d}:{int(minute):02d}"
    except ValueError:
        time_str = f"{hour}:{minute}"

    if dom == "*" and month == "*" and dow == "*":
        # Every day
        if lang == "fr":
            return f"tous les jours à {time_str}"
        return f"every day at {time_str}"

    if dom == "*" and month == "*" and dow != "*" and re.fullmatch(r"[\d,]+", dow):
        # Specific days of the week (simple numeric values only — not ranges or expressions)
        day_names = _parse_day_names(dow, days_list)
        if lang == "fr":
            return f"tous les {', '.join(day_names)} à {time_str}"
        return f"every {', '.join(day_names)} at {time_str}"

    if dom != "*" and month == "*" and dow == "*":
        # Specific days of the month
        day_nums = _parse_dom(dom)
        if lang == "fr":
            days_fmt = ", ".join(str(d) for d in day_nums)
            return f"le {days_fmt} de chaque mois à {time_str}"
        days_fmt = ", ".join(_ordinal(d) for d in day_nums)
        return f"the {days_fmt} of every month at {time_str}"

    # Fallback: raw expression
    if lang == "fr":
        return f"expression personnalisée : {expr}"
    return f"custom expression: {expr}"


def build_schedule_expr(
    choice: int,
    hour: int,
    minute: int,
    week_days: Optional[list[int]] = None,
    month_days: Optional[list[int]] = None,
    custom_expr: Optional[str] = None,
) -> str:
    """
    Build a cron schedule expression from wizard answers.

    Args:
        choice:      1=daily, 2=week days, 3=month days, 4=custom expression
        hour:        0-23
        minute:      0-59
        week_days:   list of 1-7 (1=Mon, 7=Sun) for choice 2
        month_days:  list of 1-31 for choice 3
        custom_expr: full 5-field expression for choice 4

    Returns:
        5-field cron expression string
    """
    if choice == 1:
        return f"{minute} {hour} * * *"
    if choice == 2:
        dow = ",".join(str(d) for d in sorted(week_days or []))
        return f"{minute} {hour} * * {dow}"
    if choice == 3:
        dom = ",".join(str(d) for d in sorted(month_days or []))
        return f"{minute} {hour} {dom} * *"
    if choice == 4:
        return (custom_expr or "").strip()
    raise ValueError(f"Invalid choice: {choice}")


def make_slug(name: str) -> str:
    """Convert a free-form name to a filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "custom"


def suggest_name(existing_names: list[str]) -> str:
    """Suggest a cron name that does not conflict with existing ones."""
    for candidate in ("nightly", "daily", "weekly", "monthly"):
        if candidate not in existing_names:
            return candidate
    i = 2
    while f"audit-{i}" in existing_names:
        i += 1
    return f"audit-{i}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_day_names(dow: str, days_list: list[str]) -> list[str]:
    """Parse a DOW field (1-7, Mon=1) into a list of day names."""
    result = []
    for part in dow.split(","):
        part = part.strip()
        if part.isdigit():
            idx = (int(part) - 1) % 7
            result.append(days_list[idx])
        else:
            result.append(part)
    return result


def _parse_dom(dom: str) -> list[int]:
    """Parse a DOM field into a sorted list of day-of-month integers."""
    result = []
    for part in re.split(r"[,\s]+", dom.strip()):
        if part.isdigit():
            result.append(int(part))
    return sorted(result)


def _ordinal(n: int) -> str:
    """Return the English ordinal string for an integer (1st, 2nd, 3rd, …)."""
    suffix = (
        "th"
        if 11 <= (n % 100) <= 13
        else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    )
    return f"{n}{suffix}"


# ---------------------------------------------------------------------------
# Cron expression validator
# ---------------------------------------------------------------------------

def _validate_custom_cron(expr: str) -> str:
    """
    Validate a 5-field cron expression entered by the user.

    Checks:
    1. Has exactly 5 whitespace-separated fields.
    2. Minute field, if a plain integer, is in 0–59.
    3. Hour field, if a plain integer, is in 0–23.

    Returns:
        Empty string if valid; a human-readable error message otherwise.
    """
    if not re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", expr):
        return "expected 5 fields: minute hour dom month dow"
    fields = expr.split()
    minute_s, hour_s = fields[0], fields[1]
    if minute_s.isdigit() and not (0 <= int(minute_s) <= 59):
        return f"minute value {minute_s!r} out of range (0–59)"
    if hour_s.isdigit() and not (0 <= int(hour_s) <= 23):
        return f"hour value {hour_s!r} out of range (0–23)"
    return ""


# ---------------------------------------------------------------------------
# MTA detection
# ---------------------------------------------------------------------------

def _detect_mta() -> tuple[bool, str]:
    """Detect whether a sendmail-compatible MTA is available.

    Returns (available, name) where name is the MTA product if identifiable,
    or "" when sendmail is found but the provider cannot be determined.
    """
    import shutil
    if not shutil.which("sendmail"):
        return False, ""
    for name, check in [
        ("Postfix", lambda: Path("/etc/postfix/main.cf").exists()),
        ("Exim",    lambda: bool(shutil.which("exim4") or shutil.which("exim"))),
        ("msmtp",   lambda: bool(shutil.which("msmtp"))),
        ("ssmtp",   lambda: bool(shutil.which("ssmtp"))),
    ]:
        if check():
            return True, name
    return True, ""


# ---------------------------------------------------------------------------
# Interactive runners (--install-cron, --manage-cron, --remove-cron)
# ---------------------------------------------------------------------------

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

    _EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

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

        answer = input("  > ").strip()

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
                resolved = input(f"  {t('email_prompt.enter_new')} : ").strip()
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
                save_ans = input(f"  {t('email_prompt.save', email=resolved)} ").strip().lower()
                if save_ans == "y":
                    store.add(resolved)

        add_ans = input(f"  {t('email_prompt.add_another')} ").strip().lower()
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


def _run_install_cron_plain(user_config, config, t) -> int:
    """Install a cron job for automated audits using the schedule wizard."""
    import os
    import shutil
    from datetime import datetime
    from pathlib import Path
    from bob import output
    output.init(no_color=config.no_color)

    W = 62
    title = t("install_cron.title")
    pad = W - 6 - len(title)
    print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
    print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
    print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
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
    raw_name = input(f"  {t('install_cron.prompt_name', suggestion=suggestion)} : ").strip()
    if raw_name.lower() in ("q", "quit"):
        print(f"  {t('install_cron.cancelled')}")
        return 0
    if not raw_name:
        raw_name = suggestion
    slug = make_slug(raw_name)
    if not slug:
        print(f"  ✖ {t('install_cron.invalid_name')}")
        return 1

    # --- Step 2: Schedule type ---
    print()
    print(f"  {t('install_cron.prompt_schedule')}")
    print(f"    1. {t('install_cron.schedule_daily')}")
    print(f"    2. {t('install_cron.schedule_weekdays')}")
    print(f"    3. {t('install_cron.schedule_monthdays')}")
    print(f"    4. {t('install_cron.schedule_custom')}")
    print()
    raw_choice = input("  > ").strip()
    if raw_choice.lower() in ("q", "quit"):
        print(f"  {t('install_cron.cancelled')}")
        return 0
    if not raw_choice:
        raw_choice = "1"
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
        raw_days = input("  > ").strip()
        if raw_days.lower() in ("q", "quit"):
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
        raw_days = input("  > ").strip()
        if raw_days.lower() in ("q", "quit"):
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
        custom_expr = input("  > ").strip()
        if custom_expr.lower() in ("q", "quit"):
            print(f"  {t('install_cron.cancelled')}")
            return 0
        err = _validate_custom_cron(custom_expr)
        if err:
            print(f"  ✖ {t('install_cron.invalid_schedule')} ({err})")
            return 1

    # --- Step 3: Time ---
    if choice != 4:
        print()
        raw_time = input(f"  {t('install_cron.prompt_time')} : ").strip()
        if raw_time.lower() in ("q", "quit"):
            print(f"  {t('install_cron.cancelled')}")
            return 0
        if not raw_time:
            raw_time = "03:00"
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

    cron_path   = CRON_DIR / f"bob-{slug}"
    script_path = SCRIPT_DIR / f"bob-{slug}"

    if cron_path.exists():
        ans = input(f"\n  {t('install_cron.overwrite', path=str(cron_path))} ").strip().lower()
        if ans != "y":
            return 0

    audit_bin = shutil.which("bob") or "/usr/local/bin/bob"
    now_str   = datetime.now().strftime("%Y-%m-%d")
    try:
        bob_path = str(Path(__file__).parent.parent)
    except (TypeError, AttributeError):
        bob_path = "/usr/local/lib"

    script_content = (
        "#!/bin/bash\n"
        f"# BOB script — generated {now_str} by bob --install-cron\n"
        "# Re-generate: sudo bob --install-cron\n\n"
        f'NOTIFY_EMAILS={shlex.quote(notify_email)}\n'
        f'LOG_DIR={shlex.quote(str(log_dir))}\n'
        f'export PYTHONPATH={shlex.quote(bob_path)}:"$PYTHONPATH"\n\n'
        f'{shlex.quote(str(audit_bin))} --quiet --detailed\n'
        "RC=$?\n\n"
        'if [ "$RC" -gt 0 ] && [ -n "$NOTIFY_EMAILS" ]; then\n'
        '    LOG=$(ls -t "$LOG_DIR"/bob_*.log 2>/dev/null | head -1)\n'
        '    if [ -n "$LOG" ]; then\n'
        '        IFS="," read -ra _ADDRS <<< "$NOTIFY_EMAILS"\n'
        '        for _ADDR in "${_ADDRS[@]}"; do\n'
        "            export AUDIT_LOG=\"$LOG\"\n"
        "            export AUDIT_EMAIL=\"$_ADDR\"\n"
        "            export AUDIT_RC=\"$RC\"\n"
        "            python3 << 'PYTHON_EOF'\n"
        "import os, re\n"
        "from bob.report_markdown import send_audit_log_as_html_email\n\n"
        "hostname = os.uname().nodename\n"
        "log_file = os.environ.get('AUDIT_LOG')\n"
        "email = os.environ.get('AUDIT_EMAIL')\n"
        "score = 'N/A'\n"
        "if log_file:\n"
        "    try:\n"
        "        content = open(log_file, encoding='utf-8', errors='replace').read()\n"
        "        m = re.search(r'Score\\s*:\\s*(\\d+/10)', content)\n"
        "        if m:\n"
        "            score = m.group(1)\n"
        "    except OSError:\n"
        "        pass\n"
        "subject = f'[BOB] {hostname} - Score {score}'\n"
        "if log_file and email:\n"
        "    send_audit_log_as_html_email(log_file, email, subject)\n"
        "PYTHON_EOF\n"
        "        done\n"
        "    fi\n"
        "fi\n"
    )

    try:
        fd = os.open(str(script_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
        with os.fdopen(fd, "w") as fh:
            fh.write(script_content)
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
        fd = os.open(str(cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as fh:
            fh.write(cron_content)
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


def _run_install_cron_curses(stdscr, user_config, config, t) -> int:
    """Curses TUI for --install-cron."""
    import curses as _c
    import os as _os
    import shutil
    from datetime import datetime
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
                try:
                    stdscr.addstr(0, 0, "  bob --install-cron".ljust(w - 1), hdr_attr)
                    stdscr.addstr(2, 2, t("install_cron.landing_prompt"))
                    stdscr.addstr(h - 1, 0, "  Enter: create   q: quit".ljust(w - 1), ftr_attr)
                except _c.error:
                    pass
                stdscr.refresh()
                try:
                    ch = stdscr.get_wch()
                except _c.error:
                    continue
                ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)
                if ch_i in (ord("q"), ord("Q")):
                    raise _CronQuit()
                if ch_i in (10, 13) or ch_i == _c.KEY_ENTER:
                    step = STEP_NAME

            elif step == STEP_NAME:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                try:
                    stdscr.addstr(0, 0, "  bob --install-cron".ljust(w - 1), hdr_attr)
                    stdscr.addstr(2, 2, t("install_cron.prompt_name", suggestion=suggestion))
                except _c.error:
                    pass
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
                class _FakeEntry:
                    pass
                _fe = _FakeEntry()
                _fe.name = raw_name
                _fe.hour = 3
                _fe.minute = 0
                result = _curses_schedule_wizard(stdscr, _fe, config, t, title_prefix="Install cron")
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
                    try:
                        stdscr.addstr(0, 0, "  bob --install-cron".ljust(w - 1), hdr_attr)
                        stdscr.addstr(2, 2, t("install_cron.overwrite", path=str(cron_path)))
                        stdscr.addstr(h - 1, 0, "  y: overwrite   Esc: back   q: quit".ljust(w - 1), ftr_attr)
                    except _c.error:
                        pass
                    stdscr.refresh()
                    try:
                        ch = stdscr.get_wch()
                    except _c.error:
                        continue
                    ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)
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

        audit_bin = shutil.which("bob") or "/usr/local/bin/bob"
        now_str   = datetime.now().strftime("%Y-%m-%d")
        try:
            bob_path = str(_Path(__file__).parent.parent)
        except (TypeError, AttributeError):
            bob_path = "/usr/local/lib"

        script_content = (
            "#!/bin/bash\n"
            f"# BOB script — generated {now_str} by bob --install-cron\n"
            "# Re-generate: sudo bob --install-cron\n\n"
            f"NOTIFY_EMAILS={shlex.quote(notify_email)}\n"
            f"LOG_DIR={shlex.quote(str(log_dir))}\n"
            f"export PYTHONPATH={shlex.quote(bob_path)}:\"$PYTHONPATH\"\n\n"
            f"{shlex.quote(str(audit_bin))} --quiet --detailed\n"
            "RC=$?\n\n"
            'if [ "$RC" -gt 0 ] && [ -n "$NOTIFY_EMAILS" ]; then\n'
            '    LOG=$(ls -t "$LOG_DIR"/bob_*.log 2>/dev/null | head -1)\n'
            '    if [ -n "$LOG" ]; then\n'
            '        IFS="," read -ra _ADDRS <<< "$NOTIFY_EMAILS"\n'
            '        for _ADDR in "${_ADDRS[@]}"; do\n'
            "            export AUDIT_LOG=\"$LOG\"\n"
            "            export AUDIT_EMAIL=\"$_ADDR\"\n"
            "            export AUDIT_RC=\"$RC\"\n"
            "            python3 << 'PYTHON_EOF'\n"
            "import os, re\n"
            "from bob.report_markdown import send_audit_log_as_html_email\n\n"
            "hostname = os.uname().nodename\n"
            "log_file = os.environ.get('AUDIT_LOG')\n"
            "email = os.environ.get('AUDIT_EMAIL')\n"
            "score = 'N/A'\n"
            "if log_file:\n"
            "    try:\n"
            "        content = open(log_file, encoding='utf-8', errors='replace').read()\n"
            "        m = re.search(r'Score\\s*:\\s*(\\d+/10)', content)\n"
            "        if m:\n"
            "            score = m.group(1)\n"
            "    except OSError:\n"
            "        pass\n"
            "subject = f'[BOB] {hostname} - Score {score}'\n"
            "if log_file and email:\n"
            "    send_audit_log_as_html_email(log_file, email, subject)\n"
            "PYTHON_EOF\n"
            "        done\n"
            "    fi\n"
            "fi\n"
        )

        try:
            fd = _os.open(str(script_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o755)
            with _os.fdopen(fd, "w") as fh:
                fh.write(script_content)
        except OSError as exc:
            _curses_status_flash(stdscr, f"✖ Cannot write {script_path}: {exc}")
            return 1

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


def run_install_cron(user_config, config, t) -> int:
    """Dispatcher: curses TUI in a TTY, plain text fallback otherwise."""
    import sys as _sys
    if not _sys.stdout.isatty():
        return _run_install_cron_plain(user_config, config, t)
    import curses as _curses
    import os as _os
    _os.environ.setdefault("ESCDELAY", "25")
    try:
        return _curses.wrapper(lambda scr: _run_install_cron_curses(scr, user_config, config, t))
    except _CronQuit:
        return 0
    except Exception:
        return _run_install_cron_plain(user_config, config, t)


def _manage_email_store(t) -> None:
    """Interactive sub-menu to manage the EmailStore (add / delete emails).

    Loops until the user explicitly quits with Enter or 'q'.
    The list is refreshed from disk before each iteration.
    """
    from bob.config import EmailStore

    W = 62
    title = t("manage_cron.email_store_title")
    pad = W - 6 - len(title)

    while True:
        store = EmailStore.load()
        emails = store.all()

        print()
        print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
        print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
        print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
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
            if not re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", raw):
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


# ---------------------------------------------------------------------------
# Curses helpers for --manage-cron sub-screens
# ---------------------------------------------------------------------------

class _CronQuit(Exception):
    """Raised from any sub-screen when the user presses q to quit entirely."""


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
        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue
        ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)
        if ch_i == 27:
            _c.curs_set(0)
            return None
        elif ch_i in (10, 13) or ch_i == _c.KEY_ENTER:
            _c.curs_set(0)
            return text
        elif ch_i in (127, 8) or ch_i == _c.KEY_BACKSPACE:
            if buf:
                buf.pop()
        elif isinstance(ch, str) and ch >= " ":
            buf.append(ch)


def _apply_cron_schedule(entry, schedule_expr: str) -> str:
    """Patch the cron file with *schedule_expr*. Returns error string or ''."""
    import os as _os
    try:
        text = entry.cron_path.read_text(encoding="utf-8")
    except OSError as exc:
        return str(exc)
    new_line = f"{schedule_expr}  root  {entry.script_path}"
    new_text = re.sub(
        r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$",
        lambda _: new_line,
        text,
        flags=re.MULTILINE,
    )
    try:
        fd = _os.open(str(entry.cron_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o640)
        with _os.fdopen(fd, "w") as fh:
            fh.write(new_text)
    except OSError as exc:
        return str(exc)
    return ""


def _apply_cron_email_str(entry, new_email: str) -> str:
    """Patch cron + script files with *new_email*. Returns error string or ''."""
    try:
        lines = entry.cron_path.read_text(encoding="utf-8").splitlines()
        updated = [
            f"# email: {new_email}" if ln.startswith("# email:") else ln
            for ln in lines
        ]
        _atomic_write(entry.cron_path, "\n".join(updated) + "\n")
    except OSError as exc:
        return str(exc)
    if entry.script_path.exists():
        try:
            text = entry.script_path.read_text(encoding="utf-8")
            text = re.sub(
                r"^NOTIFY_EMAILS=.*$",
                lambda _: f"NOTIFY_EMAILS={__import__('shlex').quote(new_email)}",
                text,
                flags=re.MULTILINE,
            )
            _atomic_write(entry.script_path, text)
        except OSError as exc:
            return str(exc)
    return ""


def _curses_schedule_wizard(stdscr, entry, config, t, title_prefix: str = "Edit schedule") -> "str | None":
    """Full schedule wizard inside curses. Returns new cron expression or None."""
    import curses as _c
    has_color = _c.has_colors()
    hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
    ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE

    def _hdr(suffix=""):
        h2, w2 = stdscr.getmaxyx()
        label = f"  {title_prefix}: {entry.name}  {suffix}" if entry else f"  {title_prefix}  {suffix}"
        try:
            stdscr.addstr(0, 0, label[:w2 - 1].ljust(w2 - 1), hdr_attr)
        except _c.error:
            pass

    def _ftr(msg="  Esc: back   q: quit"):
        h2, w2 = stdscr.getmaxyx()
        try:
            stdscr.addstr(h2 - 1, 0, msg[:w2 - 1].ljust(w2 - 1), ftr_attr)
        except _c.error:
            pass

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
        try:
            stdscr.addstr(2, 2, t("install_cron.prompt_schedule"))
        except _c.error:
            pass
        for i, opt in enumerate(options):
            is_cur = (i == sel)
            attr = (_c.color_pair(1) | _c.A_BOLD) if (is_cur and has_color) else (_c.A_REVERSE if is_cur else _c.A_NORMAL)
            try:
                stdscr.addstr(4 + i, 2, f"  {i + 1}. {opt}  "[:w - 3], attr)
            except _c.error:
                pass
        _ftr("  ↑↓: move   Enter: select   Esc: back   q: quit")
        stdscr.refresh()
        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue
        ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)
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
        elif isinstance(ch, str) and ch in ("1", "2", "3", "4"):
            choice = int(ch)
            break

    # Step 2 — extra input depending on choice
    week_days = None
    month_days = None
    custom_expr = None
    hour = entry.hour if entry else 3
    minute = entry.minute if entry else 0

    if choice == 2:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        try:
            stdscr.addstr(2, 2, t("install_cron.prompt_weekdays"))
            stdscr.addstr(3, 4, "(1=Mon 2=Tue 3=Wed 4=Thu 5=Fri 6=Sat 7=Sun)")
        except _c.error:
            pass
        _ftr()
        raw = _curses_readline(stdscr, h - 1, w, "Days (e.g. 1,5)")
        if raw is None:
            return None
        parts = re.split(r"[\s,]+", raw)
        week_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 7]
        if not week_days:
            return None

    elif choice == 3:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        try:
            stdscr.addstr(2, 2, t("install_cron.prompt_monthdays"))
            stdscr.addstr(3, 4, "(e.g. 1,15)")
        except _c.error:
            pass
        _ftr()
        raw = _curses_readline(stdscr, h - 1, w, "Days (e.g. 1,15)")
        if raw is None:
            return None
        parts = re.split(r"[\s,]+", raw)
        month_days = [int(p) for p in parts if p.isdigit() and 1 <= int(p) <= 31]
        if not month_days:
            return None

    elif choice == 4:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        try:
            stdscr.addstr(2, 2, t("install_cron.prompt_custom"))
            stdscr.addstr(3, 4, "(minute hour dom month dow)")
        except _c.error:
            pass
        _ftr()
        raw = _curses_readline(stdscr, h - 1, w, "Expression")
        if raw is None:
            return None
        err = _validate_custom_cron(raw)
        if err:
            stdscr.erase()
            try:
                stdscr.addstr(2, 2, f"✖ {err}")
                stdscr.addstr(4, 2, "Press any key to cancel…")
            except _c.error:
                pass
            stdscr.refresh()
            try:
                stdscr.get_wch()
            except _c.error:
                pass
            return None
        custom_expr = raw

    # Step 3 — time (not for custom)
    if choice != 4:
        default_time = f"{hour:02d}:{minute:02d}"
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        _hdr()
        try:
            stdscr.addstr(2, 2, t("install_cron.prompt_time") + f"  (default: {default_time})")
        except _c.error:
            pass
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
        try:
            stdscr.addstr(2, 2, t("install_cron.preview", schedule=human))
            stdscr.addstr(4, 2, t("manage_cron.confirm_update"))
        except _c.error:
            pass
        _ftr("  y: confirm   Esc: back   q: quit")
        stdscr.refresh()
        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue
        ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)
        if ch_i in (ord("q"), ord("Q")):
            raise _CronQuit()
        if ch_i in (ord("y"), ord("Y"), 10, 13) or ch_i == _c.KEY_ENTER:
            return schedule_expr
        return None


def _curses_email_list_sub(stdscr, current_email: str, t) -> "str | None":
    """Select notification emails for a cron entry. Returns comma-sep str or None."""
    import curses as _c
    from bob.config import EmailStore
    _EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
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
        try:
            stdscr.addstr(0, 0, hdr[:w - 1].ljust(w - 1), hdr_attr)
        except _c.error:
            pass

        if not saved:
            try:
                stdscr.addstr(2, 2, "No saved emails.")
                stdscr.addstr(3, 2, "→ Press  n  to add an email address.")
                stdscr.addstr(4, 2, "→ Press  Enter  to skip (no email notification).")
            except _c.error:
                pass
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
                try:
                    stdscr.addstr(row + 1, 0, line[:w - 1].ljust(w - 1), attr)
                except _c.error:
                    pass

        ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
        if status:
            footer = f"  {status}"
            status = ""
        elif selected:
            footer = f"  {len(selected)} selected — Enter: confirm"
        else:
            footer = "  0 selected — n: add email   Enter: no email"
        try:
            stdscr.addstr(h - 1, 0, footer[:w - 1].ljust(w - 1), ftr_attr)
        except _c.error:
            pass

        stdscr.refresh()
        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue
        ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)

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
            try:
                stdscr.addstr(0, 0, "  Add email address".ljust(w - 1), hdr_attr)
                stdscr.addstr(h - 2, 0, "  Esc: back".ljust(w - 1), ftr_attr)
            except _c.error:
                pass
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
    _EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
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
        try:
            stdscr.addstr(0, 0, hdr[:w - 1].ljust(w - 1), hdr_attr)
        except _c.error:
            pass

        if not emails:
            try:
                stdscr.addstr(2, 2, t("manage_cron.email_store_empty"))
                stdscr.addstr(4, 2, "n: " + t("manage_cron.email_store_ex_add"))
            except _c.error:
                pass
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
                try:
                    stdscr.addstr(row + 1, 0, line[:w - 1].ljust(w - 1), attr)
                except _c.error:
                    pass

        if status:
            footer = f"  {status}"
            status = ""
        else:
            footer = f"  {n} email(s)"
        try:
            stdscr.addstr(h - 1, 0, footer[:w - 1].ljust(w - 1), ftr_attr)
        except _c.error:
            pass

        stdscr.refresh()
        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue
        ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)

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
            try:
                stdscr.addstr(0, 0, "  Add email address".ljust(w - 1), hdr_attr)
                stdscr.addstr(2, 2, t("manage_cron.email_store_enter"))
            except _c.error:
                pass
            raw = _curses_readline(stdscr, h - 1, w, "Email")
            if raw and _EMAIL_RE.match(raw.strip()):
                store.add(raw.strip())
                status = t("manage_cron.email_store_added", email=raw.strip())
            elif raw:
                status = t("manage_cron.email_store_invalid_email")


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
        try:
            stdscr.addstr(0, 0, hdr[:w - 1].ljust(w - 1), hdr_attr)
        except _c.error:
            pass
        for i, opt in enumerate(options):
            is_cur = (i == sel)
            attr = (_c.color_pair(1) | _c.A_BOLD) if (is_cur and has_color) else (
                _c.A_REVERSE if is_cur else _c.A_NORMAL)
            try:
                stdscr.addstr(2 + i, 2, f"  {i + 1}. {opt}  "[:w - 3], attr)
            except _c.error:
                pass
        try:
            stdscr.addstr(h - 1, 0, "  Esc: back   q: quit"[:w - 1].ljust(w - 1), ftr_attr)
        except _c.error:
            pass
        stdscr.refresh()
        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue
        ch_i = ord(ch) if isinstance(ch, str) and len(ch) == 1 else (ch if isinstance(ch, int) else -1)

        if ch_i == 27:
            return
        elif ch_i in (ord("q"), ord("Q")):
            raise _CronQuit()
        elif ch_i in (_c.KEY_UP, ord("k")):
            sel = max(0, sel - 1)
        elif ch_i in (_c.KEY_DOWN, ord("j")):
            sel = min(1, sel + 1)
        elif ch_i in (_c.KEY_ENTER, 10, 13) or ch_i == ord("1") and sel == 0 or ch_i == ord("2") and sel == 1:
            chosen = sel
            if ch_i == ord("1"):
                chosen = 0
            elif ch_i == ord("2"):
                chosen = 1
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



def _curses_status_flash(stdscr, msg: str) -> None:
    """Display *msg* on the body area and wait for a keypress."""
    import curses as _c
    has_color = _c.has_colors()
    hdr_attr = (_c.color_pair(5) | _c.A_BOLD) if has_color else _c.A_REVERSE
    ftr_attr = _c.color_pair(2) if has_color else _c.A_REVERSE
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    try:
        stdscr.addstr(0, 0, " " * (w - 1), hdr_attr)
        stdscr.addstr(2, 2, msg[:w - 3])
        stdscr.addstr(4, 2, "Press any key to continue…")
        stdscr.addstr(h - 1, 0, " " * (w - 1), ftr_attr)
    except _c.error:
        pass
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
        try:
            stdscr.addstr(0, 0, header[:w - 1].ljust(w - 1), hdr_attr)
        except _c.error:
            pass

        # ── Body ─────────────────────────────────────────────────────────────
        if not crons:
            try:
                stdscr.addstr(2, 2, t("manage_cron.no_crons"))
                stdscr.addstr(4, 2, "m: " + t("manage_cron.prompt_ex_email_book"))
            except _c.error:
                pass
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
                try:
                    stdscr.addstr(row + 1, 0, line[:w - 1].ljust(w - 1), attr)
                except _c.error:
                    pass

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
        try:
            stdscr.addstr(h - 1, 0, footer[:w - 1].ljust(w - 1), ftr_attr)
        except _c.error:
            pass

        stdscr.refresh()

        try:
            ch = stdscr.get_wch()
        except _c.error:
            continue

        if isinstance(ch, str):
            ch = ord(ch) if len(ch) == 1 else -1

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


def _run_manage_cron_plain(config, t) -> int:
    """Manage installed cron jobs — list, edit schedule/email, delete.

    Loops until the user explicitly quits (Enter / 'q').
    The cron list is refreshed from disk at the start of each iteration.
    """
    from bob import output
    output.init(no_color=config.no_color)

    W = 62
    title = t("manage_cron.title")
    pad = W - 6 - len(title)

    while True:
        print(f"\033[1;34m╔{'═'*(W-2)}╗\033[0m")
        print(f"\033[1;34m║\033[0m  \033[1m{title}\033[0m{' '*max(0,pad)}  \033[1;34m║\033[0m")
        print(f"\033[1;34m╚{'═'*(W-2)}╝\033[0m")
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
    _os.environ.setdefault("ESCDELAY", "25")
    try:
        return _curses.wrapper(lambda scr: _run_manage_cron_curses(scr, config, t))
    except _CronQuit:
        return 0
    except Exception:
        return _run_manage_cron_plain(config, t)


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically (temp file + os.replace)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(str(tmp), str(path))


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

    try:
        lines = entry.cron_path.read_text(encoding="utf-8").splitlines()
        updated = []
        for line in lines:
            if line.startswith("# email:"):
                updated.append(f"# email: {new_email}")
            else:
                updated.append(line)
        _atomic_write(entry.cron_path, "\n".join(updated) + "\n")
    except OSError as exc:
        print(f"  ✖ Cannot update cron file: {exc}")
        return

    if entry.script_path.exists():
        try:
            text = entry.script_path.read_text(encoding="utf-8")
            # Fix: script uses NOTIFY_EMAILS (plural)
            text = re.sub(
                r"^NOTIFY_EMAILS=.*$",
                lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",
                text,
                flags=re.MULTILINE,
            )
            _atomic_write(entry.script_path, text)
        except OSError as exc:
            print(f"  ✖ Cannot update script: {exc}")
            return

    label = new_email if new_email else t("manage_cron.no_email")
    print(f"  ✔ {t('manage_cron.email_updated', name=entry.name, email=label)}")


def edit_cron_schedule(entry, config, t) -> None:
    """Re-run the schedule wizard for an existing cron entry and patch its cron file."""
    import os as _os

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
        raw_days = input("  > ").strip()
        if raw_days.lower() in ("q", "quit"):
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
        raw_days = input("  > ").strip()
        if raw_days.lower() in ("q", "quit"):
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
        custom_expr = input("  > ").strip()
        if custom_expr.lower() in ("q", "quit"):
            print(f"  {t('manage_cron.cancelled')}")
            return
        err = _validate_custom_cron(custom_expr)
        if err:
            print(f"  ✖ {t('install_cron.invalid_schedule')} ({err})")
            return

    if choice != 4:
        print()
        raw_time = input(f"  {t('install_cron.prompt_time')} : ").strip()
        if raw_time.lower() in ("q", "quit"):
            print(f"  {t('manage_cron.cancelled')}")
            return
        if not raw_time:
            raw_time = f"{entry.hour:02d}:{entry.minute:02d}"
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

    try:
        text = entry.cron_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"  ✖ Cannot read {entry.cron_path}: {exc}")
        return

    new_line = f"{schedule_expr}  root  {entry.script_path}"
    new_text = re.sub(
        r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$",
        lambda _: new_line,
        text,
        flags=re.MULTILINE,
    )

    try:
        fd = _os.open(str(entry.cron_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o640)
        with _os.fdopen(fd, "w") as fh:
            fh.write(new_text)
    except OSError as exc:
        print(f"  ✖ Cannot write {entry.cron_path}: {exc}")
        return

    print(f"  ✔ {t('manage_cron.updated', name=entry.name, schedule=human)}")
