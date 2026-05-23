"""
Cron management utilities for BOB.

Handles:
- CronEntry dataclass representing an installed cron job
- Listing installed cron jobs (/etc/cron.d/bob-*)
- Parsing generated cron files to extract metadata
- Converting cron expressions to human-readable descriptions (EN/FR)
- Building cron expressions from wizard answers
- Interactive install wizard (plain-text flow)
- Interactive management (plain-text flow)

Curses TUI code lives in bob.tui.cron.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from bob._tty import read_line as _rl, prompt_wizard

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

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

_CRON_FIELD_BOUNDS = (
    ("minute",       0, 59),
    ("hour",         0, 23),
    ("day of month", 1, 31),
    ("month",        1, 12),
    ("day of week",  0, 7),  # 0 and 7 both = Sunday
)


def _validate_cron_field(field: str, name: str, lo: int, hi: int) -> str:
    """Validate one cron field. Returns "" on success or an error message.

    Accepts the standard syntax: ``*``, ``N``, ``N-M``, ``*/K``, ``N-M/K``,
    and comma-separated lists of the above. Rejects out-of-range numbers
    that the original isdigit-only check let through (e.g. ``0-1000`` or
    ``*/200``).
    """
    for chunk in field.split(","):
        if not chunk:
            return f"{name} has an empty entry"
        # Step: BASE/K
        if "/" in chunk:
            base, _, step_s = chunk.partition("/")
            if not step_s.isdigit() or int(step_s) < 1:
                return f"{name} step {step_s!r} must be a positive integer"
            chunk = base
        # Range: N-M
        if "-" in chunk and chunk != "*":
            lo_s, _, hi_s = chunk.partition("-")
            if not (lo_s.isdigit() and hi_s.isdigit()):
                return f"{name} range {chunk!r} must be numeric"
            n, m = int(lo_s), int(hi_s)
            if not (lo <= n <= hi and lo <= m <= hi):
                return f"{name} range {chunk!r} out of bounds ({lo}-{hi})"
            if n > m:
                return f"{name} range {chunk!r} reversed"
            continue
        # Wildcard
        if chunk == "*":
            continue
        # Plain integer
        if chunk.isdigit():
            n = int(chunk)
            if not (lo <= n <= hi):
                return f"{name} value {n} out of range ({lo}-{hi})"
            continue
        return f"{name} value {chunk!r} not understood"
    return ""


def _validate_custom_cron(expr: str) -> str:
    """
    Validate a 5-field cron expression entered by the user.

    Each field is checked for syntax (``*``, ``N``, ``N-M``, ``N-M/K``,
    comma-separated lists) and bounds — minute 0-59, hour 0-23, dom 1-31,
    month 1-12, dow 0-7. Out-of-range numbers (e.g. ``0-1000``, ``*/200``)
    are rejected.

    Returns:
        Empty string if valid; a human-readable error message otherwise.
    """
    if not re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", expr):
        return "expected 5 fields: minute hour dom month dow"
    fields = expr.split()
    for value, (name, lo, hi) in zip(fields, _CRON_FIELD_BOUNDS):
        err = _validate_cron_field(value, name, lo, hi)
        if err:
            return err
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
    from datetime import datetime
    from pathlib import Path
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

    cron_path   = CRON_DIR / f"bob-{slug}"
    script_path = SCRIPT_DIR / f"bob-{slug}"

    if cron_path.exists():
        ans = input(f"\n  {t('install_cron.overwrite', path=str(cron_path))} ").strip().lower()
        if ans != "y":
            return 0

    now_str      = datetime.now().strftime("%Y-%m-%d")
    script_content = build_script_content(notify_email, log_dir)

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


# ---------------------------------------------------------------------------
# Management — plain-text helpers
# ---------------------------------------------------------------------------

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


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically (temp file + os.replace)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(str(tmp), str(path))


def build_script_content(notify_email: str, log_dir: "Path | str") -> str:
    """Build the bash script content for a BOB cron job."""
    import shutil
    from datetime import datetime
    audit_bin = shutil.which("bob") or "/usr/local/bin/bob"
    now_str   = datetime.now().strftime("%Y-%m-%d")
    try:
        bob_path = str(Path(__file__).parent.parent)
    except (TypeError, AttributeError):
        bob_path = "/usr/local/lib"
    return (
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


# ---------------------------------------------------------------------------
# File-patching helpers — shared between the plain-text wizard
# (edit_cron_schedule / edit_cron_email below) and the curses TUI
# (bob/tui/cron.py imports these). Centralising avoids drift between the
# two branches — see v0.4.8 cleanup pass.
# ---------------------------------------------------------------------------

def apply_cron_schedule(entry, schedule_expr: str) -> str:
    """Patch *entry.cron_path* in place with *schedule_expr*.

    Replaces the unique `MIN HOUR DOM MONTH DOW root <script>` line of the
    cron file. Returns an empty string on success, or the OSError string on
    read/write failure (caller renders it to the user).
    """
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
        fd = os.open(str(entry.cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as fh:
            fh.write(new_text)
    except OSError as exc:
        return str(exc)
    return ""


def apply_cron_email(entry, new_email: str) -> tuple[str, int]:
    """Patch *entry.cron_path* and the associated wrapper script with *new_email*.

    Accepts the legacy `NOTIFY_EMAIL=` form (no S) in the script for
    backward-compat with pre-v0.3 generated wrappers.

    Returns:
        (error_string, script_subst_count)
        - error_string is "" on success, otherwise the OSError message.
        - script_subst_count is the number of replacements done in the
          wrapper script. 0 indicates the NOTIFY_EMAILS= line was missing
          (the caller may want to warn the user).
    """
    try:
        lines = entry.cron_path.read_text(encoding="utf-8").splitlines()
        updated = [
            f"# email: {new_email}" if ln.startswith("# email:") else ln
            for ln in lines
        ]
        _atomic_write(entry.cron_path, "\n".join(updated) + "\n")
    except OSError as exc:
        return (str(exc), 0)

    subst_count = 0
    if entry.script_path.exists():
        try:
            text = entry.script_path.read_text(encoding="utf-8")
            # Match both NOTIFY_EMAILS= (current) and NOTIFY_EMAIL= (legacy)
            text, subst_count = re.subn(
                r"^NOTIFY_EMAILS?=.*$",
                lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",
                text,
                flags=re.MULTILINE,
            )
            _atomic_write(entry.script_path, text)
        except OSError as exc:
            return (str(exc), subst_count)
    return ("", subst_count)


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
