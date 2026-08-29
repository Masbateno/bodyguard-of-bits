"""CronEntry data + parsing + validation + day/MTA helpers.

Extracted from bob/cron.py in v0.6.0 (#14 split). Standalone — no other
bob.cron submodule imports. The CronEntry dataclass and its parsing layer
form the foundation that ``_io`` (file patching), ``_install`` (wizard),
and ``_manage`` (CRUD) all build on.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

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
    # M-1 (v0.7.0): False when the minute/hour fields aren't plain integers
    # (e.g. ``*/15``, ``0-23/3``). In that case hour=0, minute=0 are placeholders
    # for UI defaults and ``schedule_expr`` is the only source of truth.
    time_simple: bool = True

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

def parse_cron_file(path: Path, legacy: bool = False) -> CronEntry | None:
    """Parse a BOB cron file and return a CronEntry, or None if unrecognised."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
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
        # M-1 (v0.7.0): pre-fix, returning None here was silent — a malformed
        # bob-* cron file (non-root user, missing column, partial overwrite)
        # was simply omitted from list_installed_crons(). Log a warning so
        # operators can see why a BOB cron has "disappeared" from the wizard.
        _log.warning(
            "cron file %s has no recognisable BOB cron line "
            "(expected 5 schedule fields + 'root' + command); skipping",
            path,
        )
        return None

    minute_s, hour_s, dom, month, dow, script = cron_match.groups()
    script = script.strip()
    schedule_expr = f"{minute_s} {hour_s} {dom} {month} {dow}"

    try:
        hour = int(hour_s)
        minute = int(minute_s)
        time_simple = True
    except ValueError:
        # M-1 (v0.7.0): pre-fix, hour=0/minute=0 fallback was silent — the
        # reschedule wizard then showed "00:00" as the current time even when
        # the cron expression was e.g. "*/15 * * * *", misleading the user.
        # Now: flag the entry as non-simple, log explicitly, and let the UI
        # adapt (see bob.cron._manage / bob.tui.cron).
        _log.info(
            "cron file %s uses non-integer time fields (minute=%r hour=%r); "
            "schedule_expr=%r is the source of truth, hour/minute are placeholders",
            path, minute_s, hour_s, schedule_expr,
        )
        hour, minute = 0, 0
        time_simple = False

    return CronEntry(
        name=name,
        schedule_expr=schedule_expr,
        hour=hour,
        minute=minute,
        script_path=Path(script),
        cron_path=path,
        email=email,
        legacy=legacy,
        time_simple=time_simple,
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
    week_days: list[int] | None = None,
    month_days: list[int] | None = None,
    custom_expr: str | None = None,
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
            # I-3 (v0.6.1): bound K against the field range. Pre-fix, `*/200`
            # for minute (0-59) passed validation; cron then interpreted it
            # as "every 200 minutes" which never fires (rolls over hourly).
            if int(step_s) > (hi - lo + 1):
                return f"{name} step {step_s!r} exceeds field range ({hi - lo + 1})"
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
    # strict=True documents the invariant the regex above already
    # guarantees (exactly 5 fields; _CRON_FIELD_BOUNDS has 5 entries).
    # It cannot fire today — if someone adds a 6th bound without
    # touching the regex it fails loudly instead of silently
    # validating only the first five.
    for value, (name, lo, hi) in zip(fields, _CRON_FIELD_BOUNDS, strict=True):
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
