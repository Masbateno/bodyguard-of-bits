"""v0.43.0 (B-045) — the journals of what was done with BOB, one per domain.

Decided with the user (22 November 2026, evening): for follow-up, an action
leaves a trace whoever runs it, the team's master included — "outside the
declared perimeter" is marked on top, it does not replace the trace. One
journal per domain:

- ``team``  — the team declaration's changes, attempts outside a declared
  perimeter, actions with no login session (bob/team.py);
- ``cron``  — scheduled audits created, changed, removed; addresses added to or
  removed from the address book;
- ``admin`` — configuration (``--ignore``, ``--unignore``, ``--reconfigure``,
  ``--reset-baseline``, ``--test-email``, ``--test-webhook``,
  ``--install-completion``), reports deleted, and every change to what is
  recorded.

Kept even without a team, by default. What is recorded can be set per
category (``bob --journals``): ``cron``, ``carnet``, ``config``, ``rapports``.
Never switched off (decided): the team journal, and every change of these
settings — switching a journal off cannot be done silently.

Each journal is written like the journal of ``--fix --apply``
(bob/fix_journal.py, whose writer this uses): ``/var/log/bob/<name>.journal``,
root's, 0640 group adm, lines chained, append-only where the file system
allows it, each line also sent to the system log (``bob-<name>``). The same
limits: the digests are no signature; the witness makes a rewrite visible,
not impossible.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

from bob import fix_journal as FJ

#: name → file name and system-log tag.
CHANNELS: "dict[str, tuple[str, str]]" = {
    "team":  ("team.journal", "bob-team"),
    "cron":  ("cron.journal", "bob-cron"),
    "admin": ("admin.journal", "bob-admin"),
}
#: The categories one can switch off, and the journal each one writes to.
CATEGORIES: "dict[str, str]" = {
    "cron": "cron", "carnet": "cron", "config": "admin", "rapports": "admin",
}
#: Where the settings live (a seam for the tests).
SETTINGS = Path("/etc/bob/journals.conf")
_SETTINGS_UID = 0
_SETTINGS_MODE = 0o644
_HEADER = ("# BOB journals — what is recorded; written by `bob --journals`, not by hand\n"
           "# (a change by hand is seen and written to the admin journal).\n")


def _genesis(name: str) -> str:
    return FJ._digest(f"bob-{name}\0".encode())


def path(name: str) -> Path:
    return FJ.DIR / CHANNELS[name][0]


def witness_message(event: dict, digest: str) -> str:
    head = f"{event['kind']} id={event['id']} sha256={digest} body={FJ.body_digest(event)}"
    by = json.dumps(event.get("by", {}), sort_keys=True, separators=(",", ":"))
    rest = {k: v for k, v in event.items()
            if k not in ("kind", "id", "by", "v", "at", "host", "witness", "append_only", "prev")}
    return f"{head} by={by} " + json.dumps(rest, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False)[:1500]


def append(channel: str, kind: str, **data) -> dict:
    """Write one event to journal *channel*; raises FixJournalError / OSError."""
    event = {"kind": kind, "id": secrets.token_hex(6), **data}
    return FJ._append(event, name=CHANNELS[channel][0], genesis=_genesis(channel),
                      tag=CHANNELS[channel][1], describe=witness_message)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

@dataclass
class Event:
    number: int
    kind: str
    at: str
    who: dict
    data: dict


@dataclass
class Journal:
    name: str = ""
    events: "list[Event]" = field(default_factory=list)
    intact: bool = True
    broken_at: "int | None" = None
    unreadable: str = ""
    foreign_owner: str = ""


def parse(raw: str, name: str) -> Journal:
    journal = Journal(name=name)
    prev = _genesis(name)
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict) or event.get("prev") != prev:
            if journal.intact:
                journal.intact, journal.broken_at = False, number
            if not isinstance(event, dict):
                continue
        prev = FJ._digest(FJ._canonical(event))
        journal.events.append(Event(
            number=number, kind=str(event.get("kind", "")), at=str(event.get("at", "")),
            who=event.get("by") if isinstance(event.get("by"), dict) else {}, data=event))
    return journal


def load(name: str) -> Journal:
    """Journal *name* as it stands; absent is empty; unreadable says why (it
    is root's: an ordinary account cannot read it)."""
    from bob.annotations import _read_raw
    raw, why, uid = _read_raw(path(name), FJ.MAX_FILE)
    if raw is None:
        return Journal(name=name, intact=False, unreadable=why)
    journal = parse(raw, name)
    if raw and uid is not None and uid != FJ._JOURNAL_UID:
        journal.intact = False
        journal.foreign_owner = FJ._owner_name(uid)
    return journal


# ---------------------------------------------------------------------------
# What is recorded
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    off: "set[str]" = field(default_factory=set)
    digest: str = ""
    exists: bool = False
    unread_lines: "list[str]" = field(default_factory=list)
    foreign_owner: str = ""


def _digest_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def parse_settings(text: str) -> Settings:
    s = Settings(digest=_digest_text(text), exists=True)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cat, sep, value = (p.strip() for p in line.partition(":"))
        if not sep or cat not in CATEGORIES or value not in ("on", "off"):
            s.unread_lines.append(raw)
            continue
        if value == "off":
            s.off.add(cat)
    return s


def render_settings(off: "set[str]") -> str:
    return _HEADER + "".join(f"{c}: {'off' if c in off else 'on'}\n" for c in CATEGORIES)


def load_settings() -> Settings:
    """What is recorded. Absent: everything (the default). Unreadable: also
    everything — a setting not read never switches a journal off."""
    from bob.annotations import _read_raw
    raw, why, uid = _read_raw(SETTINGS, 64 << 10)
    if raw is None or (raw == "" and uid is None):
        return Settings(unread_lines=[f"({why})"] if raw is None else [])
    s = parse_settings(raw)
    if uid is not None and uid != _SETTINGS_UID:
        s.foreign_owner = FJ._owner_name(uid)
    return s


def write_settings(off: "set[str]") -> str:
    if os.geteuid() != _SETTINGS_UID:
        from bob.team import TeamError
        raise TeamError("needs_root")
    from bob._atomic import atomic_write
    text = render_settings(off)
    SETTINGS.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(SETTINGS, text, mode=_SETTINGS_MODE)
    return _digest_text(text)


def _say(text: str) -> None:
    print(text, file=sys.stderr)


def _t():
    from bob import i18n
    return i18n.t


def _write(channel: str, kind: str, say, **data) -> None:
    try:
        append(channel, kind, **data)
    except (FJ.FixJournalError, OSError) as exc:
        t = _t()
        reason = (t(f"fix_journal.err.{exc.key}", **exc.vars) if isinstance(exc, FJ.FixJournalError)
                  else (exc.strerror or type(exc).__name__))
        (say or _say)("  " + t("journals.not_recorded", path=str(path(channel)), reason=reason))


def _settings_checked(say) -> Settings:
    """The settings, and — written once — a settings file BOB did not write."""
    s = load_settings()
    if not s.exists:
        return s
    journal = load("admin")
    if journal.unreadable:
        return s
    last = next((e.data.get("digest") for e in reversed(journal.events) if e.kind == "journals"), None)
    if last == s.digest and not s.foreign_owner:
        return s
    (say or _say)("  " + _t()("journals.altered", path=str(SETTINGS)))
    if not any(e.kind == "journals_altered" and e.data.get("digest") == s.digest for e in journal.events):
        _write("admin", "journals_altered", say, digest=s.digest)
    return s


def record(category: str, kind: str, *, say=None, **data) -> None:
    """Write *kind* to the journal of *category* unless that category is
    switched off. Never raises: a trace that cannot be written is said."""
    if category in _settings_checked(say).off:
        return
    _write(CATEGORIES[category], kind, say, category=category, **data)


def set_categories(cats: "list[str]", on: bool, t, *, ask=None, say=None) -> "list[str]":
    """``sudo bob --journals on|off CAT[,CAT]``: always written (decided)."""
    from bob import team
    unknown = [c for c in cats if c not in CATEGORIES]
    if unknown or not cats:
        raise team.TeamError("journals_unknown", category=", ".join(unknown) or "—",
                             known=", ".join(CATEGORIES))
    if os.geteuid() != _SETTINGS_UID:
        raise team.TeamError("needs_root")
    if not team.gate("equipe", "journals", t, ask=ask, say=say):
        return []
    current = _settings_checked(say).off
    off = (current - set(cats)) if on else (current | set(cats))
    digest = write_settings(off)
    _write("admin", "journals", say, categories=sorted(cats), state="on" if on else "off",
           off=sorted(off), digest=digest)
    return [t("journals.done", categories=", ".join(cats), state=t("journals.state_on") if on else t("journals.state_off"))]


def size_text(name: str, t) -> str:
    """How large journal *name* is, and how far BOB reads one (v0.43.0, asked
    by the user): a journal past that bound is said too large, never read in
    part. Absent and unreadable are said apart."""
    return file_size_text(path(name), t)


def file_size_text(file: Path, t) -> str:
    """The same for any journal file — the journal of --fix --apply too."""
    from bob.manage_logs import _format_size
    try:
        size = file.stat().st_size
    except FileNotFoundError:
        return t("journals.size_absent")
    except OSError:
        return t("journals.size_unknown")
    return t("journals.size", size=_format_size(size, t), limit=_format_size(FJ.MAX_FILE, t))


def state_rows(t) -> "list[tuple[str, str]]":
    """One row per journal — its chain's state, then its size in one column
    (CONVENTIONS.md: columns line up) — with the row's kind for a screen."""
    states = []
    for name in CHANNELS:
        j = load(name)
        if j.unreadable:
            state, kind = t("journals.state_unreadable", name=name, reason=j.unreadable), "warn"
        elif j.intact and not j.foreign_owner:
            state, kind = t("journals.state_intact", name=name, count=len(j.events)), ("ok" if j.events else "body")
        else:
            state, kind = t("journals.state_broken", name=name, line=j.broken_at or 0), "alert"
        states.append((state.rstrip("."), kind, name))
    width = max(len(s) for s, _k, _n in states)
    return [(f"{s:<{width}} — {size_text(n, t)}", k) for s, k, n in states]


def show(t) -> "list[str]":
    """``bob --journals``: what is recorded, and each journal's state."""
    s = load_settings()
    lines = [t("journals.header", path=str(SETTINGS)), ""]
    # v0.43.0 — columns aligned on the longest of each (CONVENTIONS.md): the
    # French "NON enregistré" overran a fixed width of 12.
    states = {cat: t("journals.state_off") if cat in s.off else t("journals.state_on") for cat in CATEGORIES}
    cat_w = max(len(c) for c in CATEGORIES)
    state_w = max(len(x) for x in states.values())
    always = t("journals.always")
    lead_w = max(cat_w + 1 + state_w, len(always))
    for cat, name in CATEGORIES.items():
        lines.append(f"  {f'{cat:<{cat_w}} {states[cat]}':<{lead_w}} → {path(name)}")
    lines.append(f"  {always:<{lead_w}} → {path('team')}")
    if s.unread_lines:
        lines += ["", t("journals.unread_lines", count=len(s.unread_lines))]
    lines.append("")
    lines += [text for text, _kind in state_rows(t)]
    return lines


#: v0.43.0 — the tone of each action (asked by the user, 23 November 2026):
#: green adds or turns on, red removes, turns off or alarms, yellow the rest.
_OP_TONE = {"init": "good", "grant": "good", "revoke": "bad", "remove": "bad",
            "unignore": "good", "ignore": "bad", "reset_baseline": "bad",
            "on": "good", "off": "bad"}
_KIND_TONE = {"cron_created": "good", "address_added": "good",
              "cron_removed": "bad", "address_removed": "bad", "report_deleted": "bad",
              "journals_altered": "bad", "altered": "bad",
              "cron_schedule": "neutral", "cron_email": "neutral"}
#: v0.43.0 (user, 23 November 2026) — the journal's columns line up: the team's
#: action word padded to the longest one (revoke, remove), the account to a
#: fixed width, the configuration's action word to the longest one. The
#: padding is outside the colour.
_TEAM_OP_WIDTH = max(len(op) for op in ("init", "grant", "revoke", "remove"))
_ACCOUNT_WIDTH = 12
_CONFIG_OP_WIDTH = max(len(op) for op in ("ignore", "unignore", "reconfigure", "reset_baseline",
                                          "test_email", "test_webhook", "install_completion"))


def _padded(word: str, kind: str, width: int) -> str:
    from bob import _names
    return _names.tone(word, kind) + " " * max(0, width - len(word))


_OUTCOME_TONE = {"confirmed": "bad", "unconfirmed": "bad", "abandoned": "neutral",
                 "unattributed": "neutral"}


def _lead(text: str, kind: str) -> str:
    """*text* with its action — the part before " — ", else all of it — in *kind*'s tone."""
    from bob import _names
    head, sep, rest = text.partition(" — ")
    return _names.tone(head, kind) + sep + rest


def event_text(event: Event, t) -> str:
    """One event, said in the reader's language, its action term in the
    colour of its effect (bob/_names.py)."""
    from bob import _names
    d = event.data
    k = event.kind
    if k == "attempt":
        outcome = d.get("outcome") if d.get("outcome") in ("confirmed", "abandoned", "unconfirmed",
                                                           "unattributed") else "unconfirmed"
        return _lead(t(_ATTEMPT_KEYS[outcome], action=t(f"team.action.{d.get('action', '')}"),
                       attribute=str(d.get("attribute", ""))), _OUTCOME_TONE[outcome])
    if k == "team":
        op = str(d.get("op", ""))
        return t("team.journal.team", op=_padded(op, _OP_TONE.get(op, "neutral"), _TEAM_OP_WIDTH),
                 account=_names.cell(str(d.get("account", "")), _ACCOUNT_WIDTH),
                 attributes=", ".join(d.get("attributes") or []) or "—")
    if k == "altered":
        return _lead(t("team.journal.altered"), "bad")
    if k in ("config", "journals"):
        fields = {f: str(d.get(f, "")) for f in _EVENT_FIELDS}
        word = "op" if k == "config" else "state"
        width = _CONFIG_OP_WIDTH if k == "config" else 0
        fields[word] = _padded(fields[word], _OP_TONE.get(fields[word], "neutral"), width)
        return t(_EVENT_KEYS[k], **fields)
    if k in _EVENT_KEYS:
        return _lead(t(_EVENT_KEYS[k], **{f: str(d.get(f, "")) for f in _EVENT_FIELDS}),
                     _KIND_TONE.get(k, "neutral"))
    return k


_ATTEMPT_KEYS = {
    "confirmed": "team.journal.attempt_confirmed",
    "abandoned": "team.journal.attempt_abandoned",
    "unconfirmed": "team.journal.attempt_unconfirmed",
    "unattributed": "team.journal.attempt_unattributed",
}
_EVENT_KEYS = {
    "cron_created": "journals.ev.cron_created",
    "cron_schedule": "journals.ev.cron_schedule",
    "cron_email": "journals.ev.cron_email",
    "cron_removed": "journals.ev.cron_removed",
    "address_added": "journals.ev.address_added",
    "address_removed": "journals.ev.address_removed",
    "config": "journals.ev.config",
    "report_deleted": "journals.ev.report_deleted",
    "journals": "journals.ev.journals",
    "journals_altered": "journals.ev.journals_altered",
}
_EVENT_FIELDS = ("name", "schedule", "email", "address", "op", "value", "path",
                 "categories", "state")


def cron_origin(entry, t, journal: "Journal | None" = None) -> str:
    """When and by whom a scheduled audit was created (v0.43.0, asked by the
    user): from the cron journal when it holds the creation — the trace —
    else from the job's header ("created" line, then the "generated" date),
    said as the file's. The account is marked (bob/_names.py)."""
    from bob import _names
    from bob._python_support import display_date
    from bob.annotations import who_label
    from bob.fixlog import _lang, clock
    journal = journal if journal is not None else load("cron")
    found = None
    for ev in journal.events:
        if ev.kind == "cron_created" and ev.data.get("name") == entry.name:
            found = ev
    lang = _lang(t)
    if found is not None:
        return t("manage_cron.origin", date=display_date(found.at[:10], lang), time=clock(found.at)[:5],
                 who=_names.mark(who_label(found.who) if found.who else "?"))
    if entry.created_at:
        return t("manage_cron.origin_file", date=display_date(entry.created_at[:10], lang),
                 time=clock(entry.created_at)[:5], who=_names.mark(entry.created_by or "?"))
    if entry.generated:
        return t("manage_cron.origin_date_only", date=display_date(entry.generated[:10], lang))
    return t("manage_cron.origin_unknown")


def address_origin(address: str, t, journal: "Journal | None" = None) -> str:
    """When and by whom *address* was added to the address book (v0.43.0, asked
    by the user): the last addition the cron journal holds. The book's file
    keeps the addresses only; an address added before 0.43.0, or while the
    ``carnet`` category was off, says so. The account is marked."""
    from bob import _names
    from bob._python_support import display_date
    from bob.annotations import who_label
    from bob.fixlog import _lang, clock
    journal = journal if journal is not None else load("cron")
    found = None
    for ev in journal.events:
        if ev.kind == "address_added" and ev.data.get("address") == address:
            found = ev
    if found is None:
        return t("manage_cron.address_origin_unknown")
    return t("manage_cron.address_origin", date=display_date(found.at[:10], _lang(t)),
             time=clock(found.at)[:5], who=_names.mark(who_label(found.who) if found.who else "?"))


def journal_lines(name: str, t) -> "tuple[list[str], int]":
    """A journal in text, its chain's verdict first: 0 intact, 2 broken, 4 unreadable."""
    from bob import _names
    from bob.annotations import who_label
    journal = load(name)
    if journal.unreadable:
        return [t("journals.unreadable", path=str(path(name)), reason=journal.unreadable)], 4
    lines = []
    if journal.foreign_owner:
        lines.append(t("journals.foreign_owner", path=str(path(name)), owner=journal.foreign_owner))
    lines.append((t("journals.state_intact", name=name, count=len(journal.events)) if journal.intact
                  else t("journals.state_broken", name=name, line=journal.broken_at or 0)).rstrip(".")
                 + " — " + size_text(name, t))
    lines.append("")
    # v0.43.0 (user, 23 November 2026) — the columns line up, as everywhere in
    # BOB (CONVENTIONS.md): the author padded to the longest author of this
    # journal, the action — the part before " — " — to its longest action, so
    # every detail starts in one column. Widths are measured on the visible
    # text, the marks left out.
    rows = [(who_label(ev.who) if ev.who else "?", event_text(ev, t), ev) for ev in journal.events]
    who_w = max((len(w) for w, _x, _e in rows), default=0)
    heads = [_names.plain(text).partition(" — ") for _w, text, _e in rows]
    head_w = max((len(h) for h, sep, _r in heads if sep), default=0)
    for (who, text, ev), (head, sep, _rest) in zip(rows, heads, strict=True):
        if sep:
            marked_head, _s, marked_rest = text.partition(" — ")
            text = marked_head + " " * (head_w - len(head)) + " — " + marked_rest
        lines.append(f"  {ev.number:>4}  {ev.at}  {_names.cell(who, who_w)}  {text}")
    return lines, (0 if journal.intact and not journal.foreign_owner else 2)


def run(args: "list[str]", t) -> int:
    """``bob --journals [on|off CAT[,CAT] | show NAME]``."""
    from bob import team
    try:
        if not args:
            lines, code = show(t), 0
        elif args[0] in ("on", "off") and len(args) >= 2:
            cats = [c.strip() for a in args[1:] for c in a.split(",") if c.strip()]
            lines, code = set_categories(cats, args[0] == "on", t), 0
        elif args[0] == "show" and len(args) == 2 and args[1] in CHANNELS:
            lines, code = journal_lines(args[1], t)
        else:
            raise team.TeamError("journals_usage")
    except team.TeamError as exc:
        print(t(f"team.err.{exc.key}", **exc.vars), file=sys.stderr)
        return 3
    from bob import _names
    for line in lines:
        print(_names.plain(line))          # the screen's name marks, not printed
    return code
