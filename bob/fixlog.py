"""v0.40.0 — the journal of ``--fix --apply`` in words (B-031).

One rendering, read by the ``--manage-logs`` screens and by
``bob --fix-journal``: what the journal holds, day by day and command by
command, and above all whether it is the journal BOB wrote. Decided with the
user (20 November 2026): a falsification must be "shown explicitly, or at
least be easy to demonstrate" — so the verdict comes first, in its own colour,
and every claim it makes points at what proves it: the line number, the
journal line against its witness in the system log.

Every line is ``(text, kind)``: ``alert`` (a falsification shown), ``warn``
(something not demonstrated, or a protection missing), ``ok``, ``body``.
"""

from __future__ import annotations

from datetime import datetime

from bob import _names
from bob import fix_journal as FJ
from bob import fix_witness as W

#: An entry's outcome, as a mark and a locale key under ``fixlog.status.``.
_MARK = {"ok": "✔", "failed": "✖", "timeout": "⚠", "unconfirmed": "⚠", FJ.STARTED: "?"}
#: What an entry's witness says of it, under ``fixlog.proof.``: the kinds that
#: show a falsification, then those that only fail to demonstrate.
_ALERTS = ("differs", "conflicting", "rechained")
_WARNS = ("not_shown",)


def _lang(t) -> str:
    from bob import i18n
    return "fr" if i18n.current_lang() == "fr" else "en"


def when(at: str, t) -> str:
    """A time in the reader's local time and the locale's format."""
    try:
        return datetime.fromisoformat(at).astimezone().strftime(t("manage_logs.note_date_fmt"))
    except (TypeError, ValueError):
        return at or "?"


def clock(at: str) -> str:
    try:
        return datetime.fromisoformat(at).astimezone().strftime("%H:%M:%S")
    except (TypeError, ValueError):
        return "??:??:??"


def day_label(day: str, t) -> str:
    """``jeudi 20 novembre 2026`` / ``Thursday 2026-11-20``."""
    from bob._python_support import display_date
    try:
        weekday = t(f"fixlog.weekday.{datetime.fromisoformat(day).weekday()}")
    except ValueError:
        return day
    return f"{weekday} {display_date(day, _lang(t))}"


def who(entry_who: dict) -> str:
    """The operator, marked as an account name (v0.43.0, bob/_names.py)."""
    from bob import _names
    return _names.mark(who_plain(entry_who))


def who_plain(entry_who: dict) -> str:
    from bob.annotations import who_label
    return who_label(entry_who if isinstance(entry_who, dict) else {})


def status_text(entry: "FJ.Entry", t) -> str:
    return f"{_MARK.get(entry.status, '?')} {t('fixlog.status.' + entry.status)}"


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------

def verdict_lines(verdict: "W.Verdict", journal: "FJ.Journal", t) -> "list[tuple[str, str]]":
    """The verdict first, then each finding behind it, then what vouches for
    the journal and what does not (witness, append-only, sealing)."""
    out: "list[tuple[str, str]]" = []
    if journal.unreadable is not None:
        why = journal.unreadable
        if why in ("link", "denied", "not_regular", "too_large"):
            why = t(f"fixlog.unreadable.{why}")
        out.append((t("fixlog.verdict.unreadable", path=FJ.path(), reason=why), "warn"))
        return out
    witnessed = [ln for ln in journal.seen if ln.witness == "syslog"]
    if verdict.overall == "tampered":
        out.append((t("fixlog.verdict.tampered"), "alert"))
    elif verdict.overall == "unproven":
        out.append((t("fixlog.verdict.unproven"), "warn"))
    elif journal.seen and not witnessed:
        out.append((t("fixlog.verdict.chain_only"), "ok"))
    elif journal.seen and not verdict.confirmed:
        # Measured on the test Mint (20 November 2026), journald rotated and
        # vacuumed: "INTACT — … 0 line(s) match their witness" read as
        # confirmed when nothing had been held against a witness at all.
        out.append((t("fixlog.verdict.chain_only_unwitnessed"), "ok"))
    elif journal.seen:
        out.append((t("fixlog.verdict.intact", count=len(verdict.confirmed)), "ok"))
    elif not verdict.removed:
        out.append((t("fixlog.verdict.empty"), "info"))
    if verdict.foreign_owner:
        out.append(("  " + t("fixlog.finding.foreign_owner", owner=verdict.foreign_owner), "alert"))
    if verdict.chain_broken_at:
        # v0.44.0 (B-050) — with archives, the file it breaks in.
        line = FJ.line_label(journal.files, verdict.chain_broken_at, t)
        out.append(("  " + t("fixlog.finding.chain", line=line), "alert"))
    if verdict.differs:
        out.append(("  " + t("fixlog.finding.differs", count=len(verdict.differs)), "alert"))
    if verdict.conflicting:
        out.append(("  " + t("fixlog.finding.conflicting", count=len(verdict.conflicting)), "alert"))
    if verdict.rechained:
        out.append(("  " + t("fixlog.finding.rechained", count=len(verdict.rechained)), "alert"))
    if verdict.removed:
        out.append(("  " + t("fixlog.finding.removed", count=len(verdict.removed)), "alert"))
    if verdict.not_shown:
        out.append(("  " + t("fixlog.finding.not_shown", count=len(verdict.not_shown)), "warn"))
    if verdict.append_only_removed:
        out.append(("  " + t("fixlog.finding.append_only_removed"), "warn"))
    if verdict.witness_gone:
        out.append(("  " + t("fixlog.finding.witness_gone", count=len(verdict.witness_gone)), "info"))
    no_witness = len(verdict.no_witness)
    if no_witness:
        out.append(("  " + t("fixlog.finding.no_witness", count=no_witness), "info"))
    out.extend(_guards(verdict, journal, t))
    if journal.skipped:                       # v0.44.0 (B-050) — archives beyond the read budget
        out.append(("  " + t("journals.skipped", count=journal.skipped,
                             budget=_size(FJ.CHAIN_BUDGET, t)), "info"))
    return out


def _size(size: int, t) -> str:
    from bob.manage_logs import _format_size
    return _format_size(size, t)


def _guards(verdict: "W.Verdict", journal: "FJ.Journal", t) -> "list[tuple[str, str]]":
    """What vouches for the journal, each said as it stands."""
    out: "list[tuple[str, str]]" = []
    witness = verdict.witness
    state = witness.state if witness else "failed"
    detail = (witness.detail if witness else "") or ""
    # v0.44.0 (the user, 27 November 2026) — each line in the colour of what
    # it says (CONVENTIONS.md): a guard in place green, one missing yellow,
    # what only informs cyan; the commands in violet.
    kind = "ok" if state == "ok" else "warn"
    out.append(("  " + t(f"fixlog.witness.{state}", detail=detail), kind))
    if witness and witness.persistent is False:
        out.append(("  " + t("fixlog.witness.volatile"), "warn"))
    if witness and witness.sealed is not None:
        text = t("fixlog.sealed.yes" if witness.sealed else "fixlog.sealed.no")
        text = _names.verbatim_in(text, "journalctl --setup-keys", "journalctl --verify")
        out.append(("  " + text, "ok" if witness.sealed else "warn"))
    if journal.seen:
        if verdict.append_only_now is True:
            out.append(("  " + t("fixlog.append_only.set"), "ok"))
        elif not verdict.append_only_removed:
            last = journal.seen[-1].append_only
            key = "fixlog.append_only.unavailable" if last is False else "fixlog.append_only.unknown"
            out.append(("  " + t(key), "warn"))
    return out


# ---------------------------------------------------------------------------
# Days, entries, one entry
# ---------------------------------------------------------------------------

def entry_proof(entry: "FJ.Entry", verdict: "W.Verdict") -> str:
    return verdict.of_entry(entry)


def proof_kind(proof: str) -> str:
    if proof in _ALERTS:
        return "alert"
    if proof in _WARNS:
        return "warn"
    return "body"


def day_row(day: str, entries: "list[FJ.Entry]", verdict: "W.Verdict", t) -> "tuple[str, str]":
    """One line of the list of days: the date, how many commands and what
    came of them; marked when an entry of the day is shown falsified."""
    applied = sum(1 for e in entries if e.status == "ok")
    failed = sum(1 for e in entries if e.status == "failed")
    other = len(entries) - applied - failed
    text = t("fixlog.day_row", day=day_label(day, t), count=len(entries), applied=applied,
             failed=failed, other=other)
    proofs = {entry_proof(e, verdict) for e in entries}
    if proofs & set(_ALERTS):
        return text + "   " + t("fixlog.day_tampered"), "alert"
    if proofs & set(_WARNS):
        return text + "   " + t("fixlog.day_unproven"), "warn"
    return text, "body"


def entry_row(entry: "FJ.Entry", verdict: "W.Verdict", t, width: int = 200) -> "tuple[str, str]":
    proof = entry_proof(entry, verdict)
    tag = f"  [{t('fixlog.proof.' + proof)}]" if proof_kind(proof) != "body" else ""
    short = f"{_MARK.get(entry.status, '?')} {t('fixlog.short.' + entry.status)}"
    from bob import _names
    # v0.43.0 (user, 23 November 2026) — the list row follows the conventions
    # (CONVENTIONS.md): the status in the colour of its effect, the operator in
    # the accounts' colour, the command in violet like in its detail.
    tone = {"ok": "good", "failed": "bad"}.get(entry.status, "neutral")
    # The status column as wide as the longest status in this language: the
    # French "⚠ non confirmée" ran into the operator's name (CONVENTIONS.md).
    status_w = max(len(f"{_MARK.get(st, '?')} {t('fixlog.short.' + st)}") for st in FJ.STATUSES + (FJ.STARTED,))
    head = (f"{clock(entry.at)}  {_names.tone(short, tone)}{' ' * max(0, status_w - len(short))} "
            f"{_names.cell(who_plain(entry.who), 16)} ")
    command = " ".join(entry.command.split())
    room = max(10, width - len(_names.plain(head)) - len(tag) - 1)
    if len(command) > room:
        command = command[:room - 1] + "…"
    return head + _names.tone(command, "verbatim") + tag, proof_kind(proof)


def entry_detail(entry: "FJ.Entry", verdict: "W.Verdict", t) -> "list[tuple[str, str]]":
    """Everything an entry holds, then what its witness says of it, then its
    notes (added, never edited)."""
    proof = entry_proof(entry, verdict)
    out = [
        (t("fixlog.detail.when", date=when(entry.at, t)), "body"),
        (t("fixlog.detail.who", who=who(entry.who)), "body"),
        (t("fixlog.detail.finding", finding=entry.finding or "?", message=entry.message), "body"),
        (t("fixlog.detail.command"), "body"),
        ("    " + entry.command, "verbatim"),
    ]
    if entry.how == "native" and entry.action:
        import json
        out.append((t("fixlog.detail.native", action=json.dumps(entry.action, sort_keys=True,
                                                                 ensure_ascii=False)), "body"))
    status_kind = "ok" if entry.status == "ok" else ("warn" if entry.status != "failed" else "alert")
    out.append((t("fixlog.detail.status", status=status_text(entry, t)), status_kind))
    if entry.status != FJ.STARTED:
        out.append((t("fixlog.detail.rc", rc="—" if entry.rc is None else entry.rc,
                      seconds="?" if entry.seconds is None else entry.seconds,
                      ended=when(entry.ended, t)), "body"))
    else:
        out.append((t("fixlog.detail.interrupted"), "warn"))
    if entry.error:
        out.append((t("fixlog.detail.error"), "body"))
        out.append(("    " + entry.error, "verbatim"))
    out.append((t("fixlog.proof_detail." + proof), proof_kind(proof) if proof != "confirmed" else "ok"))
    out.extend(_witnessed(entry, verdict, t))
    out.append(("", "body"))
    if entry.notes:
        out.append((t("fixlog.detail.notes", count=len(entry.notes)), "body"))
        for note in entry.notes:
            out.append(("  " + t("fixlog.detail.note", date=when(note.at, t), who=who(note.who),
                                 text=note.text), "body"))
    else:
        out.append((t("fixlog.detail.no_notes"), "body"))
    return out


def _witnessed(entry: "FJ.Entry", verdict: "W.Verdict", t) -> "list[tuple[str, str]]":
    """The demonstration, for an entry the witness contradicts: what the
    system log recorded when each of its lines was written, beside what the
    journal says now."""
    if entry_proof(entry, verdict) not in _ALERTS or verdict.witness is None:
        return []
    out = [(t("fixlog.detail.witnessed"), "body")]
    for item in verdict.witness.items:
        # Only the lines the witness contradicts: measured on the test Mint
        # (20 November 2026), a note reattributed under an entry printed the
        # entry's two untouched lines too, and the reader had to find the one.
        if item.id in entry.lines and verdict.of(item.id) in _ALERTS:
            stamp = item.at.astimezone().strftime(t("manage_logs.note_date_fmt")) if item.at else "?"
            out.append((f"    {stamp}  {item.message}", "verbatim"))
    return out


def removed_lines(verdict: "W.Verdict", t) -> "list[tuple[str, str]]":
    """The proof of what was cut: each line the system log holds and the
    journal no longer does, as journald recorded it."""
    out = []
    for item in verdict.removed:
        stamp = item.at.astimezone().strftime(t("manage_logs.note_date_fmt")) if item.at else "?"
        out.append((f"{stamp}  {item.message}", "verbatim"))
    return out


# ---------------------------------------------------------------------------
# bob --fix-journal
# ---------------------------------------------------------------------------

def text_report(t) -> "tuple[list[tuple[str, str]], str]":
    """The whole journal as text, and its verdict (``tampered``,
    ``unproven``, ``intact``)."""
    journal = FJ.load()
    verdict = W.verify(journal)
    from bob.journals import file_size_text
    out = [(t("fixlog.title", path=FJ.path()), "body"), ("", "body")]
    out.extend(verdict_lines(verdict, journal, t))
    out.append((file_size_text(FJ.path(), t), "body"))      # v0.43.0 — its size, after the verdict
    for day, entries in FJ.days(journal):
        out.append(("", "body"))
        out.append(day_row(day, entries, verdict, t))
        for entry in entries:
            text, kind = entry_row(entry, verdict, t)
            out.append(("  " + text, kind))
            # The proof in the text too, copiable into a ticket: what the
            # system log recorded for an entry the witness contradicts.
            out.extend(("    " + line.strip(), line_kind) for line, line_kind in _witnessed(entry, verdict, t))
            for note in entry.notes:
                out.append(("      " + t("fixlog.detail.note", date=when(note.at, t), who=who(note.who),
                                         text=note.text), "body"))
    if verdict.removed:
        out.append(("", "body"))
        out.append((t("fixlog.removed_title", count=len(verdict.removed)), "alert"))
        out.extend(("  " + text, kind) for text, kind in removed_lines(verdict, t))
    if journal.unreadable is not None and verdict.overall == "intact":
        return out, "unproven"
    return out, verdict.overall
