"""v0.43.0 (B-045) — the team journal: the team declaration's changes, attempts
outside a declared perimeter, actions with no login session.

One of the journals of bob/journals.py (``team``), never switched off
(decided with the user, 22 November 2026). Within a perimeter, an action is
traced in the journal of its own domain (cron, admin), not here.
"""

from __future__ import annotations

from bob import journals as J

NAME = J.CHANNELS["team"][0]
WITNESS_TAG = J.CHANNELS["team"][1]
_GENESIS = J._genesis("team")
#: What came of an attempt outside the declared perimeter.
OUTCOMES = ("confirmed", "abandoned", "unconfirmed", "unattributed")

Event = J.Event
TeamJournal = J.Journal


def path():
    return J.path("team")


def append(kind: str, **data) -> dict:
    """Write one event; raises FixJournalError / OSError when it cannot."""
    return J.append("team", kind, **data)


def parse(raw: str) -> TeamJournal:
    return J.parse(raw, "team")


def load() -> TeamJournal:
    return J.load("team")


def last_declaration_digest(journal: TeamJournal) -> "str | None":
    """The digest of the declaration as BOB last wrote it, per the journal."""
    for event in reversed(journal.events):
        if event.kind == "team" and isinstance(event.data.get("digest"), str):
            return event.data["digest"]
    return None


def altered_already_recorded(journal: TeamJournal, digest: str) -> bool:
    return any(e.kind == "altered" and e.data.get("digest") == digest for e in journal.events)
