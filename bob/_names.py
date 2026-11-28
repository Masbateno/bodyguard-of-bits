"""v0.43.0 — account names and action terms marked in text, so a full screen
can colour them.

Asked by the user (22 and 23 November 2026): in every wizard, account names
in colour; in the journals, the term that says what was done in the colour of
its effect — green for what adds or turns on, red for what removes, turns off
or alarms, yellow for the rest. A marked piece opens with one control
character (SO for a name, DC1/DC2/DC3 for a tone) and closes with SI; no
account name or journal value can hold them. The shared drawer
(bob/tui/fixlog.put_marked) draws each piece in its colour; every text output
strips them (``plain``) — a terminal, a file or a pipe never receives them.
"""

from __future__ import annotations

OPEN = "\x0e"
CLOSE = "\x0f"
GOOD = "\x11"
BAD = "\x12"
NEUTRAL = "\x13"
#: v0.43.0 — material to reproduce exactly (a command), in the violet of
#: VERBATIM, inside a line drawn in another colour.
VERBATIM = "\x14"
_KINDS = {OPEN: "name", GOOD: "good", BAD: "bad", NEUTRAL: "neutral", VERBATIM: "verbatim"}
_TONE_OPEN = {"good": GOOD, "bad": BAD, "neutral": NEUTRAL, "verbatim": VERBATIM}


def mark(name: str) -> str:
    """*name*, marked as an account name."""
    return f"{OPEN}{name}{CLOSE}"


def tone(text: str, kind: str) -> str:
    """*text* marked with the tone *kind* (good, bad, neutral)."""
    return f"{_TONE_OPEN[kind]}{text}{CLOSE}" if kind in _TONE_OPEN else text


def verbatim_in(text: str, *commands: str) -> str:
    """*text* with each of *commands* it holds marked as material to reproduce
    exactly (violet). v0.44.0 (the user, 27 November 2026): the information
    lines of the wizards in colour, as CONVENTIONS.md says, commands included."""
    for command in commands:
        text = text.replace(command, tone(command, "verbatim"))
    return text


def cell(name: str, width: int) -> str:
    """*name* marked, padded to *width* visible columns."""
    return mark(name) + " " * max(0, width - len(name))


def plain(text: str) -> str:
    """*text* without the marks, for any output that is not a full screen."""
    for ch in (OPEN, CLOSE, GOOD, BAD, NEUTRAL, VERBATIM):
        text = text.replace(ch, "")
    return text


def segments(text: str) -> "list[tuple[str, str | None]]":
    """*text* cut into (piece, kind) pairs: kind is "name", "good", "bad",
    "neutral", or None for plain text. A CLOSE with no opening (a piece cut
    by wrapping) is dropped, never drawn."""
    out: "list[tuple[str, str | None]]" = []
    buf, kind = "", None
    for ch in text:
        if ch in _KINDS:
            if buf:
                out.append((buf, kind))
            buf, kind = "", _KINDS[ch]
        elif ch == CLOSE:
            if buf:
                out.append((buf, kind))
            buf, kind = "", None
        else:
            buf += ch
    if buf:
        out.append((buf, kind))
    return out
