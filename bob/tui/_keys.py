"""The one key contract every BOB curses screen obeys.

Before v0.16.3 each wizard invented its own. `--explain` navigated with the
arrows alone, `--manage-logs` added PgUp/PgDn, the cron screens added `j`/`k`
and none of them had `g`/`G`; `Esc` went back in some screens and did nothing
in others; and the line telling the operator which keys exist was translated in
one wizard and hardcoded English in the other two — the class v0.15.3 closed
for `--help`, still open on every interactive screen.

They also disagreed about *where* to say it: `--manage-logs` and `--explain`
merged the title and the hints into the top banner, the cron wizards kept a
title on row 0 and a hint line on the last row.

So: one navigation floor on every screen that shows a list, one meaning per
key, one translated footer composed from the actions a screen declares — the
line and the bindings cannot drift apart, because a screen declares its actions
once and both are derived from that.

Modelled on ``bob/tui/_palette.py``, and for the same reason: the previous
arrangement was three copies that happened to agree, which is how the palette
defect stayed uniform and invisible.

This module never imports curses: the constants are resolved against a
module handed in by the caller. ``bob-core`` ships without ``bob-tui``
and must still import, and two non-TUI modules import this one at top
level on the strength of that. tests/test_v0164_headless_import.py
holds it.
"""

from __future__ import annotations

# --- actions ---------------------------------------------------------------
# The value is the locale suffix under ``tui.keys.``.
MOVE     = "move"       #: ↑↓ / j k
PAGE     = "page"       #: PgUp / PgDn
EDGE     = "edge"       #: g / G
SELECT   = "select"     #: Enter
BACK     = "back"       #: Esc
QUIT     = "quit"       #: q
TOGGLE   = "toggle"     #: Space
ALL      = "all"        #: a
UNMARK   = "unmark"     #: u
DELETE   = "delete"     #: d
CHANGE   = "change"     #: c
SUMMARY  = "summary"    #: s — switch to the condensed view
FULL     = "full"       #: s — switch back to the whole log
CONFIRM  = "confirm"    #: y
NEW      = "new"        #: n
CREATE   = "create"     #: Enter, on a landing screen
SUBMIT   = "submit"     #: Enter, on a text-input screen
LANG     = "lang"       #: l — switch the interface language, landing screens only
BOOK     = "book"       #: m — open the email address book
#: v0.39.0 — the report preview's detached blocks and its notes.
NOTES    = "notes"      #: n — show/hide the notes block
ANNOTATE = "annotate"   #: a — manage the notes (add, edit, withdraw, purge)
COMPARE  = "compare"    #: c — show/hide the comparison with the previous report
HISTORY  = "history"    #: h — show/hide the history of this host's reports
NUMBERS  = "numbers"    #: # — show/hide line numbers
NOTE_ADD = "note_add"   #: a — add a note
NOTE_EDIT = "note_edit"  #: e — edit a note
NOTE_WITHDRAW = "note_withdraw"  #: r — withdraw a note
NOTE_PURGE = "note_purge"  #: p — purge a note's text
NOTE_JOURNAL = "note_journal"  #: v — show/hide every action on the notes
#: ← → — the neighbouring entry of the list a nested view was opened from,
#: without going back to it (v0.32.0, the --manage-logs preview: ← older log,
#: → newer). Arrows only: h/l would pair with jk but ``l`` is LANG, ``n``/``p``
#: collide with NEW, and ``[``/``]`` need AltGr on an AZERTY keyboard. PAGE is
#: the precedent for an action bound to special keys alone.
PEER     = "peer"
#: v0.39.0 — Tab in a text field that completes a path.
COMPLETE = "complete"
#: v0.40.0 — r, on the journal of --fix --apply: the lines the system log
#: holds and the journal no longer does (the proof of a cut).
REMOVED  = "removed"
#: v0.40.0 (B-032) — b, in the report preview: show/hide the computation of
#: the score, as --breakdown prints it.
BREAKDOWN = "breakdown"
EXPAND = "expand"       #: t — every block of the preview at once (v0.43.0)
CEILING = "ceiling"     #: p — the reports' size ceiling (v0.43.0)
#: v0.39.0 (user, 19 November 2026: the keys a screen accepts are exactly the
#: keys it announces) — a numbered menu's digits, announced with the menu's own
#: range: ``pick(4)`` is drawn "1-4" and binds 1 to 4, never 5. The digits were
#: accepted and never announced.
_PICK = "pick:"


def pick(count: int) -> str:
    """The action choosing one of *count* numbered entries by its digit."""
    return f"{_PICK}{max(1, min(9, count))}"


def _pick_count(action: str) -> int:
    return int(action[len(_PICK):]) if action.startswith(_PICK) else 0

#: Every screen that renders a list gets these three, in this order. A screen
#: that scrolls but cannot page is a screen whose behaviour depends on which
#: wizard the operator happens to be in.
NAVIGATION = (MOVE, PAGE, EDGE)

#: ``q`` quits, and only from a wizard's first screen. Deeper in, ``Esc`` goes
#: back one step and nothing leaves outright: a single keystroke should not
#: abandon a half-entered cron job from three screens down. So a landing screen
#: declares QUIT and not BACK — it has nowhere to go back to — and every screen
#: below it declares BACK and not QUIT.
LANDING_EXIT = (LANG, QUIT)
NESTED_EXIT  = (BACK,)

#: ``tui.keys.lang`` deliberately holds the name of the *other* language, in
#: that language: en.json says "Français", fr.json says "English". Read in the
#: current locale it therefore names the language ``l`` switches *to*, which is
#: what an operator needs to see, and it needs no special case in the composer.
#:
#: The switch exists because these wizards run under ``sudo``, and sudo resets
#: the environment: an operator whose shell is French can land in an English
#: wizard through no choice of their own, with no way out but Ctrl-C and a
#: re-run with ``--french``.

#: What each action is bound to. Curses constants are resolved lazily so this
#: module stays importable without a terminal (and without curses at all, for
#: the headless `bob-core` build the tui package documents).
_LITERAL: "dict[str, tuple[int, ...]]" = {
    MOVE:    tuple(ord(c) for c in "jkJK"),
    EDGE:    (ord("g"), ord("G")),
    SELECT:  (10, 13),
    CREATE:  (10, 13),
    SUBMIT:  (10, 13),
    BACK:    (27,),
    QUIT:    (ord("q"), ord("Q")),
    TOGGLE:  (ord(" "),),
    ALL:     (ord("a"), ord("A")),
    UNMARK:  (ord("u"), ord("U")),
    DELETE:  (ord("d"), ord("D")),
    CHANGE:  (ord("c"), ord("C")),
    SUMMARY: (ord("s"), ord("S")),
    FULL:    (ord("s"), ord("S")),
    CONFIRM: (ord("y"), ord("Y")),
    NEW:     (ord("n"), ord("N")),
    LANG:    (ord("l"), ord("L")),
    BOOK:    (ord("m"), ord("M")),
    NOTES:   (ord("n"), ord("N")),
    ANNOTATE: (ord("a"), ord("A")),
    COMPARE: (ord("c"), ord("C")),
    HISTORY: (ord("h"), ord("H")),
    NUMBERS: (ord("#"),),
    NOTE_ADD: (ord("a"), ord("A")),
    NOTE_EDIT: (ord("e"), ord("E")),
    NOTE_WITHDRAW: (ord("r"), ord("R")),
    NOTE_PURGE: (ord("p"), ord("P")),
    NOTE_JOURNAL: (ord("v"), ord("V")),
    COMPLETE: (9,),
    REMOVED: (ord("r"), ord("R")),
    BREAKDOWN: (ord("b"), ord("B")),
    EXPAND: (ord("t"), ord("T")),
    CEILING: (ord("p"), ord("P")),
}

#: The glyph cluster shown for each action. Navigation is drawn without a
#: label — the arrows say what they do — so the footer fits 80 columns in both
#: locales with room for a screen's own actions.
_GLYPH = {
    MOVE: "↑↓ jk", PAGE: "PgUp/PgDn", EDGE: "g/G",
    SELECT: "⏎", CREATE: "⏎", SUBMIT: "⏎", BACK: "Esc", QUIT: "q",
    TOGGLE: "Spc", ALL: "a", UNMARK: "u", DELETE: "d",
    CHANGE: "c", SUMMARY: "s", FULL: "s", CONFIRM: "y", NEW: "n", LANG: "l", BOOK: "m",
    PEER: "←/→",
    NOTES: "n", ANNOTATE: "a", COMPARE: "c", HISTORY: "h", NUMBERS: "#",
    NOTE_ADD: "a", NOTE_EDIT: "e", NOTE_WITHDRAW: "r", NOTE_PURGE: "p", NOTE_JOURNAL: "v",
    COMPLETE: "Tab", REMOVED: "r", BREAKDOWN: "b", EXPAND: "t", CEILING: "p",
}


def _literal(action: str) -> "tuple[int, ...]":
    """The plain keys *action* binds — a numbered menu's digits included."""
    count = _pick_count(action)
    if count:
        return tuple(range(ord("1"), ord("1") + count))
    return _LITERAL.get(action, ())


def _glyph(action: str) -> str:
    count = _pick_count(action)
    if count:
        return "1" if count == 1 else f"1-{count}"
    return _GLYPH[action]


def _label_key(action: str) -> str:
    return "tui.keys.pick" if _pick_count(action) else "tui.keys." + action


#: The curses constants each action is bound to, by name.
_SPECIAL = {
    MOVE: ("KEY_UP", "KEY_DOWN"),
    PAGE: ("KEY_PPAGE", "KEY_NPAGE"),
    PEER: ("KEY_LEFT", "KEY_RIGHT"),
    SELECT: ("KEY_ENTER",),
    CREATE: ("KEY_ENTER",),
    SUBMIT: ("KEY_ENTER",),
}


def _special(curses, action: str) -> "tuple[int, ...]":
    """Curses key constants for *action*, resolved against a live module.

    v0.32.0 — only *action*'s own names are looked up. The table used to be
    built whole on every call, so resolving Enter read KEY_LEFT too.
    """
    return tuple(getattr(curses, name) for name in _SPECIAL.get(action, ()))


#: v0.33.0 — the arrow and page keys a terminal sends when it ignores the
#: keypad mode curses asks for (smkx): ``ESC [ A`` instead of ``ESC O A``.
#: curses knows only the form terminfo declares, so it returned Esc, then
#: ``[``, then the letter — read as BACK, then as the action bound to that
#: letter: ↑ as ``A`` (mark all), ← as ``D`` (delete), measured in a pty on
#: Linux Mint 22.3 (0.32.0). Both introducers are accepted (CSI ``[`` and SS3
#: ``O``); the tilde forms carry the page and home/end keys.
_FINAL = {"A": "KEY_UP", "B": "KEY_DOWN", "C": "KEY_RIGHT", "D": "KEY_LEFT",
          "H": "KEY_HOME", "F": "KEY_END"}
_TILDE = {"5": "KEY_PPAGE", "6": "KEY_NPAGE", "1": "KEY_HOME", "7": "KEY_HOME",
          "4": "KEY_END", "8": "KEY_END"}


def complete_escape(win, curses, ch: int) -> int:
    """*ch* as read; when it is Esc and an arrow or page sequence follows in
    the input already received, that key instead. Nothing waits: the bytes of
    a sequence arrive together, so an Esc pressed alone stays BACK. Bytes that
    form no known sequence are pushed back, in order."""
    if ch != 27 or not hasattr(win, "nodelay"):
        return ch                           # a window that cannot be read without waiting is not peeked
    seq: "list[int]" = []
    win.nodelay(True)
    try:
        while len(seq) < 4:
            nxt = win.getch()
            if nxt == -1:
                break
            seq.append(nxt)
            if len(seq) > 1 and not 48 <= nxt <= 57:
                break                       # a final byte ends the sequence
    finally:
        win.nodelay(False)
    text = "".join(chr(c) for c in seq if 0 <= c < 256)
    name = None
    if len(text) == 2 and text[0] in "[O":
        name = _FINAL.get(text[1])
    elif len(text) == 3 and text[0] == "[" and text[2] == "~":
        name = _TILDE.get(text[1])
    key = getattr(curses, name, None) if name else None
    if key is not None:
        return key
    for c in reversed(seq):
        curses.ungetch(c)
    return 27


def resolve(curses, ch: int, actions: "tuple[str, ...]") -> "str | None":
    """Which declared action *ch* triggers, or None.

    Order matters only in that a screen must not declare two actions sharing a
    key; :func:`conflicts` is the guard for that.
    """
    for action in actions:
        if ch in _literal(action) or ch in _special(curses, action):
            return action
    return None


def accepted(curses, actions: "tuple[str, ...]") -> "set[int]":
    """Every key code a screen declaring *actions* answers to — and so the only
    ones it may answer to (v0.39.0, CONVENTIONS.md "keys"). ↑↓ ride on MOVE,
    PgUp/PgDn on PAGE, ←/→ on PEER."""
    keys: "set[int]" = set()
    for action in actions:
        keys.update(_literal(action))
        keys.update(_special(curses, action))
    return keys


def direction(curses, ch: int) -> int:
    """-1 for up, +1 for down, 0 otherwise — for MOVE and PAGE alike."""
    if ch in (curses.KEY_UP, curses.KEY_PPAGE, ord("k"), ord("K")):
        return -1
    if ch in (curses.KEY_DOWN, curses.KEY_NPAGE, ord("j"), ord("J")):
        return 1
    return 0


def side(curses, ch: int) -> int:
    """-1 for ←, +1 for →, 0 otherwise — for PEER."""
    if ch == curses.KEY_LEFT:
        return -1
    if ch == curses.KEY_RIGHT:
        return 1
    return 0


def is_top(ch: int) -> bool:
    """``g`` means top, ``G`` means bottom — the pager convention."""
    return ch == ord("g")


def conflicts(actions: "tuple[str, ...]") -> "list[str]":
    """Actions in *actions* that share a literal key with another."""
    seen: "dict[int, str]" = {}
    clash = []
    for action in actions:
        for key in _literal(action):
            if key in seen and seen[key] != action:
                clash.append(f"{action} and {seen[key]} both bind {key!r}")
            seen[key] = action
    return clash


def footer_lines(t, actions: "tuple[str, ...]", width: int = 78) -> "list[str]":
    """The hint lines for a screen declaring *actions*, translated.

    Navigation is drawn as a bare glyph cluster; everything else carries its
    label, because ``d`` and ``c`` mean nothing on their own.

    Returns one line, or two when the actions do not fit. Wrapping rather than
    truncating is the point: ``--manage-logs`` declares seven actions and its
    line runs to 88 columns in English and 105 in French, so a ``[:w]`` slice
    would silently eat the exit hint — the one an operator needs most, and the
    one they cannot guess.
    """
    return [line for line, _caps in footer_layout(t, actions, width)]


def footer_layout(t, actions: "tuple[str, ...]", width: int = 78
                  ) -> "list[tuple[str, list[tuple[int, int]]]]":
    """The hint lines of :func:`footer_lines`, each with its key caps.

    v0.40.0 (user, 20 November 2026) — a cap is ``(start, end)``, a column span
    of the line covering one key: each navigation key tight on its glyph (they
    are one space apart), each action's glyph with the space on each side. The text is the
    very text footer_lines always returned — no width moves, no wrap moves —
    and the chrome paints the caps in their own colour so a key cannot run
    into its neighbour's label.
    """
    nav = [_glyph(a) for a in actions if a in NAVIGATION]
    # (text, its caps as spans relative to the part's start). The navigation
    # cluster gives each of its keys a cap of its own, tight on the glyph: its
    # keys are one space apart, and padded caps would merge into one white block
    # (the user, 20 November 2026). An action's cap takes the space on each side.
    nav_caps, offset = [], 0
    for glyph in nav:
        nav_caps.append((offset, offset + len(glyph)))
        offset += len(glyph) + 1
    parts = ([(" ".join(nav), nav_caps)] if nav else []) + [
        (f"{_glyph(a)} {t(_label_key(a))}", [(-1, len(_glyph(a)) + 1)])
        for a in actions if a not in NAVIGATION
    ]
    sep = "   "

    def line(chunk):
        text, caps, col = "  ", [], 2
        for i, (part, part_caps) in enumerate(chunk):
            if i:
                text += sep
                col += len(sep)
            caps.extend((col + start, col + end) for start, end in part_caps)
            text += part
            col += len(part)
        return text, caps

    first = line(parts)
    if len(first[0]) <= width or len(parts) < 2:
        return [first]

    # Split on the last separator that still fits, so no cluster is broken —
    # and again on what is left, as long as it does not fit (v0.43.0: the
    # preview's French banner ran to 84 columns on its second line once `t`
    # joined it; two lines were all this split had ever made). One or two
    # lines that fit are cut exactly as before.
    out = []
    rest = parts
    while len(line(rest)[0]) > width and len(rest) > 1:
        cut = len(rest) - 1
        while cut > 1 and len(line(rest[:cut])[0]) > width:
            cut -= 1
        out.append(line(rest[:cut]))
        rest = rest[cut:]
    out.append(line(rest))
    return out


def footer(t, actions: "tuple[str, ...]", width: int = 78) -> str:
    """Single-line convenience for screens that declare few enough actions."""
    return footer_lines(t, actions, width)[0]

def toggle_language(config=None) -> str:
    """Switch the interface between the two shipped locales, live.

    ``t`` handed to every screen is ``bob.i18n.t``, a module function reading a
    module global, so re-initialising swaps every string on the next redraw
    with no plumbing: the screens already hold the right object.

    When a *config* is given its ``lang`` follows. That matters for
    ``--install-cron``, whose language screen defaults to the installing
    session's locale — without this, switching the display to French would
    leave the generated cron job still pinned to English, and the wizard would
    contradict itself on the very screen that asks the question.

    Returns the code now in force.
    """
    from bob import i18n

    new = "fr" if i18n.current_lang() == "en" else "en"
    i18n.init(new)
    if config is not None:
        config.lang = new
    return new
