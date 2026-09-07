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
SUMMARY  = "summary"    #: s
CONFIRM  = "confirm"    #: y
NEW      = "new"        #: n
CREATE   = "create"     #: Enter, on a landing screen
SUBMIT   = "submit"     #: Enter, on a text-input screen
LANG     = "lang"       #: l — switch the interface language, landing screens only
BOOK     = "book"       #: m — open the email address book

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
    CONFIRM: (ord("y"), ord("Y")),
    NEW:     (ord("n"), ord("N")),
    LANG:    (ord("l"), ord("L")),
    BOOK:    (ord("m"), ord("M")),
}

#: The glyph cluster shown for each action. Navigation is drawn without a
#: label — the arrows say what they do — so the footer fits 80 columns in both
#: locales with room for a screen's own actions.
_GLYPH = {
    MOVE: "↑↓ jk", PAGE: "PgUp/PgDn", EDGE: "g/G",
    SELECT: "⏎", CREATE: "⏎", SUBMIT: "⏎", BACK: "Esc", QUIT: "q",
    TOGGLE: "Spc", ALL: "a", UNMARK: "u", DELETE: "d",
    CHANGE: "c", SUMMARY: "s", CONFIRM: "y", NEW: "n", LANG: "l", BOOK: "m",
}


def _special(curses, action: str) -> "tuple[int, ...]":
    """Curses key constants for *action*, resolved against a live module."""
    return {
        MOVE: (curses.KEY_UP, curses.KEY_DOWN),
        PAGE: (curses.KEY_PPAGE, curses.KEY_NPAGE),
        SELECT: (curses.KEY_ENTER,),
        CREATE: (curses.KEY_ENTER,),
        SUBMIT: (curses.KEY_ENTER,),
    }.get(action, ())


def resolve(curses, ch: int, actions: "tuple[str, ...]") -> "str | None":
    """Which declared action *ch* triggers, or None.

    Order matters only in that a screen must not declare two actions sharing a
    key; :func:`conflicts` is the guard for that.
    """
    for action in actions:
        if ch in _LITERAL.get(action, ()) or ch in _special(curses, action):
            return action
    return None


def direction(curses, ch: int) -> int:
    """-1 for up, +1 for down, 0 otherwise — for MOVE and PAGE alike."""
    if ch in (curses.KEY_UP, curses.KEY_PPAGE, ord("k"), ord("K")):
        return -1
    if ch in (curses.KEY_DOWN, curses.KEY_NPAGE, ord("j"), ord("J")):
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
        for key in _LITERAL.get(action, ()):
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
    nav = [_GLYPH[a] for a in actions if a in NAVIGATION]
    rest = [
        f"{_GLYPH[a]} {t('tui.keys.' + a)}"
        for a in actions if a not in NAVIGATION
    ]
    parts = ([" ".join(nav)] if nav else []) + rest
    sep = "   "
    first = "  " + sep.join(parts)
    if len(first) <= width or len(parts) < 2:
        return [first]

    # Split on the last separator that still fits, so no cluster is broken.
    cut = len(parts) - 1
    while cut > 1 and len("  " + sep.join(parts[:cut])) > width:
        cut -= 1
    return ["  " + sep.join(parts[:cut]), "  " + sep.join(parts[cut:])]


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
