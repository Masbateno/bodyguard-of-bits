"""v0.39.0 — the one way a list of numbers is read, everywhere BOB asks for one.

Decided with the user (19 November 2026). Four readers had four rules: the
notes refused a range with a hole in it ("2-4" over notes 1, 2 and 4 said "no
note 3"); the plain-text report list dropped a number it did not know without
a word ("1,7" over five reports deleted the first and said nothing of the
seventh); the plain-text job list refused a range reaching past the end and
any mix of forms ("1,3-5"); the plain-text address book capped a range at a
thousand numbers. One rule now:

* ``all`` — every entry there is;
* a number — that entry, which must exist: a number with no entry refuses the
  whole selection, and says which number;
* a range ``a-b`` (a ≤ b) — every entry there is between a and b, holes and
  all; a range with no entry in it refuses the selection;
* any of these, separated by commas; spaces and case do not matter.

The result is the entries chosen, in order, once each — never empty: a
selection that chooses nothing is refused, so an action never runs on nothing
without saying why.
"""

from __future__ import annotations


class SelectionError(ValueError):
    """Why a selection was refused: *kind* names it, *vars* fill its message.

    ``bad`` — not a selection (``selection``); ``missing`` — a number with no
    entry (``number``); ``empty_range`` — a range with no entry in it
    (``low``, ``high``); ``none`` — there is nothing to choose from.
    """

    def __init__(self, kind: str, **vars_: object) -> None:
        super().__init__(kind)
        self.kind = kind
        self.vars = vars_


def parse_selection(answer: str, available: "list[int] | range") -> "list[int]":
    """The entries *answer* chooses among *available* (see the module)."""
    there = sorted(set(available))
    text = answer.strip().lower()
    if not there:
        raise SelectionError("none")
    if text == "all":
        return there
    present = set(there)
    chosen: "set[int]" = set()
    for part in text.split(","):
        part = part.strip()
        low, sep, high = part.partition("-")
        low, high = low.strip(), high.strip()
        if sep and low.isdigit() and high.isdigit() and int(low) <= int(high):
            # Over what exists, never over the span: "1-999999999" costs as
            # little as "1-3".
            inside = [n for n in there if int(low) <= n <= int(high)]
            if not inside:
                raise SelectionError("empty_range", low=int(low), high=int(high))
            chosen.update(inside)
        elif not sep and part.isdigit():
            if int(part) not in present:
                raise SelectionError("missing", number=int(part))
            chosen.add(int(part))
        else:
            raise SelectionError("bad", selection=answer.strip())
    return sorted(chosen)
