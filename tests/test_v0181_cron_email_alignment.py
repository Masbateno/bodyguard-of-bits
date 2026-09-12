"""--manage-cron aligns the e-mail column, without wrapping rows that fit.

Two coupled requirements, both learned from the wizard:

  * a job scheduled "the 1st, 15th of every month at 12:03" (37 chars) must not
    push its addresses right of the "every day at 18:56" jobs — the addresses
    line up in one column (v0.18.1);
  * that column is measured across the rows that *fit* only, so one month-long
    day list does not inflate the column and drag every short row onto two
    lines (the row that overflows wraps by itself — see the wrap tests).

`_cron_render_lines` is the pure layout the curses screen draws from.
"""

from __future__ import annotations

from bob.tui.cron import _cron_render_lines

_SHORT = [
    ("nightly              every day at 18:56", "a@x ; b@y", False),
    ("seup                 the 1st, 15th of every month at 12:03", "a@x", False),
    ("test                 every day at 22:46", "a@x ; b@y", False),
]

_GIANT = ("seup                 " + ", ".join(f"{n}th" for n in range(1, 32))
          + " of every month at 12:03")


def test_rows_that_fit_are_each_one_line():
    blocks = _cron_render_lines(_SHORT, 120)
    assert all(len(b) == 1 for b in blocks)


def test_the_address_column_is_aligned_across_fitting_rows():
    blocks = _cron_render_lines(_SHORT, 120)
    # the addresses start at the same column on every fitting row
    starts = [b[0].index("a@x") for b in blocks]
    assert len(set(starts)) == 1, f"addresses not aligned: {starts}"


def test_a_giant_row_does_not_drag_short_rows_onto_two_lines():
    """The bug: aligning to the widest row (a month-long schedule) padded every
    short row past the screen, so they all wrapped. Short rows must stay single
    AND stay aligned to each other — the giant row is excluded from the column,
    not allowed to inflate it (which would blow the padding past the screen and
    drop the short rows back to unaligned)."""
    rows = [
        ("nightly              every day at 18:56", "a@x", False),
        (_GIANT, "a@x", False),
        ("test                 the 1st and 15th of every month at 09:00", "a@x", False),
    ]
    blocks = _cron_render_lines(rows, 120)
    assert len(blocks[0]) == 1, "short row 'nightly' should stay on one line"
    assert len(blocks[2]) == 1, "short row 'test' should stay on one line"
    assert len(blocks[1]) >= 2, "the month-long row should wrap"
    # the two short rows (different lengths) still line their addresses up
    assert blocks[0][0].index("a@x") == blocks[2][0].index("a@x"), (
        "the giant row inflated the column and un-aligned the short rows"
    )


def test_a_single_row_is_one_line():
    blocks = _cron_render_lines([("solo                 every day at 03:00", "", False)], 120)
    assert blocks == [["  solo                 every day at 03:00"]]


def test_no_rows_is_empty():
    assert _cron_render_lines([], 120) == []
