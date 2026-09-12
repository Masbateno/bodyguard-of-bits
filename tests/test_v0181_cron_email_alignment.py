"""--manage-cron layout: aligned address column, and a separator between jobs.

Requirements learned from the wizard:

  * a variable-width schedule ("the 1st, 15th of every month at 12:03" vs "every
    day at 18:56") must not push the addresses out of column — they line up
    (v0.18.1);
  * the column is measured across the jobs that *fit* only, so one month-long
    day list does not inflate it and drag every short job onto two lines;
  * a dim separator line sits between jobs so they are told apart at a glance.

`_cron_render_lines` returns the flat display as ``(text, entry_index)`` rows;
a separator carries index ``-1``.
"""

from __future__ import annotations

from bob.tui.cron import _cron_render_lines


def _lines_of(display, idx):
    return [t for t, e in display if e == idx]


def _seps(display):
    return [t for t, e in display if e == -1]


_SHORT = [
    ("nightly", "every day at 18:56", "a@x", False),
    ("seup", "the 1st, 15th of every month at 12:03", "a@x", False),
    ("test", "every day at 22:46", "a@x", False),
]


def test_rows_that_fit_are_each_one_line():
    display = _cron_render_lines(_SHORT, 120)
    for idx in range(3):
        assert len(_lines_of(display, idx)) == 1


def test_the_address_column_is_aligned_across_fitting_rows():
    display = _cron_render_lines(_SHORT, 120)
    starts = [_lines_of(display, idx)[0].index("a@x") for idx in range(3)]
    assert len(set(starts)) == 1, f"addresses not aligned: {starts}"


def test_a_separator_sits_between_jobs():
    display = _cron_render_lines(_SHORT, 120)
    assert len(_seps(display)) == 2, "three jobs → two separators between them"
    assert all(set(s.strip()) <= {"─"} for s in _seps(display)), "separator is a rule"
    # a separator never sits before the first job
    assert display[0][1] == 0


def test_a_single_job_has_no_separator():
    display = _cron_render_lines([("solo", "every day at 03:00", "", False)], 120)
    assert _seps(display) == []


def test_a_giant_row_does_not_drag_short_rows_onto_two_lines():
    """Aligning to the widest row padded every short row past the screen, so
    they all wrapped. Short rows stay single AND aligned to each other; the
    giant row is excluded from the column."""
    giant = ", ".join(f"{n}th" for n in range(1, 32)) + " of every month at 12:03"
    rows = [
        ("nightly", "every day at 18:56", "a@x", False),
        ("seup", giant, "a@x", False),
        ("test", "the 1st and 15th of every month at 09:00", "a@x", False),
    ]
    display = _cron_render_lines(rows, 120)
    assert len(_lines_of(display, 0)) == 1
    assert len(_lines_of(display, 2)) == 1
    assert len(_lines_of(display, 1)) >= 2
    assert _lines_of(display, 0)[0].index("a@x") == _lines_of(display, 2)[0].index("a@x"), (
        "the giant row inflated the column and un-aligned the short rows"
    )


def test_no_rows_is_empty():
    assert _cron_render_lines([], 120) == []
