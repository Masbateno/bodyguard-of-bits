"""--manage-cron wraps a too-wide job instead of truncating it.

A job scheduled on many days of the month renders a schedule so long the row ran
past the screen and was clipped. A job too wide to fit now wraps: schedule and
addresses flow together (the addresses land at the end of the wrapped text, not
on a line of their own), every continuation line is indented to the schedule
column so it lines up under the jobs above, and it adapts to the width.

`_cron_render_lines` returns the flat display as ``(text, entry_index)`` rows.
"""

from __future__ import annotations

from bob.tui.cron import _cron_render_lines, _CRON_SCHED_COL

_LONG = ", ".join(f"{n}th" for n in range(1, 32)) + " of every month at 12:03"
_EMAILS = "cedricclauzel30@gmail.com ; cedricclauzel@mailo.com"


def _lines(w, emails=_EMAILS, marked=False):
    display = _cron_render_lines([("nightly", _LONG, emails, marked)], w)
    return [t for t, e in display if e == 0]


def test_a_wide_row_wraps_instead_of_truncating():
    w = 60
    lines = _lines(w)
    assert len(lines) >= 2
    assert all(len(ln) <= w - 1 for ln in lines)          # nothing clipped
    joined = " ".join(ln.strip() for ln in lines)
    for token in ("1th", "31th", "of every month at 12:03"):
        assert token in joined, token


def test_the_addresses_flow_onto_the_schedule_continuation():
    """The addresses ride the wrapped flow (end of the last line), not a
    separate line of their own."""
    lines = _lines(60)
    assert "cedricclauzel" in lines[-1]


def test_continuation_lines_align_under_the_schedule_column():
    lines = _lines(60)
    for cont in lines[1:]:
        assert cont.startswith(" " * _CRON_SCHED_COL)
        assert cont[_CRON_SCHED_COL] != " "               # real content there


def test_narrower_screen_reflows_to_more_lines():
    assert len(_lines(50)) >= len(_lines(100))


def test_a_marked_row_keeps_its_check_on_the_first_line():
    assert _lines(60, marked=True)[0].startswith("✔ ")


def test_no_emails_produces_no_dangling_line():
    lines = _lines(60, emails="")
    assert lines and not any(ln.strip() == "" for ln in lines)
