"""--manage-cron wraps a too-wide row instead of truncating it.

A cron scheduled on many days of the month renders a long human schedule ("the
1st, 2nd, … 31st of every month at 12:03"); with the addresses after it the row
ran past the screen and was clipped. A row too wide to fit now wraps — the
schedule keeps its own line(s), the addresses move to an indented continuation
line — and it adapts to the terminal width. `_cron_render_lines` is the pure
layout the curses screen draws from.
"""

from __future__ import annotations

from bob.tui.cron import _cron_render_lines

_LONG = ("nightly              " + ", ".join(f"{n}th" for n in range(1, 32))
         + " of every month at 12:03")
_EMAILS = "cedricclauzel30@gmail.com ; cedricclauzel@mailo.com"


def _block(w, emails=_EMAILS, marked=False):
    return _cron_render_lines([(_LONG, emails, marked)], w)[0]


def test_a_wide_row_wraps_instead_of_truncating():
    w = 60
    lines = _block(w)
    assert len(lines) >= 2
    assert all(len(ln) <= w - 1 for ln in lines)          # nothing clipped
    joined = " ".join(ln.strip() for ln in lines)
    for token in ("1th", "31th", "of every month at 12:03"):
        assert token in joined, token


def test_the_addresses_flow_onto_the_schedule_continuation():
    """The addresses ride the wrapped schedule's flow (at the end of the last
    line), not a separate indented line of their own."""
    lines = _block(60)
    assert any("cedricclauzel30@gmail.com" in ln for ln in lines)
    assert any("cedricclauzel@mailo.com" in ln for ln in lines)
    # the addresses are appended to the schedule text, so the last line holds an
    # address and is not an address-only, deeply-indented line
    assert "cedricclauzel" in lines[-1]
    assert not lines[-1].startswith("    ")  # no separate 4-space email line


def test_narrower_screen_reflows_to_more_lines():
    assert len(_block(50)) >= len(_block(100))


def test_a_marked_row_keeps_its_check_on_the_first_line():
    assert _block(60, marked=True)[0].startswith("✔ ")


def test_no_emails_produces_no_dangling_line():
    lines = _block(60, emails="")
    assert lines and not any(ln.strip() == "" for ln in lines)
