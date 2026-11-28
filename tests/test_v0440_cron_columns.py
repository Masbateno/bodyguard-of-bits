"""v0.44.0 — --manage-cron's name column doubled, and every column held.

Asked by the user (27 November 2026): "dans --manage-cron, il faut agrandir la
colonne du nom du cron, il faudrait la doubler, et aussi veiller à ce que
toutes les colonnes restent alignées". Before: a 20-column name field that a
longer name overran, pushing its schedule and addresses out of their columns;
and a job padded to the address column could overrun the screen and fall back
to an unpadded line, out of the column too.
"""

from __future__ import annotations

from bob.tui.cron import _CRON_SCHED_COL, _cron_render_lines, _cron_sched_col


def _job(display, idx):
    return [t for t, e in display if e == idx]


def test_the_name_column_is_doubled():
    name = "1. " + "n" * 37                  # 40 columns: fits the doubled field
    display = _cron_render_lines([(name, "every day at 03:00", "", False)], 120)
    assert _CRON_SCHED_COL == 43
    line = _job(display, 0)[0]
    assert line.startswith("  " + name) and line.index("every day") == 43


def test_a_long_name_takes_its_own_line_and_pushes_nothing():
    long_name = "1. " + "audit-of-the-whole-fleet-every-night-" * 2
    rows = [(long_name, "every day at 03:00", "a@x", False),
            ("2. short", "every day at 04:00", "b@x", False)]
    display = _cron_render_lines(rows, 120)
    first = _job(display, 0)
    assert first[0].strip() == long_name.strip()          # whole, on its own line
    assert first[1].index("every day") == 43                # the schedule in its column
    assert first[1].index("a@x") == _job(display, 1)[0].index("b@x")


def test_every_address_starts_in_one_column_and_no_line_overruns():
    width = 120                              # job 1 fits unpadded, not padded to job 2
    rows = [("1. a", "every day at 03:00", "x" * 40 + "@example.org", False),
            ("2. b", "the 1st, 15th and 28th of every month at 12:03", "c@x", False),
            ("3. c", "every day at 05:00", "d@x", False)]
    display = _cron_render_lines(rows, width)
    assert all(len(t) <= width - 1 for t, _e in display)
    one_line = [_job(display, i)[0] for i in range(3) if len(_job(display, i)) == 1]
    starts = {ln.index(ln.split()[-1]) for ln in one_line}
    assert len(one_line) >= 2 and len(starts) == 1, one_line


def test_an_address_is_never_cut_in_two():
    address = "someone.with.a.rather.long.name@example.org"   # 43: wider than the 36 left at 60 columns
    rows = [("1. nightly", ", ".join(f"{n}th" for n in range(1, 32)), address, False)]
    lines = _job(_cron_render_lines(rows, 60), 0)
    assert any(address in ln for ln in lines)


def test_a_narrow_terminal_shrinks_the_name_column_not_the_schedule():
    assert _cron_sched_col(80) == 43
    assert _cron_sched_col(70) == 2 + 30 + 1
    assert _cron_sched_col(40) == 2 + 20 + 1
