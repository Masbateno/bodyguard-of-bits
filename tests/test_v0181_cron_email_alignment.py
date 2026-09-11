"""--manage-cron aligns the e-mail column regardless of schedule length.

Measured in the wizard: a job scheduled "the 1st, 15th of every month at 12:03"
(37 chars) pushed its addresses right of the jobs scheduled "every day at 18:56"
(18 chars), because the schedule column was padded to a fixed 30. The addresses
no longer lined up::

    nightly   every day at 18:56               a@x ; b@y
    seup      the 1st, 15th of every month at 12:03   a@x
    test      every day at 22:46               a@x ; b@y

The left column (name + schedule + legacy tag) is now padded to the widest
across every job, so the addresses start at one column.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bob import i18n
from bob.tui.cron import _cron_left_columns


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _crons():
    return [
        SimpleNamespace(name="nightly", schedule_expr="56 18 * * *", legacy=False),
        SimpleNamespace(name="seup", schedule_expr="3 12 1,15 * *", legacy=False),
        SimpleNamespace(name="test", schedule_expr="46 22 * * *", legacy=False),
    ]


def test_every_left_column_has_the_same_width():
    cols = _cron_left_columns(_crons(), i18n.t, "en")
    assert len({len(c) for c in cols}) == 1, (
        "the columns are ragged, so the e-mail addresses will not align"
    )


def test_the_width_fits_the_longest_schedule():
    crons = _crons()
    cols = _cron_left_columns(crons, i18n.t, "en")
    # "the 1st, 15th of every month at 12:03" is the widest; every column must
    # be at least wide enough to hold it without truncation.
    from bob.tui.cron import cron_to_human
    longest = max(len(cron_to_human(c.schedule_expr, "en")) for c in crons)
    assert all(len(c) >= longest for c in cols)


def test_each_column_carries_its_name_and_schedule():
    cols = {c.split()[0]: c for c in _cron_left_columns(_crons(), i18n.t, "en")}
    assert "every day at 18:56" in cols["nightly"]
    assert "the 1st, 15th of every month at 12:03" in cols["seup"]


def test_a_single_job_still_produces_one_padded_column():
    one = [SimpleNamespace(name="solo", schedule_expr="0 3 * * *", legacy=False)]
    cols = _cron_left_columns(one, i18n.t, "en")
    assert len(cols) == 1 and cols[0].startswith("solo")


def test_no_jobs_is_empty_not_an_error():
    assert _cron_left_columns([], i18n.t, "en") == []
