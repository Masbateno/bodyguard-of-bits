"""v0.43.0 — --manage-cron says when and by whom each scheduled audit was created.

Asked by the user (23 November 2026): "the timestamp and the user who created
the cron, just under its line" — for comfort, though the logs hold it. Read
from the cron journal when it holds the creation (the trace), else from the
job's header: the "created" line BOB writes since 0.43.0, else the
"generated" date every version wrote, said as such.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob import _names, i18n, journals as J
from bob.cron._parse import CronEntry, _origin


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def entry(**kw):
    base = dict(name="nightly", schedule_expr="0 3 * * *", hour=3, minute=0,
                script_path=Path("/x.sh"), cron_path=Path("/etc/cron.d/bob-nightly"))
    base.update(kw)
    return CronEntry(**base)


HEADER = ("# BOB cron — generated 2026-11-20 by bob --install-cron\n# name: nightly\n"
          "# email: a@example.com\n# created: 2026-11-20T09:15:02+01:00 by alice\n")


def test_the_header_is_read():
    assert _origin(HEADER) == {"generated": "2026-11-20", "created_at": "2026-11-20T09:15:02+01:00",
                               "created_by": "alice"}
    assert _origin("# BOB cron — generated 2026-10-01 by bob --install-cron\n")["created_by"] == ""


def test_the_journal_comes_first():
    J.append("cron", "cron_created", category="cron", name="nightly", schedule="0 3 * * *", email="")
    text = J.cron_origin(entry(created_at="2020-01-01T00:00:00+00:00", created_by="mallory"), i18n.t)
    assert text.startswith("created on ") and "by " + _names.mark("?") not in text
    assert "mallory" not in text and "2020" not in text


def test_without_the_journal_the_file_says_it_and_is_named_as_the_source():
    text = J.cron_origin(entry(**_origin(HEADER)), i18n.t)
    assert _names.plain(text) == "created on 2026-11-20 at " + text.split(" at ")[1].split(" ")[0] \
        + " by alice (per the job's file)"
    assert _names.mark("alice") in text                    # the account in its colour


def test_an_older_job_says_its_date_and_no_author():
    text = J.cron_origin(entry(generated="2026-10-01"), i18n.t)
    assert text == "created on 2026-10-01 — author not recorded"
    assert J.cron_origin(entry(), i18n.t) == "creation not recorded"


def test_the_line_sits_under_its_job():
    from bob.tui.cron import _CRON_SCHED_COL, _cron_render_lines
    rows = [("1. nightly", "every day at 03:00", "", False), ("2. weekly", "Mondays at 04:00", "", False)]
    lines = _cron_render_lines(rows, 100, ["origin one", "origin two"])
    texts = [(text.strip(), idx) for text, idx in lines]
    assert ("origin one", 0) in texts and ("origin two", 1) in texts
    i = [t for t, _ in texts].index("origin one")
    assert texts[i - 1][0].startswith("1. nightly") and lines[i][0].startswith(" " * _CRON_SCHED_COL)


def test_a_new_job_writes_when_and_by_whom(tmp_path, monkeypatch):
    from bob import annotations
    from bob.cron import _io
    from bob.cron import _parse
    monkeypatch.setattr(_parse, "CRON_DIR", tmp_path)
    monkeypatch.setattr(_io, "use_crontab", lambda: False)
    monkeypatch.setattr(annotations, "operator", lambda: {"uid": 0, "login": "alice"})
    path = _io.write_cron_job("nightly", "nightly", "a@example.com", "0 3 * * *", "/x.sh", "2026-11-23")
    origin = _origin(path.read_text())
    assert origin["created_by"] == "alice" and origin["created_at"].startswith("20")


def test_an_address_says_when_and_by_whom_it_was_added():
    J.append("cron", "address_added", category="carnet", address="ops@example.com")
    text = J.address_origin("ops@example.com", i18n.t)
    assert _names.plain(text).startswith("added on ") and " by " in text
    assert J.address_origin("old@example.com", i18n.t) == "addition not recorded"


def test_the_last_addition_counts():
    J.append("cron", "address_added", category="carnet", address="ops@example.com")
    first = J.load("cron").events[-1]
    J.append("cron", "address_removed", category="carnet", address="ops@example.com")
    J.append("cron", "address_added", category="carnet", address="ops@example.com")
    journal = J.load("cron")
    assert journal.events[-1].at >= first.at
    assert J.address_origin("ops@example.com", i18n.t, journal) == J.address_origin(
        "ops@example.com", i18n.t, J.Journal(events=[journal.events[-1]]))
