"""v0.43.0 — ``t`` in the report preview: everything at once, then nothing.

Asked by the user (22 November 2026): one key that shows the notes with their
journal, the comparison, the history and the computation together — and the
line numbers too. Pressed again, it hides them all. Driven on the preview
itself (a fake screen), the frames read as drawn.
"""

from __future__ import annotations

import os

import pytest

from bob import annotations as A
from bob import i18n
from tests.test_v0320_manage_logs_peer import ESC, _Screen, fake_curses  # noqa: F401
from tests.test_v0390_preview_blocks import _report


@pytest.fixture(autouse=True)
def _owner(monkeypatch):
    monkeypatch.setattr(A, "_JOURNAL_UID", os.geteuid())


def _has(frame, text):
    return any(text in row for row in frame.values())


def test_t_shows_everything_then_nothing(tmp_path, fake_curses):
    import bob.manage_logs as ml
    older = _report(tmp_path, "20261115_090000", score=5)
    newer = _report(tmp_path, "20261116_090000", score=6)
    A.add(newer, "a note")
    scr = _Screen([ord("t"), ord("t"), ESC], h=60, w=120)
    ml._curses_preview_log(scr, newer, i18n.t, [newer, older])
    titles = [i18n.t("manage_logs.note_journal_title"), i18n.t("manage_logs.block_compare"),
              i18n.t("manage_logs.block_history"), i18n.t("manage_logs.block_breakdown"),
              i18n.t("manage_logs.block_notes", count=1)]
    shown, hidden = scr.frames[1], scr.frames[2]
    assert all(_has(shown, title) for title in titles)
    assert _has(shown, "1 │ report 20261116")                # the line numbers
    assert not any(_has(hidden, title) for title in titles)
    assert not _has(hidden, "1 │ report")


def test_t_is_on_the_banner(tmp_path, fake_curses):
    import bob.manage_logs as ml
    from bob.tui import _keys
    assert _keys.EXPAND in ml._preview_keys("full") and _keys.EXPAND in ml._preview_keys("summary")
    assert not _keys.conflicts(ml._preview_keys("full"))


def test_the_french_banner_wraps_to_a_third_line_rather_than_overflow():
    """With t, the preview's French banner ran to 84 columns on its second
    line: the split made two lines at most. Every line now fits, and every
    key is still there."""
    import bob.manage_logs as ml
    from bob.tui import _keys
    i18n.init("fr")
    try:
        lines = _keys.footer_lines(i18n.t, ml._preview_keys("full", peers=True), 78)
    finally:
        i18n.init("en")
    assert len(lines) == 3 and all(len(x) <= 78 for x in lines)
    assert any("←/→ plus ancien/récent" in x for x in lines) and any("Esc retour" in x for x in lines)
