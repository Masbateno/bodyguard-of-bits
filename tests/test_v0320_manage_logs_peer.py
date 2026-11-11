"""v0.32.0 — the --manage-logs preview moves to the neighbouring log with ←/→.

Before, reading the next report meant Esc, ↓, Enter: back to the list and in
again, losing the summary view on the way. The preview now takes ← for the
older log and → for the newer one, keeps the full or summary view, starts the
new log at its top, stops at either end, and hands the list back the log it
showed last so the cursor sits on it.

The keys follow bob/tui/_keys.py, decided with the user (11 November 2026):
arrows only — h/l would pair with jk but ``l`` is LANG, ``n``/``p`` collide
with NEW, ``[``/``]`` need AltGr on AZERTY — and time runs left to right, as in
the score chart. The list is sorted newest first, so ← is the entry below.
"""

from __future__ import annotations

import os
import sys

import pytest

from bob import i18n
from bob.tui import _keys


class _FakeCurses:
    A_BOLD = 1 << 0
    A_REVERSE = 1 << 1
    A_NORMAL = 0
    A_DIM = 1 << 2
    KEY_UP, KEY_DOWN, KEY_PPAGE, KEY_NPAGE, KEY_ENTER = 1001, 1002, 1003, 1004, 1005
    KEY_LEFT, KEY_RIGHT = 1006, 1007
    COLOR_BLACK, COLOR_RED, COLOR_GREEN, COLOR_YELLOW = 0, 1, 2, 3
    COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE = 4, 5, 6, 7

    class error(Exception):
        pass

    @staticmethod
    def curs_set(_n):
        return 0

    @staticmethod
    def color_pair(n: int) -> int:
        return n << 8

    @staticmethod
    def has_colors() -> bool:
        return False


L, R, ENTER, ESC = _FakeCurses.KEY_LEFT, _FakeCurses.KEY_RIGHT, _FakeCurses.KEY_ENTER, 27


class _Screen:
    """Records the screen as it stands each time a key is read."""

    def __init__(self, keys, h=24, w=110):
        self._h, self._w = h, w
        self._keys = list(keys)
        self.rows: "dict[int, str]" = {}
        self.frames: "list[dict[int, str]]" = []

    def getmaxyx(self):
        return self._h, self._w

    def erase(self):
        self.rows.clear()

    def addstr(self, row, col, text, attr=0):
        if row < 0 or row >= self._h:
            raise _FakeCurses.error("out of bounds")
        self.rows[row] = text

    def refresh(self):
        pass

    def getch(self):
        self.frames.append(dict(self.rows))
        return self._keys.pop(0) if self._keys else ESC


@pytest.fixture
def fake_curses():
    i18n.init("en")
    real = sys.modules.get("curses")
    sys.modules["curses"] = _FakeCurses
    yield
    if real is not None:
        sys.modules["curses"] = real
    else:
        sys.modules.pop("curses", None)


def _logs(tmp_path, n=3):
    """n reports, returned newest first as the list sorts them."""
    paths = []
    for i in range(n):
        f = tmp_path / f"bob_2026110{i + 1}_120000.log"
        f.write_text(f"report {i + 1}\nscore 7/10\n", encoding="utf-8")
        paths.append(f)
    return sorted(paths, reverse=True)


class TestThePeerIndex:
    """Newest first: index 0 is the newest log."""

    def test_left_is_the_older_log(self):
        assert _ml()._peer_index(["n", "m", "o"], 0, -1) == 1

    def test_right_is_the_newer_log(self):
        assert _ml()._peer_index(["n", "m", "o"], 2, +1) == 1

    @pytest.mark.parametrize("idx, side", [(2, -1), (0, +1)], ids=["oldest-left", "newest-right"])
    def test_it_stops_at_either_end(self, idx, side):
        assert _ml()._peer_index(["n", "m", "o"], idx, side) == idx


def _ml():
    import bob.manage_logs as ml
    return ml


class TestTheKeys:

    def test_the_arrows_resolve_to_peer(self):
        assert _keys.resolve(_FakeCurses, L, (_keys.PEER,)) == _keys.PEER
        assert _keys.resolve(_FakeCurses, R, (_keys.PEER,)) == _keys.PEER
        assert _keys.resolve(_FakeCurses, ord("l"), (_keys.PEER,)) is None

    def test_side(self):
        assert (_keys.side(_FakeCurses, L), _keys.side(_FakeCurses, R),
                _keys.side(_FakeCurses, _FakeCurses.KEY_UP)) == (-1, 1, 0)

    @pytest.mark.parametrize("mode", ["full", "summary"])
    def test_offered_only_with_another_log(self, mode):
        ml = _ml()
        assert _keys.PEER not in ml._preview_keys(mode)
        with_peers = ml._preview_keys(mode, peers=True)
        assert _keys.PEER in with_peers and with_peers[-1] == _keys.BACK
        assert not _keys.conflicts(with_peers)

    @pytest.mark.parametrize("lang", ["en", "fr"])
    @pytest.mark.parametrize("mode", ["full", "summary"])
    def test_the_footer_says_it_and_fits(self, lang, mode):
        i18n.init(lang)
        try:
            lines = _keys.footer_lines(i18n.t, _ml()._preview_keys(mode, peers=True), 78)
        finally:
            i18n.init("en")
        assert all(len(x) <= 78 for x in lines)
        label = {"en": "←/→ older/newer", "fr": "←/→ plus ancien/récent"}[lang]
        assert any(label in x for x in lines)


def test_a_key_resolves_without_the_other_actions_constants():
    """Only the action asked is looked up: a curses without KEY_LEFT (a test
    stub, a minimal build) still resolves Enter."""
    class _Stub:
        KEY_ENTER = 343
    assert _keys.resolve(_Stub, 343, (_keys.SELECT,)) == _keys.SELECT


class TestThePreview:

    def test_left_shows_the_older_log_and_returns_it(self, tmp_path, fake_curses):
        logs = _logs(tmp_path)
        scr = _Screen([L])
        shown = _ml()._curses_preview_log(scr, logs[0], i18n.t, logs)
        assert shown == logs[1]
        assert logs[0].name in scr.frames[0][0] and "1/3" in scr.frames[0][0]
        assert logs[1].name in scr.frames[1][0] and "2/3" in scr.frames[1][0]
        assert any("report 2" in v for v in scr.frames[1].values())

    def test_right_at_the_newest_stays(self, tmp_path, fake_curses):
        logs = _logs(tmp_path)
        scr = _Screen([R])
        assert _ml()._curses_preview_log(scr, logs[0], i18n.t, logs) == logs[0]

    def test_the_summary_view_is_kept(self, tmp_path, fake_curses):
        logs = _logs(tmp_path)
        scr = _Screen([ord("s"), L])
        _ml()._curses_preview_log(scr, logs[0], i18n.t, logs)
        summary_tag = i18n.t("tui.mode_summary")
        assert summary_tag in scr.frames[1][0] and summary_tag in scr.frames[2][0]
        assert logs[1].name in scr.frames[2][0]

    def test_the_new_log_starts_at_its_top(self, tmp_path, fake_curses):
        logs = _logs(tmp_path)
        for f in logs[:2]:          # both long: the scroll clamp alone cannot reset it
            f.write_text("\n".join(f"line {i}" for i in range(200)), encoding="utf-8")
        scr = _Screen([_FakeCurses.KEY_NPAGE, L])
        _ml()._curses_preview_log(scr, logs[0], i18n.t, logs)
        def top_shown(frame):
            return any(v == "line 0" for v in frame.values())
        assert top_shown(scr.frames[0]) and not top_shown(scr.frames[1])   # PgDn scrolled
        assert top_shown(scr.frames[2]) and logs[1].name in scr.frames[2][0]

    def test_alone_it_offers_nothing_and_says_no_position(self, tmp_path, fake_curses):
        logs = _logs(tmp_path, n=1)
        scr = _Screen([L])
        assert _ml()._curses_preview_log(scr, logs[0], i18n.t, logs) == logs[0]
        assert "1/1" not in scr.frames[0][0]
        assert not any("older/newer" in v for v in scr.frames[0].values())


def test_the_list_cursor_follows_the_preview(tmp_path, fake_curses):
    """Enter, ←, Esc: back in the list, the cursor is on the older log."""
    logs = _logs(tmp_path)
    for i, f in enumerate(logs):
        os.utime(f, (1_700_000_000 - i * 3600,) * 2)

    class _Cfg:
        no_color = True
        lang = "en"

    scr = _Screen([ENTER, L, ESC, ESC])
    _ml()._browse_dir(scr, tmp_path, {}, _Cfg(), i18n.t)
    back_in_list = scr.frames[3]
    cursor_rows = [v for v in back_in_list.values() if v.lstrip().startswith("→")]
    assert len(cursor_rows) == 1 and logs[1].name in cursor_rows[0]
