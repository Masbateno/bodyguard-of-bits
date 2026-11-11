"""v0.33.0 — an arrow sent in normal-mode form is one key, not Esc + a letter.

curses asks the terminal for keypad mode (smkx) and recognises the arrows only
in the form terminfo declares (``ESC O D``). A terminal that ignores the
request sends ``ESC [ D``: curses returned Esc, ``[``, ``D`` — BACK, then the
action bound to ``D`` (delete in the --manage-logs list), ↑ as ``A`` (mark
all). Measured in a pty on Linux Mint 22.3 with 0.32.0 (netnsbench/c0320).
bob/tui/_keys.complete_escape reads the bytes already received after an Esc
and returns the key they form.
"""

from __future__ import annotations

import pytest

from bob.tui import _keys


class _Curses:
    KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT = 259, 258, 260, 261
    KEY_PPAGE, KEY_NPAGE, KEY_HOME, KEY_END = 339, 338, 262, 360
    pushed: list

    def __init__(self):
        self.pushed = []

    def ungetch(self, c):
        self.pushed.append(c)


class _Win:
    def __init__(self, pending):
        self.pending = [ord(c) if isinstance(c, str) else c for c in pending]
        self.modes = []

    def nodelay(self, flag):
        self.modes.append(flag)

    def getch(self):
        return self.pending.pop(0) if self.pending else -1


@pytest.mark.parametrize("pending, key", [
    ("[A", "KEY_UP"), ("[B", "KEY_DOWN"), ("[C", "KEY_RIGHT"), ("[D", "KEY_LEFT"),
    ("OA", "KEY_UP"), ("OD", "KEY_LEFT"), ("[H", "KEY_HOME"), ("[F", "KEY_END"),
    ("[5~", "KEY_PPAGE"), ("[6~", "KEY_NPAGE"),
], ids=lambda x: str(x))
def test_a_sequence_is_its_key(pending, key):
    c = _Curses()
    win = _Win(pending)
    assert _keys.complete_escape(win, c, 27) == getattr(c, key)
    assert win.modes == [True, False] and not c.pushed


def test_esc_alone_stays_back():
    c = _Curses()
    assert _keys.complete_escape(_Win(""), c, 27) == 27 and not c.pushed


def test_unknown_bytes_are_given_back_in_order():
    c = _Curses()
    assert _keys.complete_escape(_Win("x"), c, 27) == 27
    assert c.pushed == [ord("x")]
    c = _Curses()
    assert _keys.complete_escape(_Win("[Z"), c, 27) == 27
    assert list(reversed(c.pushed)) == [ord("["), ord("Z")]


def test_other_keys_pass_untouched():
    win = _Win("[D")
    assert _keys.complete_escape(win, _Curses(), ord("d")) == ord("d") and win.modes == []


def test_the_preview_takes_a_normal_mode_left_as_left(tmp_path):
    """End to end: ESC [ D in the --manage-logs preview shows the older log
    (0.32.0: Esc left the preview)."""
    import sys
    from bob import i18n
    from tests.test_v0320_manage_logs_peer import _FakeCurses, _logs

    class _Screen:
        def __init__(self, keys):
            self.keys = list(keys)
            self.rows = {}
            self.frames = []

        def getmaxyx(self):
            return 24, 110

        def erase(self):
            self.rows.clear()

        def addstr(self, row, col, text, attr=0):
            self.rows[row] = text

        def refresh(self):
            pass

        def nodelay(self, flag):
            pass

        def getch(self):
            self.frames.append(dict(self.rows))
            return self.keys.pop(0) if self.keys else -1

    class _C(_FakeCurses):
        @staticmethod
        def ungetch(c):
            pass

    i18n.init("en")
    real = sys.modules.get("curses")
    sys.modules["curses"] = _C
    try:
        import bob.manage_logs as ml
        logs = _logs(tmp_path)
        scr = _Screen([27, ord("["), ord("D")])
        # after the sequence the screen reads -1 (nothing), then Esc to leave
        scr.keys += [27]
        shown = ml._curses_preview_log(scr, logs[0], i18n.t, logs)
    finally:
        if real is not None:
            sys.modules["curses"] = real
    assert shown == logs[1]
