"""--manage-logs: each log directory with its reports' size and its creation date.

0.28.1 — asked by the user (29 October 2026): the directory picker, and the
text mode's directory headers, now say how much the BOB reports in a directory
weigh and when the directory was created.

Measured (30 October 2026) before writing it:
- Python's ``os.stat`` has no birth time on Linux (no ``st_birthtime``, no
  ``os.statx`` in 3.10-3.14); statx(2) through the C library gives it — on
  ext4 and tmpfs it matched ``stat -c %W``, on /proc and /sys it is absent;
  it worked on glibc (Debian 13, Python 3.10) and musl (Alpine 3.24, 3.14.7).
- BusyBox's ``stat -c %W`` prints the letter "W" and exits 0: the command
  is not used.
- ``glob`` on a directory BOB may not read answers an empty list (the picker
  said "empty"); ``iterdir`` raises, and the label now says "unreadable".

The size is the BOB reports' total, as the user decided; the date is the
directory's real creation date, or "unknown" — never the modification time in
its place.
"""

from __future__ import annotations

import ctypes
import json
import os
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import bob.manage_logs as ml
from bob import i18n

_FIXED = 1772885123.0      # 7 March 2026 13:05 (UTC+1), a measured ext4 birth time


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")
    yield
    i18n.init("en")


def _uc(log_dir, extra=None):
    store = {"log_dir": str(log_dir)}
    if extra:
        store["log_dirs_extra"] = json.dumps([str(e) for e in extra])
    uc = MagicMock()
    uc.get.side_effect = lambda k: store.get(k)
    uc.set.side_effect = lambda k, v: store.update({k: v})
    return uc


def _reports(d: Path, *sizes):
    d.mkdir(parents=True, exist_ok=True)
    for i, n in enumerate(sizes):
        (d / f"bob_2026-10-{i + 1:02d}_10-00-00.log").write_bytes(b"x" * n)
    return d


# --- the rendered screen ----------------------------------------------------

class _FakeCurses:
    A_BOLD, A_REVERSE, A_NORMAL, A_DIM = 1, 2, 0, 4
    KEY_UP, KEY_DOWN, KEY_PPAGE, KEY_NPAGE, KEY_ENTER = 1001, 1002, 1003, 1004, 1005
    COLOR_BLACK, COLOR_RED, COLOR_GREEN, COLOR_YELLOW = 0, 1, 2, 3
    COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_WHITE = 4, 5, 6, 7

    class error(Exception):
        pass

    @staticmethod
    def curs_set(_n):
        return 0

    @staticmethod
    def color_pair(n):
        return n << 8

    @staticmethod
    def has_colors():
        return False


class _Screen:
    def __init__(self, keys):
        self._keys = list(keys)
        self.rows = {}

    width = 160

    def getmaxyx(self):
        return 24, self.width

    def erase(self):
        self.rows.clear()

    def addstr(self, row, col, text, attr=0):
        self.rows[row] = text

    def refresh(self):
        pass

    def getch(self):
        return self._keys.pop(0) if self._keys else ord("q")


def _render_picker(uc, width=160):
    real = sys.modules.get("curses")
    sys.modules["curses"] = _FakeCurses
    try:
        scr = _Screen([ord("q")])
        scr.width = width
        ml._dir_picker(scr, uc, SimpleNamespace(no_color=True), i18n.t)
        return "\n".join(scr.rows.values())
    finally:
        if real is not None:
            sys.modules["curses"] = real
        else:
            sys.modules.pop("curses", None)


class TestThePickerShowsSizeAndCreation:
    def test_each_directory_row_says_count_size_and_creation(self, tmp_path, monkeypatch):
        cur = _reports(tmp_path / "cur", 3000, 1_000_000, 1_100_000)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: _FIXED)
        screen = _render_picker(_uc(cur))
        row = next(line for line in screen.splitlines() if str(cur) in line)
        day = time.strftime("%Y-%m-%d", time.localtime(_FIXED))
        assert "3 report(s)" in row
        assert "2.0 MB" in row
        assert f"created {day}" in row

    def test_an_unknown_creation_is_said_unknown_not_replaced(self, tmp_path, monkeypatch):
        cur = _reports(tmp_path / "cur", 10)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: None)
        row = next(line for line in _render_picker(_uc(cur)).splitlines() if str(cur) in line)
        assert "creation date unknown" in row
        mday = time.strftime("%Y-%m-%d", time.localtime(cur.stat().st_mtime))
        assert mday not in row, "the modification date stood in for an unknown creation date"

    def test_in_french_the_date_is_written_in_french(self, tmp_path, monkeypatch):
        cur = _reports(tmp_path / "cur", 2_000_000)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: _FIXED)
        i18n.init("fr")
        row = next(line for line in _render_picker(_uc(cur)).splitlines() if str(cur) in line)
        assert "1 rapport(s)" in row and "1,9 Mo" in row
        assert "créé le 7 mars 2026" in row

    def test_the_current_tag_survives_a_narrow_screen(self, tmp_path, monkeypatch):
        """Measured in a real terminal: with the longer label, a long path pushed
        "[current]" past the right edge — it now follows the path."""
        cur = _reports(tmp_path / ("a-rather-long-directory-name-" * 2) / "cur", 10)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: _FIXED)
        width = len(str(cur)) + 20
        row = next(line for line in _render_picker(_uc(cur), width).splitlines() if str(cur) in line)
        assert "[" + i18n.t("manage_logs.current_label") + "]" in row

    def test_every_tracked_directory_has_its_own_figures(self, tmp_path, monkeypatch):
        cur = _reports(tmp_path / "cur", 5000)
        old = _reports(tmp_path / "old", 5000, 5000)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: _FIXED)
        screen = _render_picker(_uc(cur, [old]))
        assert "1 report(s), 4 KB" in next(l for l in screen.splitlines() if str(cur) in l)
        assert "2 report(s), 9 KB" in next(l for l in screen.splitlines() if str(old) in l)


# --- what the label is built from ------------------------------------------

class TestTheReportsSize:
    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory")
    def test_an_unreadable_directory_is_unreadable_not_empty(self, tmp_path, monkeypatch):
        d = _reports(tmp_path / "locked", 100)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: None)
        d.chmod(0)
        try:
            assert list(d.glob("bob_*.log")) == []      # what the former reading saw
            label = ml._dir_report_label(d, i18n.t)
        finally:
            d.chmod(0o700)
        assert label.startswith(i18n.t("manage_logs.dir_unreadable") + ", ")
        assert i18n.t("manage_logs.dir_empty") not in label

    def test_a_report_whose_size_cannot_be_read_makes_the_total_unknown(self, tmp_path, monkeypatch):
        d = _reports(tmp_path / "d", 100, 200)
        real = Path.stat
        victim = sorted(d.iterdir())[1]

        def stat(self, *a, **k):
            if self == victim:
                raise PermissionError("denied")
            return real(self, *a, **k)
        monkeypatch.setattr(Path, "stat", stat)
        assert ml._reports_size(d) == (2, None)
        monkeypatch.setattr(ml, "_dir_birth_time", lambda p: None)
        assert "size unknown" in ml._dir_report_label(d, i18n.t)

    def test_only_bob_reports_are_counted(self, tmp_path):
        d = _reports(tmp_path / "d", 1000)
        (d / "notes.txt").write_bytes(b"y" * 50_000)
        (d / "bob_report.txt").write_bytes(b"y" * 50_000)
        assert ml._reports_size(d) == (1, 1000)

    @pytest.mark.parametrize("size, en, fr", [
        (0, "0 KB", "0 Ko"), (100, "1 KB", "1 Ko"), (1024 * 1023, "1023 KB", "1023 Ko"),
        (1024 * 1024, "1.0 MB", "1,0 Mo"), (2_000_000, "1.9 MB", "1,9 Mo"),
    ])
    def test_the_size_reads_in_kb_then_mb(self, size, en, fr):
        assert ml._format_size(size, i18n.t) == en
        i18n.init("fr")
        assert ml._format_size(size, i18n.t) == fr


class TestTheBirthTime:
    def test_a_real_directory_gives_a_plausible_birth_or_none(self, tmp_path):
        """Live: the CI's filesystem may not record it; when it does, the
        directory was just created."""
        born = ml._dir_birth_time(tmp_path)
        assert born is None or abs(born - time.time()) < 3600

    def _fake_libc(self, monkeypatch, ret, mask, sec):
        def statx(fd, path, flags, want, buf):
            struct.pack_into("I", buf, 0, mask)
            struct.pack_into("q", buf, 80, sec)
            return ret

        class _Lib:
            pass
        lib = _Lib()
        lib.statx = statx
        monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: lib)

    def test_the_birth_time_is_read_when_statx_returns_it(self, tmp_path, monkeypatch):
        self._fake_libc(monkeypatch, 0, 0x7ff | 0x800, int(_FIXED))
        assert ml._dir_birth_time(tmp_path) == _FIXED

    def test_without_the_birth_time_bit_it_is_unknown(self, tmp_path, monkeypatch):
        """/proc and /sys answer without the bit: the seconds field is not a date."""
        self._fake_libc(monkeypatch, 0, 0x7ff, int(_FIXED))
        assert ml._dir_birth_time(tmp_path) is None

    def test_a_failed_statx_is_unknown(self, tmp_path, monkeypatch):
        self._fake_libc(monkeypatch, -1, 0x7ff | 0x800, int(_FIXED))
        assert ml._dir_birth_time(tmp_path) is None

    def test_a_c_library_without_statx_is_unknown(self, tmp_path, monkeypatch):
        class _NoStatx:
            pass
        monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: _NoStatx())
        assert ml._dir_birth_time(tmp_path) is None

    def test_a_zero_birth_time_is_unknown(self, tmp_path, monkeypatch):
        self._fake_libc(monkeypatch, 0, 0x800, 0)
        assert ml._dir_birth_time(tmp_path) is None


# --- the text mode ------------------------------------------------------------

def test_the_text_mode_headers_carry_the_same_figures(tmp_path, monkeypatch, capsys):
    cur = _reports(tmp_path / "cur", 3000)
    old = _reports(tmp_path / "old", 4000)
    monkeypatch.setattr(ml, "_dir_birth_time", lambda p: _FIXED)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "q")
    ml._run_manage_logs_plain(_uc(cur, [old]), SimpleNamespace(no_color=True), i18n.t)
    out = capsys.readouterr().out
    day = time.strftime("%Y-%m-%d", time.localtime(_FIXED))
    cur_line = next(l for l in out.splitlines() if str(cur) in l)
    old_line = next(l for l in out.splitlines() if str(old) in l)
    assert f"1 report(s), 2 KB, created {day}" in cur_line
    assert f"1 report(s), 3 KB, created {day}" in old_line
