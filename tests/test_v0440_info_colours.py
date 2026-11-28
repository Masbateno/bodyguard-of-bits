"""v0.44.0 — the information lines of the wizards in colour.

Asked by the user (27 November 2026): the message closing a new scheduled
audit ("Scheduled command: …", "✔ Mail transport: …") and the journal of
--fix --apply's guards ("Witness: …", "journald sealing (FSS): not
configured …") were drawn in the screen's plain white. As CONVENTIONS.md says
for the text output: green done or in place, yellow a warning, red refused,
cyan information — and violet for a command to reproduce exactly.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from bob import _names, i18n


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


class _Verdict(SimpleNamespace):
    def __getattr__(self, _name):           # every finding absent (empty) unless given
        return []


def _witness(**kw):
    return SimpleNamespace(**{"state": "ok", "detail": "", "persistent": True, "sealed": None, **kw})


# --- the journal of --fix --apply -------------------------------------------------------

def test_the_guards_say_their_state_in_its_colour():
    from bob import fixlog
    journal = SimpleNamespace(seen=[SimpleNamespace(append_only=False)], unreadable=None)
    lines = fixlog._guards(_Verdict(witness=_witness(sealed=False), append_only_removed=False),
                           journal, i18n.t)
    kinds = [kind for _text, kind in lines]
    assert kinds == ["ok", "warn", "warn"]          # witness read; no sealing; no append-only
    assert _names.tone("journalctl --setup-keys", "verbatim") in lines[1][0]


def test_a_guard_in_place_is_green_and_its_command_violet():
    from bob import fixlog
    journal = SimpleNamespace(seen=[SimpleNamespace(append_only=True)], unreadable=None)
    lines = fixlog._guards(_Verdict(witness=_witness(sealed=True), append_only_now=True),
                           journal, i18n.t)
    assert [kind for _t, kind in lines] == ["ok", "ok", "ok"]
    assert _names.tone("journalctl --verify", "verbatim") in lines[1][0]


def test_an_empty_journal_is_information():
    from bob import fixlog
    journal = SimpleNamespace(seen=[], unreadable=None, files=[], skipped=0)
    lines = fixlog.verdict_lines(_Verdict(overall="intact", witness=_witness()), journal, i18n.t)
    assert lines[0] == (i18n.t("fixlog.verdict.empty"), "info")


def test_information_has_its_colour_on_screen():
    from bob.tui import fixlog as tfl
    from bob.tui._palette import CONTEXT_INFO

    class C:
        A_BOLD, A_NORMAL = 1, 0

        @staticmethod
        def color_pair(n):
            return n << 8

    assert tfl._attrs(C, True)["info"] == CONTEXT_INFO << 8
    assert {tfl.glyph_kind(g + " x") for g in "✔⚠✖ℹ"} == {"ok", "warn", "alert", "info"}
    assert tfl.glyph_kind("Scheduled command: bob") == "body"


def test_the_text_output_colours_information_and_commands(monkeypatch, capsys):
    from bob import __main__ as M
    from bob import fixlog, output
    codes = SimpleNamespace(red_bold="<R>", yellow_bold="<Y>", green_bold="<G>", cyan="<C>",
                            violet_bold="<V>", reset="<0>")
    monkeypatch.setattr(output, "_c", codes)
    monkeypatch.setattr(fixlog, "text_report", lambda t: (
        [("nothing yet", "info"), ("no sealing (" + _names.tone("journalctl --setup-keys", "verbatim") + ")", "warn")],
        "intact"))
    M._show_fix_journal(i18n.t)
    out = capsys.readouterr().out
    assert "<C>nothing yet<0>" in out
    assert "<Y>no sealing (<V>journalctl --setup-keys<0><Y>)<0>" in out


# --- the message closing a new scheduled audit --------------------------------------------

@pytest.mark.parametrize("key, command", [
    ("install_cron.mta_found", "bob --test-email"),
    ("install_cron.mta_missing", "bob --test-email"),
    ("install_cron.mta_missing", "--webhook URL"),
    ("install_cron.reports_nobody", "sudo bob --webhook=URL"),
    ("install_cron.reports_webhook", "bob --test-webhook --webhook=URL"),
])
def test_the_commands_of_the_messages_are_marked(key, command):
    from bob.tui import cron
    text = cron._mark_commands(i18n.t(key, mta="Postfix"))
    assert _names.tone(command, "verbatim") in text


def test_a_command_marked_whole_is_not_cut_again():
    from bob.tui import cron
    whole = _names.tone("bob --quiet --profile container --english", "verbatim")
    assert cron._mark_commands("Scheduled command: " + whole) == "Scheduled command: " + whole


class _ColourCurses:
    A_BOLD, A_NORMAL, A_REVERSE, A_DIM = 1, 0, 2, 4
    COLORS = 256

    class error(Exception):
        pass

    @staticmethod
    def has_colors():
        return True

    @staticmethod
    def color_pair(n):
        return n << 8


class _Screen:
    def __init__(self):
        self.calls = []

    def getmaxyx(self):
        return 30, 100

    def erase(self):
        pass

    def refresh(self):
        pass

    def addstr(self, row, col, text, attr=0):
        self.calls.append((text, attr))

    def addnstr(self, row, col, text, n, attr=0):
        self.addstr(row, col, text[:n], attr)

    def move(self, *_a):
        pass

    def clrtoeol(self):
        pass

    def get_wch(self):
        return "x"


def test_the_closing_message_is_drawn_in_its_colours(monkeypatch):
    from bob.tui import cron
    from bob.tui._palette import CONTEXT_INFO, VERBATIM
    monkeypatch.setitem(sys.modules, "curses", _ColourCurses)
    scr = _Screen()
    msg = (i18n.t("install_cron.audit_command",
                  command=_names.tone("bob --quiet --detailed --english", "verbatim"))
           + "\n\nℹ " + i18n.t("install_cron.mta_found", mta="Postfix"))
    cron._curses_status_flash(scr, i18n.t, msg)
    pairs = {}
    for text, attr in scr.calls:
        pairs.setdefault(attr >> 8, []).append(text)
    violet = " ".join(pairs.get(VERBATIM, []))
    cyan = " ".join(pairs.get(CONTEXT_INFO, []))
    assert "bob --quiet --detailed --english" in violet and "bob --test-email" in violet
    assert "Mail transport" in cyan       # ℹ: presence is not delivery (decided with the user)


def test_a_command_cut_by_the_wrap_stays_violet_on_both_lines():
    from bob.tui import fixlog as tfl
    first, second = tfl.carry_marks(["check with \x14bob --test-email", "--verbose\x0f now"])
    assert first.endswith("\x0f") and second.startswith("\x14")
    assert [k for _p, k in _names.segments(second)][0] == "verbatim"
