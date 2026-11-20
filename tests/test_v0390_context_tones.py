"""v0.39.0 — the context line says what a message means by its colour.

Decided with the user (17 November 2026): the line above the key banner — the
one every wizard keeps for prompts and status — takes the colour of what it
says, matching both tables of DOCUMENTS/CONVENTIONS.md:

- a prompt or a question waiting for an answer: yellow (curses: ACCENT is
  "group headers, prompts");
- an action that took effect: green, ✔ (text output: green is an OK finding);
- an action refused or failed, nothing changed: red, ✖ (text output: red is an
  alert — yellow would read as a prompt here);
- information (an action cancelled): cyan, ℹ (text output: cyan).

Found doing it: --manage-cron's address book, its store and its job list drew
their messages and the delete confirmation on the bottom row, replacing the
key banner; --manage-logs drew "forget this folder?" and "move N reports?"
there too. Since 0.16.3 nothing covers the banner: they are on the context
line now.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from bob.tui import _chrome, _palette

ROOT = Path(__file__).resolve().parent.parent


class _Curses:
    A_NORMAL, A_BOLD, A_REVERSE = 0, 1, 2
    COLOR_BLACK, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_CYAN, COLOR_WHITE, COLOR_MAGENTA = 0, 1, 2, 3, 6, 7, 5
    COLORS = 256
    error = RuntimeError

    def __init__(self):
        self.pairs = {}

    @staticmethod
    def color_pair(n):
        return n << 8

    def init_pair(self, n, fg, bg):
        self.pairs[n] = (fg, bg)

    def has_colors(self):
        return True

    def start_color(self):
        pass

    def use_default_colors(self):
        pass


class _Screen:
    def __init__(self, h=24, w=80):
        self.h, self.w = h, w
        self.rows = {}

    def getmaxyx(self):
        return self.h, self.w

    def addstr(self, row, col, text, attr=0):
        self.rows[row] = (text, attr)


@pytest.mark.parametrize("text, tone", [
    ("  ✔ Note 1 added.", "ok"), ("✖ a purge needs a reason", "error"),
    ("ℹ Cancelled.", "info"), ("plain words", ""), ("", ""),
])
def test_the_glyph_gives_the_tone(text, tone):
    assert _chrome.tone_of(text) == tone


def test_the_builders_carry_the_text_output_glyphs():
    assert (_chrome.done("x"), _chrome.refused("x"), _chrome.info("x")) == ("✔ x", "✖ x", "ℹ x")


@pytest.mark.parametrize("context, tone, pair", [
    ("  ✔ done", None, _palette.CONTEXT_OK),
    ("  ✖ refused", None, _palette.CONTEXT_ERROR),
    ("  ℹ cancelled", None, _palette.CONTEXT_INFO),
    ("  New note: ", _chrome.PROMPT, _palette.CONTEXT_PROMPT),
    ("", None, _palette.CONTEXT),
])
def test_the_context_line_is_drawn_in_its_tone(context, tone, pair):
    scr, cur = _Screen(), _Curses()
    _chrome.draw_text(scr, cur, True, ["  keys"], context=context, tone=tone)
    text, attr = scr.rows[scr.h - 2]
    assert attr & ~_Curses.A_BOLD == cur.color_pair(pair)
    assert scr.rows[scr.h - 1][0].startswith("  keys")          # the banner, untouched


def test_the_palette_puts_each_tone_on_the_context_line_black():
    cur = _Curses()
    _palette.init_palette(cur)
    expect = {_palette.CONTEXT_PROMPT: cur.COLOR_YELLOW, _palette.CONTEXT_OK: cur.COLOR_GREEN,
              _palette.CONTEXT_ERROR: cur.COLOR_RED, _palette.CONTEXT_INFO: cur.COLOR_CYAN}
    for pair, fg in expect.items():
        assert cur.pairs[pair] == (fg, cur.COLOR_BLACK)
    assert cur.pairs[_palette.CONTEXT] == (cur.COLOR_WHITE, cur.COLOR_BLACK)


def _status_values(rel: str) -> "list[str]":
    """Every non-empty value assigned to a ``status`` variable in *rel*."""
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(tg, ast.Name) and tg.id == "status" for tg in node.targets):
            src = ast.get_source_segment((ROOT / rel).read_text(encoding="utf-8"), node.value)
            if src not in ('""', "''"):
                out.append(src)
    return out


@pytest.mark.parametrize("rel", ["bob/manage_logs.py", "bob/tui/cron.py"])
def test_every_status_says_what_it_means(rel):
    """A status with no glyph would be drawn white: neither done, refused nor
    information. Each one is built with its glyph, or comes from a function
    that builds it (the notes' actions)."""
    plain = [v for v in _status_values(rel)
             if not re.match(r"""^(_ch(rome)?\.(done|refused|info)\(|f["'][✔✖ℹ] |_notes_action\()""", v)]
    assert plain == [], plain


@pytest.mark.parametrize("rel", ["bob/manage_logs.py", "bob/tui/cron.py", "bob/explain.py"])
def test_nothing_is_drawn_over_the_key_banner(rel):
    """The bottom row belongs to the key banner (bob/tui/_chrome.py)."""
    src = (ROOT / rel).read_text(encoding="utf-8")
    # Any argument position: cron writes `_draw(stdscr, h - 1, 0, …)` (the first
    # version of this pattern wanted "(h - 1, 0" and missed it — its mutation
    # survived).
    assert not re.search(r"[(,]\s*h\s*-\s*1\s*,\s*0\b", src), "a write on the banner's row"


def test_prompts_are_drawn_as_prompts():
    ml = (ROOT / "bob/manage_logs.py").read_text(encoding="utf-8")
    cron = (ROOT / "bob/tui/cron.py").read_text(encoding="utf-8")
    assert ml.count("_prompt_attr(curses)") >= 1            # text input
    # v0.39.0 — both confirmations of --manage-logs ask through the shared one,
    # which draws in the prompts' tone (test_a_confirmation_is_asked_…).
    assert ml.count("_chrome.ask_confirm(stdscr, curses, t, ") == 2
    assert "context=display, tone=_chrome.PROMPT" in cron    # cron's text input
    assert "tone=_chrome.PROMPT)" in cron                    # cron's delete confirmation
    assert "_tone = _ch.PROMPT" in ml                        # report list's delete confirmation


def test_a_prompt_is_in_the_prompts_colour():
    import bob.manage_logs as ml
    cur = _Curses()
    assert ml._prompt_attr(cur) == cur.color_pair(_palette.CONTEXT_PROMPT) | cur.A_BOLD
