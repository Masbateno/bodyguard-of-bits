"""v0.40.0 — each key in the bottom banner sits in its own cap (B-033).

The user (20 November 2026): on the plain orange banner the keys were hard to
tell apart — `⏎ choisir   1-4 par numéro   Esc retour` reads as one run of
words, worse once it wraps onto two rows. Each key is now drawn black on white
(KEYCAP), with the space on each side of it, its label left white on orange;
without colours the cap is plain video on the banner's reverse video.

The banner's text does not move: the caps are painted over the very line
0.39.0 drew, so no width, no wrap and no rule about announced keys changes.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.tui import _chrome, _keys
from tests.test_v0161_tui_palette import _FakeCurses as _PaletteCurses
from tests.test_v0163_bottom_chrome import _FakeCurses, _RecordingScreen, _declared_screens


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def _parts(actions):
    """What each cap must hold, in order, and whether it is padded: each
    navigation key tight on its glyph, then each action's glyph with a space on
    each side (the user: one cap over the whole navigation cluster read as a
    single white block)."""
    return ([(_keys._glyph(a), False) for a in actions if a in _keys.NAVIGATION]
            + [(_keys._glyph(a), True) for a in actions if a not in _keys.NAVIGATION])


def _footer_0390(t, actions, width):
    """The banner's composition as 0.39.0 shipped it — the reference the caps
    must leave untouched."""
    nav = [_keys._glyph(a) for a in actions if a in _keys.NAVIGATION]
    rest = [f"{_keys._glyph(a)} {t(_keys._label_key(a))}" for a in actions if a not in _keys.NAVIGATION]
    parts = ([" ".join(nav)] if nav else []) + rest
    sep = "   "
    first = "  " + sep.join(parts)
    if len(first) <= width or len(parts) < 2:
        return [first]
    cut = len(parts) - 1
    while cut > 1 and len("  " + sep.join(parts[:cut])) > width:
        cut -= 1
    return ["  " + sep.join(parts[:cut]), "  " + sep.join(parts[cut:])]


_WIDTHS = (40, 60, 78, 100, 140)


class TestTheCaps:
    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_each_key_has_its_own_cap(self, lang):
        i18n.init(lang)
        for screen, actions in _declared_screens().items():
            for width in _WIDTHS:
                expected = iter(_parts(actions))
                for line, caps in _keys.footer_layout(i18n.t, actions, width):
                    for k, (start, end) in enumerate(caps):
                        glyph, padded = next(expected)
                        if padded:
                            assert line[start] == " " and line[end - 1] == " ", (screen, width, line, start, end)
                            assert line[start + 1:end - 1] == glyph, (screen, width, line)
                        else:
                            assert line[start:end] == glyph, (screen, width, line)
                        if k:                            # caps never touch: an orange column between
                            assert start > caps[k - 1][1], (screen, width, line, caps)
                assert next(expected, None) is None, (screen, width, "a key without its cap")

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_text_is_the_text_it_was(self, lang):
        i18n.init(lang)
        for screen, actions in _declared_screens().items():
            for width in _WIDTHS:
                assert _keys.footer_lines(i18n.t, actions, width) == _footer_0390(i18n.t, actions, width), (
                    screen, width)


class TestTheyAreDrawn:
    def _draw(self, actions, has_color, w=100):
        scr = _RecordingScreen(24, w)
        _chrome.draw(scr, _FakeCurses, i18n.t, actions, has_color)
        return scr.writes

    def test_black_on_white_over_the_banner(self):
        from bob.tui._palette import KEYCAP
        actions = _keys.NAVIGATION + (_keys.SELECT, _keys.DELETE) + _keys.NESTED_EXIT
        writes = self._draw(actions, True)
        rows = {r: t for r, c, t, _a in writes if c == 0}
        caps = [(r, c, t, a) for r, c, t, a in writes if c > 0]
        (line, layout), = _keys.footer_layout(i18n.t, actions, 98)
        assert [(c, t) for _r, c, t, _a in caps] == [(s, line[s:e]) for s, e in layout]
        assert {a for *_rest, a in caps} == {_FakeCurses.color_pair(KEYCAP)}
        assert rows[max(rows)].rstrip() == line.rstrip()            # the row underneath unchanged

    def test_apart_without_colours(self):
        writes = self._draw(_keys.NAVIGATION + (_keys.SELECT,) + _keys.NESTED_EXIT, False)
        row_attr = {a for r, c, _t, a in writes if c == 0 and r == 23}
        cap_attr = {a for _r, c, _t, a in writes if c > 0}
        assert row_attr == {_FakeCurses.A_REVERSE} and cap_attr == {_FakeCurses.A_NORMAL}

    def test_a_cap_past_the_edge_is_cut_not_spilled(self):
        writes = self._draw(_keys.NAVIGATION + (_keys.SELECT, _keys.DELETE) + _keys.NESTED_EXIT, True, w=12)
        assert all(c + len(t) <= 11 for _r, c, t, _a in writes if c > 0)


def test_the_cap_pair_is_black_on_white():
    from bob.tui import _palette
    cur = _PaletteCurses()
    _palette.init_palette(cur)
    assert cur.pairs[_palette.KEYCAP] == (cur.COLOR_BLACK, cur.COLOR_WHITE)
