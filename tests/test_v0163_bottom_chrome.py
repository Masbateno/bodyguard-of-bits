"""v0.16.3 — the bottom of every wizard is two bands, and nothing overwrites them.

The key hints were plain accent-coloured text on the last row, and two screens
painted over that row:

  * ``--manage-logs`` replaced the whole key line with its delete confirmation,
    so the operator was asked to confirm a destructive action on a screen that
    had just hidden every key, the one to cancel included;
  * ``--install-cron`` and ``--manage-cron`` drew each text prompt at ``h - 1``,
    directly on top of the footer they had just drawn — seven prompts did this.

One row was doing two jobs. It is two bands now: a reserved line for prompts
and status, and under it an orange key banner mirroring the cyan header.

Three things are worth guarding and one is not. The colours and the row
arithmetic are exact and are checked against a recording stdscr. That no screen
sizes its body with a hard ``h - 2`` any more is static, because that constant
was already one short whenever the hints wrapped — the second banner row landed
on the body's last line and hid an entry. That no prompt is drawn on the banner
row is static too, and it is the regression that would silently return.

What is *not* guarded here is how it looks; that was read off a real pty with
pyte, which is not a test dependency.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_WIZARDS = {
    "explain":     _ROOT / "bob" / "explain.py",
    "manage_logs": _ROOT / "bob" / "manage_logs.py",
    "cron":        _ROOT / "bob" / "tui" / "cron.py",
}


# ---------------------------------------------------------------------------
# A recording screen and a curses stand-in, so the geometry is exact
# ---------------------------------------------------------------------------

class _FakeCurses:
    A_BOLD = 1 << 0
    A_REVERSE = 1 << 1
    A_NORMAL = 0
    error = RuntimeError

    @staticmethod
    def color_pair(n: int) -> int:
        return n << 8


class _RecordingScreen:
    def __init__(self, h: int = 24, w: int = 100):
        self._h, self._w = h, w
        self.writes: list[tuple[int, int, str, int]] = []

    def getmaxyx(self):
        return self._h, self._w

    def addstr(self, row, col, text, attr=0):
        if row >= self._h or row < 0:
            raise _FakeCurses.error("out of bounds")
        self.writes.append((row, col, text, attr))


def _draw(actions, *, context="", h=24, w=100, has_color=True):
    from bob.tui import _chrome
    from bob import i18n
    scr = _RecordingScreen(h, w)
    _chrome.draw(scr, _FakeCurses, i18n.t, actions, has_color, context=context)
    return scr.writes


class TestTheGeometry:

    def test_the_banner_sits_on_the_last_rows(self):
        from bob.tui import _keys
        writes = _draw(_keys.NAVIGATION + (_keys.QUIT,))
        rows = sorted(r for r, _, _, _ in writes)
        assert rows[-1] == 23, f"the banner does not reach the bottom row: {rows}"

    def test_the_context_line_sits_directly_above_the_banner(self):
        from bob.tui import _chrome, _keys
        actions = _keys.NAVIGATION + (_keys.QUIT,)
        writes = _draw(actions, context="  are you sure?")
        ctx = [(r, txt) for r, _, txt, _ in writes if "are you sure?" in txt]
        assert len(ctx) == 1, f"the context text was not drawn exactly once: {ctx}"
        n_banner = len(_chrome.banner_lines(__import__("bob.i18n", fromlist=["t"]).t,
                                            actions, 100))
        assert ctx[0][0] == 24 - 1 - n_banner, (
            f"the context line is at row {ctx[0][0]}, not directly above the "
            f"{n_banner}-row banner"
        )

    def test_the_context_line_is_reserved_even_when_empty(self):
        """A line that appears and disappears moves the banner under the eye."""
        from bob.tui import _keys
        blank = _draw(_keys.NAVIGATION + (_keys.QUIT,))
        filled = _draw(_keys.NAVIGATION + (_keys.QUIT,), context="  hello")
        assert len(blank) == len(filled), (
            "the chrome changes height depending on whether there is a message"
        )

    def test_every_chrome_row_is_padded_to_the_full_width(self):
        from bob.tui import _keys
        for _, _, text, _ in _draw(_keys.NAVIGATION + (_keys.QUIT,), w=100):
            assert len(text) == 99, f"row not padded to the width: {len(text)}"

    def test_chrome_height_matches_what_draw_actually_paints(self):
        from bob.tui import _chrome, _keys
        from bob import i18n
        for actions in (_keys.NAVIGATION + (_keys.QUIT,),
                        _keys.NAVIGATION + (_keys.TOGGLE, _keys.ALL, _keys.DELETE,
                                            _keys.CHANGE, _keys.LANG, _keys.QUIT)):
            for w in (80, 100, 200):
                painted = len({r for r, _, _, _ in _draw(actions, w=w)})
                assert painted == _chrome.chrome_height(i18n.t, actions, w), (
                    f"chrome_height disagrees with draw() at width {w}"
                )


class TestTheColours:

    def test_the_banner_is_white_on_orange_and_the_line_above_it_is_black(self):
        from bob.tui import _keys
        from bob.tui._palette import CONTEXT, FOOTER
        writes = _draw(_keys.NAVIGATION + (_keys.QUIT,), context="  x")
        by_row = {r: attr for r, _, _, attr in writes}
        bottom = max(by_row)
        assert by_row[bottom] == _FakeCurses.color_pair(FOOTER) | _FakeCurses.A_BOLD
        assert by_row[min(by_row)] == _FakeCurses.color_pair(CONTEXT)

    def test_a_monochrome_terminal_still_separates_the_bands(self):
        from bob.tui import _keys
        writes = _draw(_keys.NAVIGATION + (_keys.QUIT,), context="  x", has_color=False)
        by_row = {r: attr for r, _, _, attr in writes}
        assert by_row[max(by_row)] == _FakeCurses.A_REVERSE, "the banner loses its band"
        assert by_row[min(by_row)] == _FakeCurses.A_NORMAL


class TestNothingIsTruncatedAway:

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_exit_hint_survives_on_a_narrow_terminal(self, lang):
        """80 columns, French: five screens overflow, one to 106 characters.

        Truncating cuts from the right, which is where the exit hint sits — the
        one an operator cannot guess.
        """
        from bob import i18n
        from bob.tui import _chrome, _keys
        i18n.init(lang)
        try:
            for screen, actions in _declared_screens().items():
                exit_actions = [a for a in actions if a in (_keys.QUIT, _keys.BACK)]
                if not exit_actions:
                    continue
                painted = " ".join(_chrome.banner_lines(i18n.t, actions, 80))
                for act in exit_actions:
                    label = i18n.t("tui.keys." + act)
                    assert label in painted, (
                        f"{lang}/{screen}: the {act} hint ({label!r}) is not on "
                        f"the banner at 80 columns"
                    )
        finally:
            i18n.init("en")


def _declared_screens() -> dict:
    import bob.explain as ex
    import bob.manage_logs as ml
    import bob.tui.cron as cr
    out = {}
    for mod in (ex, ml, cr):
        for name in dir(mod):
            if name.endswith("_KEYS"):
                value = getattr(mod, name)
                if isinstance(value, tuple):
                    out[f"{mod.__name__}.{name}"] = value
    return out


# ---------------------------------------------------------------------------
# Static: no screen may go back to a hard height, or to prompting on the banner
# ---------------------------------------------------------------------------

class TestNoScreenPaintsOverItsOwnBanner:

    @pytest.mark.parametrize("name", sorted(_WIZARDS))
    def test_no_body_is_sized_with_a_hard_constant(self, name):
        """`h - 2` was already one short whenever the hints wrapped.

        Matched on the assignment itself rather than on any line mentioning
        the name: the first version of this flagged `scroll = cur_item_pos -
        body_h + 1`, which is scroll arithmetic and not a height at all.
        """
        tree = ast.parse(_WIZARDS[name].read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if not names & {"body_h", "list_h"}:
                continue
            if "chrome_height" not in ast.unparse(node.value):
                offenders.append(ast.unparse(node))
        assert not offenders, (
            f"{name}: body sized without the real chrome height: {offenders}"
        )

    @pytest.mark.parametrize("name", sorted(_WIZARDS))
    def test_no_prompt_is_drawn_on_the_bottom_row(self, name):
        """Seven prompts were drawn at ``h - 1``, erasing the keys they needed."""
        tree = ast.parse(_WIZARDS[name].read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if "readline" not in fname and "input" not in fname:
                continue
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and ast.unparse(arg) in ("h - 1", "h-1"):
                    offenders.append(f"{fname}(... {ast.unparse(arg)} ...)")
        assert not offenders, (
            f"{name}: prompt drawn on the banner row: {offenders}"
        )


# ---------------------------------------------------------------------------
# An input screen must show its keys, and must not be written in English
# ---------------------------------------------------------------------------

class TestEveryInputScreenShowsItsKeys:

    def test_the_input_helper_draws_its_own_chrome(self):
        """`--install-cron`'s name entry erased, drew a prompt, and read a line.

        It never drew a footer, so the screen asking an operator to type a name
        showed no key hints at all — not even Esc. The caller used to pass a
        row and be trusted to draw the banner itself; the helper takes the
        screen's actions and draws the banner now, which makes forgetting it
        unrepresentable rather than merely unlikely.
        """
        src = (_ROOT / "bob" / "tui" / "cron.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_curses_readline")
        params = [a.arg for a in fn.args.args]
        assert "row" not in params, (
            "_curses_readline takes a row again — the caller can once more draw "
            "the prompt without a banner"
        )
        assert "actions" in params, "_curses_readline cannot draw a banner it is not given"
        body = ast.unparse(fn)
        assert "_chrome.draw" in body, "the input helper no longer paints the chrome"

    def test_a_text_input_declares_the_key_that_submits_it(self):
        """Enter was dispatched by every input and declared by none.

        The banner offered `Esc back` alone, so the only advertised way out of
        a text field was to abandon it.
        """
        import bob.tui.cron as cron
        from bob.tui import _keys
        assert _keys.SUBMIT in cron._INPUT_KEYS, (
            "an input screen advertises no way to submit what was typed"
        )
        assert _keys.BACK in cron._INPUT_KEYS


class TestTheCronScreensAreTranslated:
    """v0.16.3 closed English-in-the-wizards everywhere except these.

    Nineteen literals survived the pass — every text prompt (`Email`, `Name`,
    `Time (HH:MM)`), the inline hints under them, the address-book screen and
    its statuses. A French operator drove a French wizard and typed into
    English fields.
    """

    _SOURCE = _ROOT / "bob" / "tui" / "cron.py"

    @staticmethod
    def _screen_literals() -> list[tuple[int, str]]:
        """String constants that reach the screen, not keys or docstrings."""
        src = TestTheCronScreensAreTranslated._SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(src)
        lines = src.splitlines()
        drawing = ("_draw", "addstr", "_curses_readline", "_curses_input",
                   "_curses_status_flash")
        # Constants living inside a t(...) call are interpolation values, not
        # screen prose: `t("...mta_found", mta=_name or "sendmail")` passes a
        # program name. Excluding them by rule rather than by whitelisting
        # "sendmail", which is how a guard starts being maintained by widening.
        translated = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (
                    getattr(node.func, "id", "") == "t"
                    or getattr(node.func, "attr", "") == "t"):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant):
                        translated.add(id(sub))

        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if fname not in drawing:
                continue
            for arg in ast.walk(node):
                if id(arg) in translated:
                    continue
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    continue
                text = arg.value
                # A locale key path, a format placeholder or punctuation is fine.
                if not any(c.isalpha() for c in text):
                    continue
                if "." in text and " " not in text:
                    continue
                if text.strip() in ("str | None", "list[str]"):
                    continue
                # The command name itself is not prose.
                if text.strip().startswith("bob "):
                    continue
                if len(text.strip()) < 4:
                    continue
                found.append((arg.lineno, text))
        return found

    def test_no_english_prose_is_drawn_on_a_cron_screen(self):
        offenders = self._screen_literals()
        assert not offenders, (
            f"{len(offenders)} untranslated literal(s) drawn on a cron screen: "
            f"{offenders[:6]}"
        )

    def test_the_harness_would_notice_one(self):
        """A scraper that finds nothing passes forever."""
        import ast as _ast
        sample = _ast.parse('_draw(stdscr, 2, 2, "Add email address")')
        found = [
            n.value for n in _ast.walk(sample)
            if isinstance(n, _ast.Constant) and isinstance(n.value, str)
            and len(n.value) > 4 and any(c.isalpha() for c in n.value)
        ]
        assert "Add email address" in found, "the literal scraper is broken"

    @pytest.mark.parametrize("key", [
        "cron_ui.field_name", "cron_ui.field_email", "cron_ui.field_time",
        "cron_ui.field_days", "cron_ui.field_expression", "cron_ui.prompt_sep",
        "cron_ui.press_any_key", "cron_ui.add_email_title", "tui.keys.submit",
    ])
    def test_both_locales_carry_the_new_keys(self, key):
        import json
        for lang in ("en", "fr"):
            data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json")
                              .read_text(encoding="utf-8"))
            node = data
            for part in key.split("."):
                assert part in node, f"{lang}.json is missing {key}"
                node = node[part]
            assert isinstance(node, str) and node.strip(), f"{lang}.json: {key} is empty"

    def test_french_puts_a_space_before_its_colon(self):
        """`Nom: nightly` is not French; the separator is a translation."""
        import json
        seps = {}
        for lang in ("en", "fr"):
            data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json")
                              .read_text(encoding="utf-8"))
            seps[lang] = data["cron_ui"]["prompt_sep"]
        assert seps["fr"].startswith(" "), f"French separator is {seps['fr']!r}"
        assert not seps["en"].startswith(" "), f"English separator is {seps['en']!r}"


class TestAToggleAdvertisesWhereItGoes:
    """`s summary` stayed on the banner while the summary was already showing.

    It is a toggle: `s` switches to the condensed view, and `s` again returns
    to the whole log. The banner named only the first direction, so an operator
    reading the summary was told they could press `s` to get the summary.

    Hiding the hint in that mode was the other candidate fix and is the wrong
    one: `s` still works there, and a screen that acts on a key it does not
    advertise is the defect this release closed everywhere else.
    """

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_label_follows_the_mode(self, lang):
        from bob import i18n
        from bob.tui import _keys
        import bob.manage_logs as ml
        i18n.init(lang)
        try:
            full = _keys.footer_lines(i18n.t, ml._preview_keys("full"), 200)[0]
            summ = _keys.footer_lines(i18n.t, ml._preview_keys("summary"), 200)[0]
            assert full != summ, "the banner reads the same in both modes"
            assert i18n.t("tui.keys.summary") in full
            assert i18n.t("tui.keys.full") in summ
            assert i18n.t("tui.keys.summary") not in summ, (
                "the summary view still offers to show the summary"
            )
        finally:
            i18n.init("en")

    def test_the_key_stays_advertised_in_both_modes(self):
        """Whatever it is called, `s` must appear — it does something."""
        from bob.tui import _keys
        import bob.manage_logs as ml
        for mode in ("full", "summary"):
            actions = ml._preview_keys(mode)
            glyphs = {_keys._GLYPH[a] for a in actions}
            assert "s" in glyphs, f"{mode}: `s` is dispatched but not advertised"

    def test_the_two_directions_never_share_a_screen(self):
        """Both bind `s`; declaring both at once would be a real conflict."""
        from bob.tui import _keys
        import bob.manage_logs as ml
        for mode in ("full", "summary"):
            assert not _keys.conflicts(ml._preview_keys(mode)), mode
