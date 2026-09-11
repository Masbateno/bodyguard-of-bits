"""v0.16.3 — one key contract, and a hint line that cannot lie.

Before this release each wizard invented its own bindings and spelled its own
hints out in English beside the dispatch. `--explain` navigated with the arrows
alone, `--manage-logs` added PgUp/PgDn, the cron screens added `j`/`k`, and none
of them had `g`/`G`. `Esc` went back in some screens and did nothing in others.
The hint line was translated in one wizard and hardcoded English in the other
two — the class v0.15.3 closed for `--help`, still open on every interactive
screen a French operator sees.

The palette lesson applied one layer up: three copies that happened to agree is
how a defect stays uniform and invisible, so the actions a screen accepts are
declared once and both the footer and the dispatch derive from that.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from bob import i18n
from bob.tui import _keys

_ROOT = Path(__file__).resolve().parent.parent
_SCREENS = ("bob/tui/cron.py", "bob/manage_logs.py", "bob/explain.py")

#: A hint line written by hand looks like this. `_keys.py` is the one place
#: allowed to spell them out, because it is where they are composed.
_HARDCODED = re.compile(
    r'"[^"]*(?:Esc:|q: quit|↑↓:|Enter:|Spc:|PgUp/PgDn:|g/G:|y: confirm)',
)


class TestNoScreenWritesItsOwnHints:

    @pytest.mark.parametrize("rel", _SCREENS)
    def test_the_hints_come_from_the_shared_module(self, rel):
        text = (_ROOT / rel).read_text(encoding="utf-8")
        offenders = [
            f"line {i}: {ln.strip()[:60]}"
            for i, ln in enumerate(text.splitlines(), 1)
            if _HARDCODED.search(ln)
        ]
        assert not offenders, (
            f"{rel} spells key hints out by hand. They drift from the dispatch "
            f"and they are not translated:\n  " + "\n  ".join(offenders[:6])
        )

    @pytest.mark.parametrize("rel", _SCREENS)
    def test_the_screen_uses_the_contract(self, rel):
        """Positive control: a file that stopped composing footers would pass
        the check above by having no hints at all."""
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert "_keys." in text, f"{rel} no longer uses the shared key contract"


def _declared_sets() -> "dict[str, tuple]":
    """Every ``_*_KEYS`` tuple the screens declare, by name."""
    import bob.explain
    import bob.manage_logs
    import bob.tui.cron

    out = {}
    for mod in (bob.tui.cron, bob.manage_logs, bob.explain):
        for name in dir(mod):
            if name.endswith("_KEYS") and isinstance(getattr(mod, name), tuple):
                out[f"{mod.__name__}.{name}"] = getattr(mod, name)
    return out


class TestEveryListOffersTheSameFloor:
    """A screen that scrolls but cannot page is a screen whose behaviour
    depends on which wizard the operator happens to be in."""

    def test_the_sweep_finds_the_screens(self):
        assert len(_declared_sets()) >= 10, _declared_sets()

    @pytest.mark.parametrize("name", sorted(_declared_sets()))
    def test_a_list_screen_declares_all_three_navigation_actions(self, name):
        actions = _declared_sets()[name]
        if _keys.MOVE not in actions:
            pytest.skip("not a list screen")
        missing = [a for a in _keys.NAVIGATION if a not in actions]
        assert not missing, f"{name} moves but cannot {missing}"

    @pytest.mark.parametrize("name", sorted(_declared_sets()))
    def test_no_screen_binds_one_key_to_two_actions(self, name):
        assert not _keys.conflicts(_declared_sets()[name])


class TestQuitOnlyOnTheFirstPage:
    """``q`` exits, and only from a wizard's landing screen: one keystroke must
    not abandon a half-entered cron job from three screens down."""

    @pytest.mark.parametrize("name", sorted(_declared_sets()))
    def test_quit_and_back_are_never_both_offered(self, name):
        actions = _declared_sets()[name]
        assert not (_keys.QUIT in actions and _keys.BACK in actions), (
            f"{name} offers both q and Esc — a screen is either a landing "
            "screen or a nested one"
        )

    @pytest.mark.parametrize("name", sorted(_declared_sets()))
    def test_the_language_switch_rides_with_quit(self, name):
        """``l`` is a landing-screen affordance too: switching language deep
        inside a wizard would redraw a half-filled form in another language."""
        actions = _declared_sets()[name]
        assert (_keys.LANG in actions) == (_keys.QUIT in actions), name

    def test_at_least_one_landing_and_one_nested_screen_exist(self):
        """Positive control for both parametrised checks above."""
        sets = _declared_sets().values()
        assert any(_keys.QUIT in a for a in sets)
        assert any(_keys.BACK in a for a in sets)


class TestTheFooterIsTranslatedAndFits:

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_every_action_has_a_label(self, lang):
        data = json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        labels = data["tui"]["keys"]
        for action in _keys._LITERAL:
            assert action in labels, f"{lang}.json has no label for {action!r}"

    @pytest.mark.parametrize("lang", ["en", "fr"])
    @pytest.mark.parametrize("name", sorted(_declared_sets()))
    def test_the_line_fits_an_eighty_column_frame(self, lang, name):
        i18n.init(lang)
        try:
            for line in _keys.footer_lines(i18n.t, _declared_sets()[name], 78):
                assert len(line) <= 78, f"{name} in {lang}: {len(line)} cols — {line}"
                assert not re.search(r"\[tui\.keys\.[a-z_]+\]", line), line
        finally:
            i18n.init("en")

    def test_the_language_label_names_the_other_language(self):
        """``l`` must advertise where it goes, not what it is."""
        i18n.init("en")
        assert i18n.t("tui.keys.lang") == "Français"
        i18n.init("fr")
        assert i18n.t("tui.keys.lang") == "English"
        i18n.init("en")

    def test_the_switch_flips_and_flips_back(self):
        i18n.init("en")

        class _Cfg:
            lang = "en"

        cfg = _Cfg()
        assert _keys.toggle_language(cfg) == "fr"
        assert cfg.lang == "fr" and i18n.t("tui.keys.back") == "retour"
        assert _keys.toggle_language(cfg) == "en"
        assert cfg.lang == "en" and i18n.t("tui.keys.back") == "back"


class TestAnAdvertisedKeyDoesSomething:
    """The sharpest one: a hint for a key nothing handles is exactly the lie
    this release removes, and it is the easy mistake now that the footer is
    generated rather than typed."""

    @staticmethod
    def _bodies() -> "dict[str, str]":
        out = {}
        for rel in _SCREENS:
            tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if isinstance(fn, ast.FunctionDef):
                    out[f"{rel}::{fn.name}"] = ast.unparse(fn)
        return out

    #: Something a dispatch must mention to be handling this action.
    _EVIDENCE = {
        _keys.MOVE:    ("KEY_UP", "_keys.MOVE"),
        _keys.PAGE:    ("KEY_PPAGE", "_keys.PAGE"),
        _keys.EDGE:    ("ord('g')", 'ord("g")', "_keys.EDGE"),
        _keys.SELECT:  ("KEY_ENTER", "_keys.SELECT"),
        _keys.CREATE:  ("KEY_ENTER", "10, 13", "_keys.CREATE"),
        _keys.BACK:    ("== 27", "_keys.BACK"),
        _keys.QUIT:    ("ord('q')", 'ord("q")', "_keys.QUIT"),
        _keys.LANG:    ("ord('l')", 'ord("l")', "_keys.LANG"),
        _keys.TOGGLE:  ("ord(' ')", 'ord(" ")', "_keys.TOGGLE"),
        _keys.DELETE:  ("ord('d')", 'ord("d")', "_keys.DELETE"),
    }

    def test_each_declared_navigation_key_is_dispatched(self):
        bodies = self._bodies()
        assert bodies, "the AST sweep found no screen functions"
        blob = "\n".join(bodies.values())
        for action in _keys.NAVIGATION:
            evidence = self._EVIDENCE[action]
            assert any(e in blob for e in evidence), (
                f"the footer advertises {action!r} on every list, and no "
                f"dispatch handles it — {evidence}"
            )

    @pytest.mark.parametrize("action", sorted(_EVIDENCE))
    def test_the_action_is_handled_somewhere(self, action):
        blob = "\n".join(self._bodies().values())
        assert any(e in blob for e in self._EVIDENCE[action]), action


#: Where each screen sits. Explicit rather than inferred: the action tuple
#: alone cannot say, and a nested screen quietly promoted to LANDING_EXIT would
#: reintroduce "one keystroke abandons everything from three screens down"
#: without any test noticing. Adding a screen means classifying it here.
_LANDING = {
    "bob.explain._FAMILY_KEYS",
    "bob.manage_logs._LIST_KEYS",
    "bob.manage_logs._MARKED_KEYS",
    "bob.tui.cron._LANDING_KEYS",
    "bob.tui.cron._MANAGE_KEYS",
}
_NESTED = {
    "bob.explain._DETAIL_KEYS",
    "bob.explain._VERSION_KEYS",
    "bob.explain._KEY_PICKER_KEYS",
    "bob.manage_logs._PREVIEW_KEYS",
    "bob.tui.cron._SCHEDULE_KEYS",
    "bob.tui.cron._CONFIRM_KEYS",
    "bob.tui.cron._INPUT_KEYS",
    "bob.tui.cron._EMAIL_KEYS",
    "bob.tui.cron._STORE_KEYS",
    "bob.tui.cron._EDIT_KEYS",
    "bob.tui.cron._CHOICE_KEYS",
}


class TestEachScreenSitsWhereItSaysItDoes:

    def test_the_inventory_covers_every_declared_screen(self):
        """Positive control: a new screen must be classified, not defaulted."""
        unknown = sorted(set(_declared_sets()) - _LANDING - _NESTED)
        assert not unknown, (
            f"these screens are in neither inventory: {unknown}. Say whether "
            "each is a wizard's first page (q and l) or nested (Esc)."
        )

    @pytest.mark.parametrize("name", sorted(_LANDING))
    def test_a_landing_screen_offers_q_and_l(self, name):
        actions = _declared_sets()[name]
        assert _keys.QUIT in actions and _keys.LANG in actions, name
        assert _keys.BACK not in actions, name

    @pytest.mark.parametrize("name", sorted(_NESTED))
    def test_a_nested_screen_offers_esc_and_neither_q_nor_l(self, name):
        actions = _declared_sets()[name]
        assert _keys.BACK in actions, name
        assert _keys.QUIT not in actions and _keys.LANG not in actions, (
            f"{name} is nested: q would abandon everything entered above it, "
            "and switching language would redraw a half-filled form"
        )


class TestTheContractIsInternallyConsistent:
    """The footer is composed from ``_GLYPH`` and the dispatch from the key
    tables. If they disagree, the line advertises a key nothing is bound to —
    the exact lie this release removes, one level below the screens."""

    def test_every_glyph_has_a_binding(self):
        import curses

        missing = [
            action for action in _keys._GLYPH
            if not _keys._LITERAL.get(action) and not _keys._special(curses, action)
        ]
        assert not missing, (
            f"{missing} appear in the footer with no key bound to them"
        )

    def test_every_binding_has_a_glyph(self):
        """The other direction: a key that works but is never advertised is a
        feature only the source reveals."""
        missing = sorted(set(_keys._LITERAL) - set(_keys._GLYPH))
        assert not missing, f"{missing} are bound but never shown"

    def test_every_action_resolves_to_itself(self):
        """Round-trip: pressing an action's key must resolve to that action."""
        import curses

        for action, codes in _keys._LITERAL.items():
            for code in codes:
                assert _keys.resolve(curses, code, (action,)) == action, (action, code)

    def test_an_unbound_key_resolves_to_nothing(self):
        """Polarity: resolve must not answer yes to everything."""
        import curses

        assert _keys.resolve(curses, ord("z"), _keys.NAVIGATION) is None

#: Which declared set belongs to which screen function. Needed because the
#: reverse check below reads a function body and must know what that screen
#: promised.
_SCREEN_OF = {
    "bob/tui/cron.py::_run_manage_cron_curses":   "bob.tui.cron._MANAGE_KEYS",
    "bob/tui/cron.py::_curses_email_list_sub":    "bob.tui.cron._EMAIL_KEYS",
    "bob/tui/cron.py::_curses_email_store_sub":   "bob.tui.cron._STORE_KEYS",
    "bob/manage_logs.py::_run_manage_logs_curses": "bob.manage_logs._LIST_KEYS",
    "bob/manage_logs.py::_curses_preview_log":    "bob.manage_logs._PREVIEW_KEYS",
    "bob/explain.py::_family_picker":              "bob.explain._FAMILY_KEYS",
    "bob/explain.py::_version_picker":             "bob.explain._VERSION_KEYS",
    "bob/explain.py::_key_picker":                 "bob.explain._KEY_PICKER_KEYS",
    "bob/explain.py::_detail_screen":             "bob.explain._DETAIL_KEYS",
}


class TestAScreenNeverActsOnAKeyItDoesNotAdvertise:
    """The mirror of "an advertised key does something", and the one that was
    missing: ``--manage-cron`` dispatched Space, ``a`` and ``m`` while
    declaring none of them, so the screen marked entries, selected them all and
    opened the address book without ever saying so. A key that works in secret
    is discoverable only by reading the source.
    """

    #: The literal a dispatch uses, per action. Only actions whose key is a
    #: plain character are checked — the arrows and Enter are shared by every
    #: screen and carry no per-screen meaning.
    #: Written with single quotes because ``ast.unparse`` normalises string
    #: literals to them — the first version of this table used double quotes,
    #: matched nothing, and reported a clean bill on a screen dispatching three
    #: undeclared keys.
    _LITERALS = {
        "ord(' ')": _keys.TOGGLE,
        "ord('a')": _keys.ALL,
        "ord('u')": _keys.UNMARK,
        "ord('d')": _keys.DELETE,
        "ord('c')": _keys.CHANGE,
        "ord('s')": _keys.SUMMARY,
        "ord('m')": _keys.BOOK,
        "ord('n')": _keys.NEW,
        "ord('q')": _keys.QUIT,
        "ord('l')": _keys.LANG,
    }

    @pytest.mark.parametrize("where", sorted(_SCREEN_OF))
    def test_every_key_the_screen_handles_is_declared(self, where):
        rel, fn_name = where.split("::")
        tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
        fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == fn_name), None)
        assert fn is not None, f"{where} no longer exists"
        body = ast.unparse(fn)

        declared = set(_declared_sets()[_SCREEN_OF[where]])
        # UNMARK is offered only once something is marked; the screen may hold
        # its dispatch unconditionally, so accept it wherever TOGGLE is.
        if _keys.TOGGLE in declared:
            declared.add(_keys.UNMARK)

        undeclared = sorted(
            action for literal, action in self._LITERALS.items()
            if literal in body and action not in declared
        )
        assert not undeclared, (
            f"{where} acts on {undeclared} without advertising them — the "
            "footer is composed from the declared set, so the operator has no "
            "way to learn these exist"
        )

    def test_the_sweep_reads_real_functions(self):
        """Positive control: a typo in the inventory would pass every case."""
        for where in _SCREEN_OF:
            rel, fn_name = where.split("::")
            tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
            assert any(isinstance(n, ast.FunctionDef) and n.name == fn_name
                       for n in ast.walk(tree)), where


class TestAMarkedRowLooksTheSameEverywhere:
    """A toggled row was red bold in --manage-logs, yellow in --manage-cron and
    uncoloured in both e-mail screens. On three of those four a mark is a
    pending destructive selection."""

    @staticmethod
    def _marked_branches(rel: str) -> "list[tuple[int, str]]":
        """Every branch guarded on "this row is marked", with its body.

        AST rather than a line window: the first version of this guard looked
        three lines around any mention of a mark and flagged the *else*
        branches beside it — the presence-in-a-neighbourhood pattern that has
        produced a false report in this project more than once.
        """
        tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test = ast.unparse(node.test)
            if not re.search(r"\bis_marked\b|\b_is_marked\b", test):
                continue
            out.append((node.lineno, "\n".join(ast.unparse(x) for x in node.body)))
        return out

    @pytest.mark.parametrize("rel", ["bob/tui/cron.py", "bob/manage_logs.py"])
    def test_the_sweep_finds_the_marked_branches(self, rel):
        """Positive control: a guard over nothing passes for ever."""
        assert self._marked_branches(rel), f"{rel} has no marked-row branch"

    @pytest.mark.parametrize("rel", ["bob/tui/cron.py", "bob/manage_logs.py"])
    def test_no_screen_colours_a_mark_by_hand(self, rel):
        offenders = [
            f"line {ln}: {body.splitlines()[0][:60]}"
            for ln, body in self._marked_branches(rel)
            if "color_pair" in body and "marked_attr" not in body
        ]
        assert not offenders, (
            f"{rel} picks the colour for a marked row itself: " + "; ".join(offenders)
        )

    @pytest.mark.parametrize("rel", ["bob/tui/cron.py", "bob/manage_logs.py"])
    def test_the_screen_uses_the_shared_attribute(self, rel):
        assert "marked_attr" in (_ROOT / rel).read_text(encoding="utf-8"), rel

    def test_the_mark_is_red_and_bold_with_colour(self):
        from bob.tui._palette import NOTICE, marked_attr

        class _C:
            A_BOLD, A_UNDERLINE = 1 << 8, 1 << 9

            @staticmethod
            def color_pair(n):
                return n

        assert marked_attr(_C, True) == (NOTICE | _C.A_BOLD)

    def test_it_falls_back_to_underline_without_colour(self):
        """Reverse video is spent on the cursor, so a mark needs its own mark."""
        from bob.tui._palette import marked_attr

        class _C:
            A_BOLD, A_UNDERLINE = 1 << 8, 1 << 9

            @staticmethod
            def color_pair(n):
                return n

        assert marked_attr(_C, False) == _C.A_UNDERLINE
