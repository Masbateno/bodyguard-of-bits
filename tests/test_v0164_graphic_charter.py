"""DOCUMENTS/CONVENTIONS.md says what a colour means. This checks it is true.

The charter was written from measurement, not memory — every rule in it was
verified against the code the day it was written. That is exactly the state a
convention is in just before it stops being true, and this project has twice
found one living in three modules that happened to agree: the curses chart
shared its cyan between the cursor row and the banner for nine releases,
because nothing compared them.

So the mechanically checkable half of the charter is checked here. The half
that is not — "violet marks what an operator can copy and run" is a judgement
about each string — stays a reading job, and the document says which is which.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PKG = _ROOT / "bob"
_DOC = _ROOT / "DOCUMENTS" / "CONVENTIONS.md"
_DOC_FR = _ROOT / "DOCUMENTS" / "CONVENTIONS_FR.md"


class TestTheCharterExists:

    @pytest.mark.parametrize("doc", [_DOC, _DOC_FR])
    def test_both_locales_carry_it(self, doc):
        assert doc.is_file(), f"{doc.name} is missing"
        text = doc.read_text(encoding="utf-8")
        assert "Cédric Clauzel" in text, "no footer"
        assert len(text.splitlines()) > 150, "too thin to be the charter"

    def test_they_link_to_each_other(self):
        assert "CONVENTIONS_FR.md" in _DOC.read_text(encoding="utf-8")
        assert "CONVENTIONS.md" in _DOC_FR.read_text(encoding="utf-8")

    @pytest.mark.parametrize("rel", ["DOCUMENTS/README_DEV.md",
                                     "DOCUMENTS/README_DEV_FR.md"])
    def test_readme_dev_points_at_it_rather_than_duplicating(self, rel):
        """The code conventions moved; a copy left behind would drift."""
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert "CONVENTIONS" in text, f"{rel} no longer points at the charter"
        assert "Snapshot / check pattern" not in text and "Pattern snapshot" not in text, (
            f"{rel} still carries the moved section — two copies will disagree"
        )


class TestColourIsDeclaredOnceAndConsumed:

    def test_no_declared_colour_is_unused(self):
        """`cyan_bold` and `violet` sat unused — declared but never consumed,
        which is a class this project has mined twice elsewhere."""
        from bob.output import _Colours
        declared = set(_Colours._fields) - {"reset"}
        elsewhere = "\n".join(p.read_text(encoding="utf-8")
                              for p in _PKG.rglob("*.py") if p.name != "output.py")
        own = (_PKG / "output.py").read_text(encoding="utf-8")
        dead = sorted(n for n in declared
                      if not re.search(rf"\.{n}\b", elsewhere)
                      and not re.search(rf"_c\.{n}\b", own))
        assert not dead, f"declared and never consumed: {dead}"

    def test_no_module_builds_its_own_escape_sequence(self):
        """The table is the authority; a literal escape bypasses --no-color."""
        offenders = []
        for path in sorted(_PKG.rglob("*.py")):
            if path.name == "output.py":
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r'"\\033\[|"\\x1b\[', line) and "#" not in line[:line.find("\\")]:
                    offenders.append(f"{path.relative_to(_ROOT)}:{n}")
        assert not offenders, (
            f"these build ANSI by hand instead of using bob.output: {offenders}"
        )

    def test_there_is_one_way_to_ask_whether_colour_is_on(self):
        """`_c` is already empty when colour is off; `_no_color` was a second
        way to ask, and print_help used it while everything else used the first.
        """
        offenders = []
        for path in sorted(_PKG.rglob("*.py")):
            if path.name == "output.py":
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\b_no_color\b", line) and not line.lstrip().startswith("#"):
                    offenders.append(f"{path.relative_to(_ROOT)}:{n}: {line.strip()[:60]}")
        assert not offenders, f"a second way to ask about colour: {offenders}"


class TestTheTwoSurfacesAgree:

    def test_violet_exists_on_both(self):
        """The charter says violet marks a command on both surfaces."""
        from bob.output import _COLOURS_ON
        from bob.tui import _palette
        assert "135" in _COLOURS_ON.violet_bold, _COLOURS_ON.violet_bold
        assert _palette.VIOLET_256 == 135, (
            "the curses violet drifted from the one the text output uses"
        )
        assert hasattr(_palette, "VERBATIM")

    def test_orange_is_the_same_orange(self):
        from bob.output import _COLOURS_ON
        from bob.tui._palette import ORANGE_256
        assert str(ORANGE_256) in _COLOURS_ON.orange, (
            "the curses orange and the text orange are different colours"
        )

    def test_curses_pairs_are_defined_in_one_place(self):
        """A guard already forbids init_pair elsewhere; this pins the count so
        a tenth pair cannot appear without the charter's table growing too."""
        from bob.tui import _palette
        pairs = {n for n in dir(_palette)
                 if n.isupper() and isinstance(getattr(_palette, n), int)
                 and not n.endswith("_256")}
        assert len(pairs) == 9, f"{len(pairs)} pairs: {sorted(pairs)}"
        doc = _DOC.read_text(encoding="utf-8")
        for name in pairs:
            assert f"`{name}`" in doc, f"pair {name} is not in the charter table"


class TestBoxesFollowOneRule:
    """Double `╔═╗` frames a top-level result; single `┌─┐` heads a section.

    Which function may draw which is a reading rule — the charter states it and
    a reviewer applies it. What is checkable is narrower and is the drift that
    would actually happen: box drawing leaking out of the presentation modules
    into the checks, and a single frame mixing both styles.
    """

    #: Modules whose job is presentation. A check module drawing its own frame
    #: is the drift; naming the roles rather than the functions keeps this from
    #: becoming a whitelist that grows every time someone adds a box.
    _PRESENTERS = {"output.py", "report.py", "report_markdown.py", "html_output.py",
                   "fixes.py", "display.py", "manage_logs.py", "breakdown.py"}

    #: Calls that put a string in front of someone.
    _OUTPUTS = {"print", "_p", "_draw", "addstr", "write", "writelines"}

    def test_no_check_module_draws_a_frame(self):
        """Drawing, not mentioning. `firmware.py` matches `^[├└]─` because that
        is what fwupd's device tree looks like — it reads those characters and
        never emits one, and a guard that cannot tell the two apart would have
        to be silenced with an exception for it."""
        offenders = []
        for path in sorted(_PKG.rglob("*.py")):
            if path.name in self._PRESENTERS:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
                if name not in self._OUTPUTS:
                    continue
                for sub in ast.walk(node):
                    if (isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                            and any(ch in sub.value for ch in "╔╚╠╣┌└┘")):
                        offenders.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
        assert not offenders, (
            f"box drawing outside the presentation modules: {sorted(set(offenders))}"
        )

    def test_no_single_frame_mixes_the_two_styles(self):
        """A frame opened with ╔ and closed with └ is neither of the two roles."""
        mixed = []
        for path in sorted(_PKG.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                body = ast.unparse(node)
                opens_double = "╔" in body
                opens_single = "┌" in body
                # A parser recognises both on purpose; it draws neither.
                draws = "print" in body or "addstr" in body or "write" in body
                if opens_double and opens_single and draws:
                    mixed.append(f"{path.name}::{node.name}")
        assert not mixed, f"these draw both frame styles: {mixed}"

    def test_the_section_header_is_the_single_rule(self):
        src = (_PKG / "output.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "print_section")
        body = ast.unparse(fn)
        assert "─" in body or "│" in body
        assert "╔" not in body, "the section header draws a summary frame"


def test_the_charter_names_the_guards_that_hold_it():
    """A charter claiming to be checked, that is not, is the defect it warns of."""
    doc = _DOC.read_text(encoding="utf-8")
    assert doc.count("*Guarded:*") >= 2, (
        "the charter no longer says which of its rules are mechanically held"
    )
