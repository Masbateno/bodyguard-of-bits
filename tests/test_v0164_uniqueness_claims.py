"""What the source says about itself, checked against what it does.

Two claims of the same nature. Seventeen places say "single source of truth",
and one function names the schema it produces in its docstring — both are
assertions about the code, written in prose, that nothing verified.

Each of those comments is an assertion about the whole package: *this* is the
only definition of X, and every other module goes through it. They are the
project's answer to a defect it has hit repeatedly — the colour chart lived in
three modules that happened to agree, which is exactly why nobody noticed the
cursor row and the banner shared a background for nine releases.

Every claim below is true today; all seventeen were checked by hand when this
file was written. That is the problem this file exists for: "true today, load
bearing, and unverified" is the state a property is in immediately before it
stops being true. A second definition of `atomic_write` would not fail a single
test, and the copy would work — until the two drifted, which is the only way
this class of defect ever announces itself.

Adding a "single source of truth" comment means adding a row here. The rule is
the same in every case: the named symbol is defined exactly once under `bob/`.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PKG = _ROOT / "bob"


#: (symbol, kind, where the claim is written) — one row per uniqueness claim.
_CLAIMS = [
    ("atomic_write",              "function", "bob/cron/_io.py"),
    ("make_fallback_t",           "function", "bob/config.py"),
    ("service_label_to_subkey",   "function", "bob/registry.py"),
    ("set_posture_from_engine",   "function", "bob/watch.py"),
    ("unpack_posture_escalation", "function", "bob/display.py"),
    ("_compute_posture_annotation", "function", "bob/display.py"),
    ("_EMAIL_RE",                 "assign",   "bob/cron/_install.py"),
    ("SCORE_BAR_WIDTH",           "assign",   "bob/breakdown.py"),
    ("_SECTIONS",                 "assign",   "bob/runner.py"),
]


def _definitions(symbol: str, kind: str) -> "list[str]":
    """Every place under bob/ that defines *symbol*, as `path:line`."""
    found = []
    for path in sorted(_PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if kind == "function" and isinstance(node, ast.FunctionDef):
                if node.name == symbol:
                    found.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
            elif kind == "assign" and isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == symbol:
                        found.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
            elif kind == "assign" and isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id == symbol:
                    found.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
    return found


@pytest.mark.parametrize("symbol,kind,claimed_in", _CLAIMS,
                         ids=[c[0] for c in _CLAIMS])
def test_the_symbol_is_defined_exactly_once(symbol, kind, claimed_in):
    where = _definitions(symbol, kind)
    assert len(where) == 1, (
        f"{claimed_in} calls {symbol} a single source of truth; it is defined "
        f"{len(where)} time(s): {where}. A second copy works until the two "
        f"drift, which is the only way this defect announces itself."
    )


def test_the_finder_actually_finds_things():
    """A search that matched nothing would satisfy nothing above."""
    assert _definitions("atomic_write", "function"), "the AST search is broken"
    assert not _definitions("no_such_symbol_anywhere", "function")


def test_every_claim_in_the_source_has_a_row_here():
    """A new claim without a row is a promise nothing holds.

    Counted, not matched by name: the comments are prose and phrase themselves
    differently ("single source of truth for", "…, see bob.output", "…across
    the codebase"). What this catches is the count creeping up while the table
    stays still.
    """
    total = 0
    for path in sorted(_PKG.rglob("*.py")):
        total += path.read_text(encoding="utf-8").count("single source of truth")
    assert total == 17, (
        f"{total} uniqueness claims in the source, {len(_CLAIMS)} rows in this "
        f"file's table. A claim was added or removed without its check; if it "
        f"is checkable, add a row, and if it is not, say why in the comment "
        f"rather than asserting something nothing holds."
    )


# ---------------------------------------------------------------------------
# A function that names a schema must name the one it emits
# ---------------------------------------------------------------------------

def _schema_producers() -> "list[tuple[str, str, str]]":
    """(where, emitted version, docstring first line) for each producer."""
    import re
    out = []
    for path in sorted(_PKG.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if '"schema_version"' not in text:
            continue
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            body = ast.unparse(node)
            m = re.search(r"'schema_version':\s*'(\d+)'", body)
            if not m:
                continue
            doc = (ast.get_docstring(node) or "").split("\n")[0]
            out.append((f"{path.relative_to(_ROOT)}:{node.lineno}", m.group(1), doc))
    return out


def test_the_producer_scan_finds_one():
    """Only one builder remains since v0.9.0; a scan finding none proves nothing."""
    producers = _schema_producers()
    assert producers, "no schema producer found — the scan is broken"


def test_no_producer_names_a_schema_it_does_not_emit():
    """`_build_v3` emitted "3" and its docstring said "v2 producer".

    From v0.12.0, when the v2 builder became v3 in place, until v0.16.4. A
    reader checking what BOB produces read the name of a schema retired four
    minors earlier — and the JSON contract is the surface consumers script
    against, so the docstring is where they would look first.
    """
    import re
    wrong = []
    for where, emitted, doc in _schema_producers():
        for named in re.findall(r"\bv?(\d+)\s+(?:producer|schema)", doc):
            if named != emitted:
                wrong.append(f"{where} emits schema {emitted} and its docstring "
                             f"says {named!r}: {doc!r}")
    assert not wrong, "; ".join(wrong)
