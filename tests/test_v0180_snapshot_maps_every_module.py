"""Every module in bob/ is named in SNAPSHOT.md.

SNAPSHOT is the map loaded first before a refactor or an audit, and a module
it does not name is a module nobody is told exists. Two had fallen off it:

* ``bob/checks/_ufw.py`` — the single ``ufw status numbered`` parser, created
  in v0.15.0 to close a defect where a rule's *source address* made unrelated
  ports look firewalled. Unmapped for four releases.
* ``bob/_sysctl_apply.py`` — the native ``--fix --apply`` path, new in
  v0.18.0 and missing from the map of the release that introduced it.

The guards on SNAPSHOT checked its counters and its line counts, never its
coverage. Presence by basename is a deliberately low bar: it cannot say
whether the description is right, only that the file is not silent.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SNAPSHOT = _ROOT / "DOCUMENTS" / "SNAPSHOT.md"


def _modules() -> list[Path]:
    return sorted(
        p for p in (_ROOT / "bob").rglob("*.py")
        if p.name != "__init__.py" and "__pycache__" not in p.parts
    )


def test_there_are_modules_to_check():
    """The mirror: an empty walk would make the next test vacuous."""
    assert len(_modules()) > 50


def test_snapshot_names_every_module():
    text = _SNAPSHOT.read_text(encoding="utf-8")
    missing = [str(p.relative_to(_ROOT)) for p in _modules() if p.name not in text]
    assert not missing, (
        "SNAPSHOT.md does not name these modules — add them to the tree and, "
        "for a top-level module, to the module table:\n  " + "\n  ".join(missing)
    )
