"""v0.24.1 — README_DEV lists every check module, in its table and its tree.

The first documentation-compliance pass found nine modules missing from both
listings of README_DEV and README_DEV_FR — every module added in 0.22.0, 0.23.0
and 0.24.0 — and a ``ssh.py`` row for what has been the ``ssh/`` package since
v0.6.0. Nothing compared the listings with ``bob/checks``. This does, by file
name only: the descriptions stay prose.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CHECKS = _ROOT / "bob" / "checks"
_DOCS = ("DOCUMENTS/README_DEV.md", "DOCUMENTS/README_DEV_FR.md")


def _modules() -> "list[str]":
    flat = sorted(p.stem for p in _CHECKS.glob("*.py") if not p.name.startswith("_"))
    pkgs = sorted(p.name for p in _CHECKS.iterdir()
                  if p.is_dir() and (p / "__init__.py").exists())
    return [f"{m}.py" for m in flat] + [f"{p}/" for p in pkgs]


@pytest.mark.parametrize("doc", _DOCS)
def test_the_module_table_lists_every_check_module(doc):
    text = (_ROOT / doc).read_text(encoding="utf-8")
    missing = [m for m in _modules()
               if not re.search(rf"^\| `{re.escape(m)}` \|", text, re.M)]
    assert not missing, f"{doc} module table lacks: {missing}"


@pytest.mark.parametrize("doc", _DOCS)
def test_the_project_tree_lists_every_check_module(doc):
    text = (_ROOT / doc).read_text(encoding="utf-8")
    missing = [m for m in _modules() if f"── {m}" not in text]
    assert not missing, f"{doc} project tree lacks: {missing}"


@pytest.mark.parametrize("doc", _DOCS)
def test_no_row_names_a_module_that_is_gone(doc):
    text = (_ROOT / doc).read_text(encoding="utf-8")
    listed = set(re.findall(r"^\| `(\w+\.py|\w+/)` \|", text, re.M))
    known = set(_modules())
    # the table also lists top-level bob/*.py modules and bob/<pkg>/ packages
    # (bob/cron.py became the bob/cron/ package in v0.6.0 — the row kept the
    # old name until this guard)
    known |= {p.name for p in (_ROOT / "bob").glob("*.py")}
    known |= {f"{p.name}/" for p in (_ROOT / "bob").iterdir()
              if p.is_dir() and (p / "__init__.py").exists()}
    assert not listed - known, f"{doc} lists modules that do not exist: {sorted(listed - known)}"
