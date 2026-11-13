"""v0.35.0 — each finding line of the README's real-run excerpt is a line BOB
can still print.

The excerpt is copied from a real run and regenerated at assembly; nothing
checked it against the texts in between. A finding whose wording changed (the
panorama's reach, Timeshift's mode in 0.35.0) would leave the README quoting a
line no version of BOB prints any more. Each `[LEVEL] message` line of the
block must match a template of the matching locale, its placeholders read as
"anything".
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_LINE = re.compile(r"^[ℹ⚠✔✖] \[[A-Z]+\] (.+)$")


@lru_cache(maxsize=None)
def _templates(lang: str) -> tuple:
    out = []

    def walk(o):
        for v in o.values():
            if isinstance(v, dict):
                walk(v)
            elif isinstance(v, str) and len(v) > 8:
                parts = re.split(r"\{[a-z_0-9]*\}", v)
                out.append(re.compile(".+?".join(re.escape(p) for p in parts), re.S))
    walk(json.loads((_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8")))
    return tuple(out)


def _excerpt(rel: str) -> list:
    text = (_ROOT / rel).read_text(encoding="utf-8")
    m = re.search(r"\n```\n\$ sudo bob\n(.*?)\n```", text, re.S)
    assert m, f"{rel}: the real-run excerpt is gone or reshaped"
    return [lm.group(1) for line in m.group(1).splitlines() if (lm := _LINE.match(line))]


@pytest.mark.parametrize("rel, lang", [("README.md", "en"), ("README_FR.md", "fr")])
def test_every_finding_line_is_a_template(rel, lang):
    lines = _excerpt(rel)
    assert len(lines) >= 10, f"{rel}: only {len(lines)} finding lines found in the excerpt"
    stale = [ln for ln in lines if not any(t.fullmatch(ln) for t in _templates(lang))]
    assert not stale, f"{rel}: {len(stale)} line(s) BOB no longer prints, first: {stale[:2]}"
