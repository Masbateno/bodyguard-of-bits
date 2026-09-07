"""v0.16.3 — the environment-variable table must list what the code reads.

`BOB_WEBHOOK_ALLOW_INSECURE` was missing from README_TECH's table: a security
escape hatch — it downgrades the webhook from HTTPS-only, and the payload
carries the host's findings — documented in SECURITY.md and nowhere in the
reference that claims to enumerate the variables.

The check reads the code rather than a list, because a list is the thing that
goes stale. It deliberately ignores variables BOB only *inherits* (`USER`,
`SUDO_USER`, `LANG` and the other POSIX locale ones): those are not knobs an
operator sets to change BOB's behaviour, and putting them in an "all are
opt-in" table would be its own inaccuracy.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: Read by BOB but not a documented knob — inherited from the process
#: environment and used to answer a question, not to change behaviour.
_INHERITED = frozenset({
    "USER", "SUDO_USER", "HOME", "PATH", "LANG", "LC_ALL", "LC_MESSAGES",
    "PYTHONPATH", "TERM", "SHELL", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "COLUMNS", "LINES", "ESCDELAY", "PYTHONNOUSERSITE",
})


def _read_by_code() -> set[str]:
    """Every environment variable the package actually consults.

    Both the direct forms and the indirect one: ``bob/_paths.py`` reads
    ``BOB_SHARE`` through a module constant, and a sweep that only matched
    ``environ.get("...")`` reported it as documented-but-unread — a false
    alarm this docstring exists to stop the next reader repeating.
    """
    names: set[str] = set()
    for py in (_ROOT / "bob").rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        text = py.read_text(encoding="utf-8")
        names |= set(re.findall(
            r'(?:os\.)?environ(?:\.get)?\(\s*"([A-Z][A-Z0-9_]{2,})"', text))
        names |= set(re.findall(r'getenv\(\s*"([A-Z][A-Z0-9_]{2,})"', text))
        # Indirect: NAME = "BOB_SOMETHING" then environ.get(NAME)
        names |= set(re.findall(r'^_\w*ENV\w* *= *"(BOB_[A-Z0-9_]+)"', text, re.M))
    return names


def _documented(rel: str) -> set[str]:
    text = (_ROOT / rel).read_text(encoding="utf-8")
    # The heading is translated — "Variables d'environnement" in the French
    # twin — so match on either. A guard that only knows the English one
    # reports the French document as empty, which is how it first failed.
    block = re.search(
        r"^## (?:Environment variables|Variables d'environnement).*?(?=^---)",
        text, re.S | re.M)
    assert block, f"{rel} has no environment-variable section"
    return set(re.findall(r"^\| `([A-Z][A-Z0-9_]+)`", block.group(0), re.M))


class TestTheTableMatchesTheCode:

    def test_the_sweep_finds_the_known_variables(self):
        """Positive control, and the one that would have caught my own
        false alarm: BOB_SHARE is read through a constant."""
        found = _read_by_code()
        for name in ("NO_COLOR", "FORCE_COLOR", "BOB_DEBUG", "BOB_SHARE",
                     "BOB_WEBHOOK_ALLOW_INSECURE"):
            assert name in found, f"the sweep no longer sees {name}"

    @pytest.mark.parametrize("rel", ["DOCUMENTS/README_TECH.md",
                                     "DOCUMENTS/README_TECH_FR.md"])
    def test_every_knob_is_documented(self, rel):
        missing = sorted(_read_by_code() - _INHERITED - _documented(rel))
        assert not missing, (
            f"{rel} does not list {missing}, which the code reads. The table "
            "says 'All are opt-in; none is required for normal operation' — a "
            "reader takes that as the complete set."
        )

    @pytest.mark.parametrize("rel", ["DOCUMENTS/README_TECH.md",
                                     "DOCUMENTS/README_TECH_FR.md"])
    def test_nothing_documented_is_dead(self, rel):
        """The other direction: a variable nothing reads is a promise BOB
        does not keep."""
        stale = sorted(_documented(rel) - _read_by_code())
        assert not stale, f"{rel} documents {stale}, which no code reads"

    def test_both_locales_list_the_same_variables(self):
        en = _documented("DOCUMENTS/README_TECH.md")
        fr = _documented("DOCUMENTS/README_TECH_FR.md")
        assert en == fr, f"only EN: {sorted(en - fr)} · only FR: {sorted(fr - en)}"
