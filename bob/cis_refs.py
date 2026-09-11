"""CIS benchmark reference lookup, loaded from data/cis_refs.json."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "cis_refs.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, dict]:
    try:
        return json.loads(_DATA_FILE.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def get_cis_ref(key: str, lang: "str | None" = None) -> str | None:
    """Return the full CIS reference text for *key*, or None if not found.

    v0.11.2: locale-aware. ``Best practice`` entries (no formal CIS code)
    carry a French ``ref_fr`` translation; when the active locale is French
    and a ``ref_fr`` is present, it is returned. CIS-coded entries have no
    ``ref_fr`` — their canonical English benchmark titles are kept verbatim
    in every locale by design. ``lang`` defaults to the active interface
    language (resolved lazily to avoid an import cycle).
    """
    entry = _load().get(key)
    if entry is None:
        return None
    if lang is None:
        from bob.i18n import current_lang
        lang = current_lang()
    if lang == "fr":
        ref_fr = entry.get("ref_fr")
        if ref_fr:
            return ref_fr
    return entry.get("ref")


def get_cis_code(key: str) -> str | None:
    """Return the short machine-readable CIS code (e.g. 'CIS:5.2.7') or None."""
    entry = _load().get(key)
    if entry is None:
        return None
    return entry.get("code")


# ---------------------------------------------------------------------------
# Benchmark families — for grouping `--explain list` (v0.18.1)
# ---------------------------------------------------------------------------

#: Stable id for the best-practice family, whose display label is localised
#: ("Best practice" / "Bonne pratique") while every CIS family name is a
#: proper noun kept verbatim in both locales.
BEST_PRACTICE_FAMILY = "Best practice"

_LEVEL_SUFFIX = re.compile(r"\s+L[12]$")


def cis_family(key: str) -> "str | None":
    """The benchmark family a key belongs to, for grouping.

    Derived from the canonical English ``ref`` — stable across locales, since
    the family drives grouping and must not shift when the interface language
    does. The benchmark name is the ref up to the first em-dash, with the
    ``L1`` / ``L2`` level stripped so both levels of one benchmark group
    together:

        "CIS Ubuntu 22.04 L1 — 3.3.1 — …"  -> "CIS Ubuntu 22.04"
        "CIS Docker 1.6 — 5.7 — …"          -> "CIS Docker 1.6"
        "CIS Red Hat 8/9 L1 — 1.7.1.4 — …"  -> "CIS Red Hat 8/9"
        "Best practice — …"                 -> "Best practice"

    Returns None when the key has no reference entry at all.
    """
    entry = _load().get(key)
    if entry is None:
        return None
    ref = entry.get("ref", "")
    if ref.startswith(BEST_PRACTICE_FAMILY):
        return BEST_PRACTICE_FAMILY
    head = ref.split(" — ", 1)[0].strip()
    return _LEVEL_SUFFIX.sub("", head) or None


def cis_family_sort_key(family: str) -> "tuple[int, str]":
    """Order families for display: CIS Ubuntu first (the primary benchmark),
    then the other CIS families alphabetically, then Best practice last.

    A CIS family added later (Fedora, openSUSE, Alpine in v0.19.x) slots in
    among the CIS families by name without touching this function.
    """
    if family == "CIS Ubuntu 22.04":
        return (0, "")
    if family == BEST_PRACTICE_FAMILY:
        return (2, "")
    return (1, family)
