"""CIS benchmark reference lookup, loaded from data/cis_refs.json."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "cis_refs.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, dict]:
    try:
        return json.loads(_DATA_FILE.read_text(encoding="utf-8"))
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
