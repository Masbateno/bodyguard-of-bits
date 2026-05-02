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


def get_cis_ref(key: str) -> str | None:
    """Return the full CIS reference text for *key*, or None if not found."""
    entry = _load().get(key)
    if entry is None:
        return None
    return entry.get("ref")


def get_cis_code(key: str) -> str | None:
    """Return the short machine-readable CIS code (e.g. 'CIS:5.2.7') or None."""
    entry = _load().get(key)
    if entry is None:
        return None
    return entry.get("code")
