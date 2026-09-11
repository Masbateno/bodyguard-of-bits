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
_VERSION_SUFFIX = re.compile(r"\s+[0-9][0-9./]*$")
_PAREN_SUFFIX = re.compile(r"\s*\(.*\)$")


def _benchmark_label(ref: str) -> "str | None":
    """The full benchmark label a reference names, e.g. "CIS Ubuntu 22.04",
    "CIS Docker 1.6", "Best practice". The ref up to the em-dash, L1/L2 and a
    trailing ``(Samba)``-style qualifier stripped. Keeps the version."""
    if not ref:
        return None
    head = _PAREN_SUFFIX.sub("", ref.split(" — ", 1)[0].strip())
    head = _LEVEL_SUFFIX.sub("", head).strip()
    return head or None


def split_benchmark(label: str) -> "tuple[str, str]":
    """Split a benchmark label into (distro family, version).

        "CIS Ubuntu 22.04" -> ("CIS Ubuntu", "22.04")
        "CIS Debian 12"    -> ("CIS Debian", "12")
        "CIS Docker 1.6"   -> ("CIS Docker", "1.6")
        "CIS Red Hat 8/9"  -> ("CIS Red Hat", "8/9")
        "Best practice"    -> ("Best practice", "")
    """
    m = _VERSION_SUFFIX.search(label)
    if m:
        return label[: m.start()].strip(), m.group(0).strip()
    return label, ""


def benchmark_labels(key: str) -> "list[str]":
    """Every benchmark label a key carries a reference for — its primary
    ``ref`` plus any per-benchmark entries under ``benchmarks``."""
    entry = _load().get(key)
    if entry is None:
        return []
    labels = []
    primary = _benchmark_label(entry.get("ref", ""))
    if primary:
        labels.append(primary)
    for lbl in entry.get("benchmarks", {}):
        if lbl not in labels:
            labels.append(lbl)
    return labels


def benchmark_refs(key: str) -> "dict[str, dict]":
    """The per-benchmark ``{label: {code, title}}`` map added beyond the
    primary reference. Empty when the key has only its primary ref."""
    entry = _load().get(key)
    return dict(entry.get("benchmarks", {})) if entry else {}


def cis_family(key: str) -> "str | None":
    """The distro-level family a key belongs to, for the top-level grouping.

    v0.18.1: distro-level, not benchmark-version-level — "CIS Ubuntu 22.04"
    and a "CIS Ubuntu 24.04" reference both land in one "CIS Ubuntu" folder,
    the versions living one level down. Derived from the canonical English
    ``ref`` so grouping does not shift with the interface language.

        "CIS Ubuntu 22.04 L1 — …"  -> "CIS Ubuntu"
        "CIS Docker 1.6 — …"        -> "CIS Docker"
        "Best practice — …"         -> "Best practice"

    Returns None when the key has no reference entry at all.
    """
    label = _benchmark_label(_load().get(key, {}).get("ref", "")) if _load().get(key) else None
    if label is None:
        return None
    if label.startswith(BEST_PRACTICE_FAMILY):
        return BEST_PRACTICE_FAMILY
    return split_benchmark(label)[0]


def cis_family_sort_key(family: str) -> "tuple[int, str]":
    """Order distro families for display: CIS Ubuntu first (the primary
    benchmark), then the other CIS families alphabetically, then Best practice
    last. A family added later slots in among the CIS families by name.
    """
    if family == "CIS Ubuntu":
        return (0, "")
    if family == BEST_PRACTICE_FAMILY:
        return (2, "")
    return (1, family)
