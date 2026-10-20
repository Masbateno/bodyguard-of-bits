"""Which Python versions BOB is phasing out, and until when (v0.25.1).

The rule (decided 2026-10-17): a Python version stays supported for **6 months
after its official upstream end of life**; it is dropped only by a release
labelled BREAKING (under the project's SemVer rule, a minor bump while in 0.x,
a major from 1.0), the first such release after that date — never a patch or
an ordinary minor — and the deprecation is announced from the release that
follows the end of life.

Python 3.10 reached end of life on 2026-10-01 (PEP 619), so it is supported
until 2027-04-01. The v0.7.0 ladder had stalled at step 1 — no release had
announced it — and 0.25.1 is the announcement.
"""

from __future__ import annotations

import sys

#: (deprecated version, supported until at least, the version that replaces it)
DEPRECATED_PYTHON: "dict[tuple[int, int], tuple[str, str]]" = {
    (3, 10): ("2027-04-01", "3.11"),   # EoL 2026-10-01 + 6 months
}


_FR_MONTHS = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet",
              "août", "septembre", "octobre", "novembre", "décembre")


def display_date(iso: str, lang: str) -> str:
    """*iso* (YYYY-MM-DD) as a sentence in *lang* writes it.

    0.26.0 — the French messages read "jusqu'au 2027-04-01", the English
    form; French writes "jusqu'au 1er avril 2027". English keeps ISO.
    """
    if lang != "fr":
        return iso
    try:
        year, month, day = (int(p) for p in iso.split("-"))
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return iso
        return f"{'1er' if day == 1 else day} {_FR_MONTHS[month - 1]} {year}"
    except (ValueError, IndexError):
        return iso


def deprecation_for(version_info=None, lang: str = "en") -> "dict | None":
    """``{running, until, next}`` when the running Python is deprecated, else None.

    ``until`` is written for *lang* (see :func:`display_date`).
    """
    vi = version_info if version_info is not None else sys.version_info
    entry = DEPRECATED_PYTHON.get((vi[0], vi[1]))
    if entry is None:
        return None
    until, nxt = entry
    return {"running": f"{vi[0]}.{vi[1]}", "until": display_date(until, lang), "next": nxt}
