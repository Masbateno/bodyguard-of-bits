"""Which parts of a documentation line describe the tool *as it is now*.

The counter guards (test_v0170_doc_counters_sweep, test_v0211_live_count_claims)
leave historical figures alone: "EXPLAIN_KEYS 117/30 → 168/45 (v0.8.0)" was true
when it was written. Until 0.25.1 they did so by skipping every *line* that
named a release anywhere — and SNAPSHOT annotates almost every row with the
release that introduced something ("since v0.9.0 D-1"), so a stale current
figure on the same row was never read: "EXPLAIN_KEYS (218 keys, 61 prefixes)"
sat beside a v0.10.1 note while the code held 226 and 62.

The unit is now the *segment*: a line is cut at table cells, semicolons,
parentheses, dashes and sentence ends, and only a segment that carries a dating
marker of its own is skipped. A blockquote line that names a release
(SNAPSHOT's per-release history) is history as a whole; one that names none is
a note about the present and is read like any other line — the `--check=list`
note's "57 filterable + 10 always-on" went unread while it was exempted.
"""

from __future__ import annotations

import re

#: A segment carrying one of these is dating its own figure.
DATING_MARKER = re.compile(
    r"\bv?0\.[0-9]+\.[0-9]+"
    r"|Baseline history|Historique de référence|baseline was"
    r"|→|\bwas\b|\bétait\b|\bbefore\b|\bavant\b|\bformerly\b|\bpre-"
    r"|realigned|réalign")

#: A release named anywhere on a blockquote line makes the quote history.
_RELEASE = re.compile(r"\bv?0\.[0-9]+\.[0-9]+|\bv0\.[0-9]+\.x\b")

#: Where one claim ends and the next begins on a single line.
_SEPARATOR = re.compile(r"\s\|\s|;|·|\. |\(|\)|—|, then ")


def undated_segments(line: str) -> "list[str]":
    """The parts of *line* that state something about the present."""
    if line.lstrip().startswith(">") and _RELEASE.search(line):
        return []
    return [seg for seg in _SEPARATOR.split(line) if not DATING_MARKER.search(seg)]
