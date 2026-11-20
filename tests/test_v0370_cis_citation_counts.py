"""v0.37.0 — the cross-benchmark citation counts the documents state are the file's.

Found while assembling 0.36.0 (14 November 2026): a new reference added three
citations (CIS Debian 12, Debian 13, Ubuntu 24.04) and the documents went on
saying "259 cross-benchmark citations on 94 keys" and "90 + 79 + 90" — no guard
read those figures. They are now read from bob/data/cis_refs.json: the number of
`benchmarks` entries, the keys carrying any, and the split per benchmark.
"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _live():
    data = json.loads((_ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))
    per = collections.Counter()
    keys = 0
    for entry in data.values():
        blocks = entry.get("benchmarks") or {}
        if blocks:
            keys += 1
        for name in blocks:
            per[name] += 1
    return sum(per.values()), keys, per


@pytest.mark.parametrize("rel, pattern", [
    ("README.md", r"\*\*(\d+) cross-benchmark citations\*\* on (\d+) keys"),
    ("README_FR.md", r"\*\*(\d+) citations inter-benchmarks\*\* sur (\d+) clés"),
    ("DOCUMENTS/SNAPSHOT.md", r"\*\*(\d+) cross-benchmark citations\*\* on (\d+) keys"),
])
def test_the_stated_citations_and_keys_are_the_files(rel, pattern):
    total, keys, _per = _live()
    m = re.search(pattern, (_ROOT / rel).read_text(encoding="utf-8"))
    assert m, f"{rel}: the cross-benchmark citation sentence is gone or reshaped"
    assert (int(m.group(1)), int(m.group(2))) == (total, keys), (
        f"{rel} says {m.group(1)} citations on {m.group(2)} keys; the file holds {total} on {keys}")


def test_the_snapshot_split_per_benchmark_is_the_files():
    _total, _keys, per = _live()
    text = (_ROOT / "DOCUMENTS" / "SNAPSHOT.md").read_text(encoding="utf-8")
    m = re.search(r"\((\d+) CIS Debian 12 \+ (\d+) CIS Debian 13 \+ (\d+) CIS Ubuntu 24\.04 \+ (\d+) CIS Ubuntu 26\.04,", text)
    assert m, "SNAPSHOT.md: the per-benchmark split of the citations is gone or reshaped"
    stated = tuple(int(g) for g in m.groups())
    live = (per["CIS Debian 12"], per["CIS Debian 13"], per["CIS Ubuntu 24.04"], per["CIS Ubuntu 26.04"])
    assert stated == live, f"SNAPSHOT.md says {stated}; the file holds {live}"
    # v0.40.0 — CIS Ubuntu 26.04 (ComplianceAsCode PR #15097, merged 20 November 2026).
    assert set(per) == {"CIS Debian 12", "CIS Debian 13", "CIS Ubuntu 24.04", "CIS Ubuntu 26.04"}, (
        f"a benchmark the split does not name: {sorted(per)}")
