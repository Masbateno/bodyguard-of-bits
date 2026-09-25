#!/usr/bin/env python3
"""Regenerate per-module line-count (LoC) figures in the documentation.

LoC drift on every commit and are deliberately NOT guarded (a strict guard
failed ~51% of the time — see the SNAPSHOT calibration note). Rather than let
them rot, this script recomputes them from the source and rewrites them in
DOCUMENTS/SNAPSHOT.md and DOCUMENTS/README_DEV{,_FR}.md. Run it before tagging
a release:

    python3 scripts/regen_loc.py            # rewrite in place
    python3 scripts/regen_loc.py --dry-run  # show what would change

It only rewrites figures it can attribute unambiguously to a real module:
 - the SNAPSHOT module index rows ``| `x.py` | N |``
 - an ASCII-tree ``(N L)`` or a README_DEV ``(~N lines)`` / ``(~N lignes)``
   on a line naming exactly one module whose basename is unique under bob/
 - the ``~XX.X kLoC`` banner (total across bob/*.py)
Blockquote lines (``>`` — the SNAPSHOT history) are never touched.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOB = ROOT / "bob"


def _loc(p: Path) -> int:
    return sum(1 for _ in p.open(encoding="utf-8", errors="replace"))


# basename -> loc, only when the basename is unique across bob/ (skip __init__.py etc.)
_paths: dict[str, list[Path]] = defaultdict(list)
for _p in BOB.rglob("*.py"):
    _paths[_p.name].append(_p)
LOC = {name: _loc(ps[0]) for name, ps in _paths.items() if len(ps) == 1}
# full "bob/…/x.py" relative path -> loc (used by the hotspot table, which
# names sub-package files like bob/tui/cron.py that a basename can't disambiguate)
LOC_BY_PATH = {str(p.relative_to(ROOT)): _loc(p) for p in BOB.rglob("*.py")}
TOTAL_KLOC = sum(_loc(p) for p in BOB.rglob("*.py")) / 1000.0

_INDEX = re.compile(r"\| `([a-z_0-9]+\.py)` \| (\d+) \|")
# hotspot table rows: "| <loc> | `bob/…/x.py` | …"  (LoC in the first column)
_HOTSPOT = re.compile(r"\| (\d+) \| `(bob/[a-z_0-9/]+\.py)` \|")
_MODULE = re.compile(r"`?([a-z_0-9]+\.py)`?")


def regen(text: str) -> tuple[str, int]:
    changed = 0
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith(">"):        # history blockquote — never touch
            out.append(line)
            continue
        orig = line
        # banner kLoC — only on non-blockquote lines (history keeps its figure)
        line = re.sub(r"~\d+(?:\.\d+)? kLoC", f"~{TOTAL_KLOC:.1f} kLoC", line)
        # 1. SNAPSHOT module index rows
        def _idx(m):
            name = m.group(1)
            return f"| `{name}` | {LOC[name]} |" if name in LOC else m.group(0)
        line = _INDEX.sub(_idx, line)
        # 1b. hotspot table rows (LoC-first, full path). Numbers only — rows are
        #     hand-sorted, so a re-sort stays a human edit; --dry-run flags drift.
        def _hot(m):
            path = m.group(2)
            return f"| {LOC_BY_PATH[path]} | `{path}` |" if path in LOC_BY_PATH else m.group(0)
        line = _HOTSPOT.sub(_hot, line)
        # 2. (~N lines/lignes) or (N L) tied to the one module named on the line
        names = [n for n in _MODULE.findall(line) if n in LOC]
        if len(set(names)) == 1:
            n = LOC[names[0]]
            line = re.sub(r"\(~\d+ lines\)", f"(~{n} lines)", line)
            line = re.sub(r"\(~\d+ lignes\)", f"(~{n} lignes)", line)
            line = re.sub(r"\((\d+) L\)", f"({n} L)", line)
            # bare "NNN L" only in an annotated tree row ("← …, 708 L, …"): the
            # "←" guard keeps it off table rows / prose where "N L" is a *delta*
            # (e.g. "net −75 L") or a package-largest figure, which are not this
            # module's own line count.
            if "←" in line:
                line = re.sub(r"\b\d+ L\b", f"{n} L", line)
        if line != orig:
            changed += 1
        out.append(line)
    return "\n".join(out), changed


def main() -> int:
    dry = "--dry-run" in sys.argv
    for rel in ("DOCUMENTS/SNAPSHOT.md", "DOCUMENTS/README_DEV.md",
                "DOCUMENTS/README_DEV_FR.md"):
        p = ROOT / rel
        old = p.read_text(encoding="utf-8")
        new, n = regen(old)
        if not dry and new != old:
            p.write_text(new, encoding="utf-8")
        print(f"{rel}: {n} line(s) {'would change' if dry else 'rewritten'}"
              f"{' + kLoC' if '~' in new and 'kLoC' in new else ''}")
    print(f"(total bob/ = ~{TOTAL_KLOC:.1f} kLoC)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
