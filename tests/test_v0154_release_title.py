"""The GitHub release title was truncated mid-phrase on every release.

publish.yml built the title as "vX.Y.Z — <headline>", taking the CHANGELOG.md
table cell and cutting at the first " — ". But the cell opens with a bold lead
that contains em dashes of its own:

    **First v0.15.3 work — the backlog v0.15.2 left.** Samba renamed ...

so the cut landed inside the bold span and left its opening ``**`` unbalanced.
Every release from at least v0.14.0 to v0.15.3 shipped as, literally,
``v0.15.3 — **First v0.15.3 work``.

This test runs the workflow's own shell block rather than reimplementing it —
a guard that reimplements the logic it watches stops testing that logic the
moment either side drifts.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"

START = "HEADLINE=$(awk -F'|'"
END = """s/\\.$//')"""


def headline_block() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    i = text.index(START)
    j = text.index(END, i) + len(END)
    # de-indent the YAML block so bash sees plain script
    lines = [ln.strip() for ln in text[i:j].splitlines()]
    return "\n".join(lines)


def extract(version: str) -> str:
    script = f"set -eu\nVERSION={version}\n{headline_block()}\nprintf '%s' \"$HEADLINE\"\n"
    out = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def documented_versions() -> list[str]:
    rows = re.findall(
        r"^\| \[(v[0-9.]+)\]\(#v[0-9]+\) \|", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M
    )
    return rows[:12]


class TestTheWorkflowBlockRuns:
    def test_the_block_was_found(self):
        """A test that silently extracted nothing would pass forever."""
        block = headline_block()
        assert "awk" in block and "case " in block
        assert len(block.splitlines()) >= 5

    def test_versions_were_found(self):
        assert len(documented_versions()) >= 6


class TestTitlesAreClean:
    def test_recent_releases_all_produce_a_title(self):
        for version in documented_versions():
            assert extract(version).strip(), f"{version}: empty headline"

    def test_no_title_carries_markdown_bold(self):
        """The defect's visible symptom: a stray ** in the release name."""
        bad = {v: h for v in documented_versions() if "*" in (h := extract(v))}
        assert not bad, f"markdown leaked into the release title: {bad}"

    def test_no_title_is_cut_inside_the_bold_lead(self):
        """The lead ends at its closing **; the title must contain all of it.

        Pre-fix, "First v0.15.3 work — the backlog v0.15.2 left." was cut to
        "First v0.15.3 work", so the title was a prefix of the real lead.
        """
        source = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        for version in documented_versions():
            row = next(
                l for l in source.splitlines()
                if l.startswith(f"| [{version}](")
            )
            m = re.search(r"\*\*(.+?)\*\*", row)
            if not m:
                continue  # no bold lead: the fallback branch, checked elsewhere
            lead = m.group(1).rstrip().rstrip(".")
            assert extract(version) == lead, (
                f"{version}: title {extract(version)!r} != lead {lead!r}"
            )

    def test_the_newest_lead_is_short_enough_to_read(self):
        """The cap lives here, not in a byte-counting cut in the workflow.

        Only the newest row is checked: that is the one the next release will
        turn into a title, and the only one still worth editing. Three older
        rows run to 130-167 characters; their releases are already published
        and rewriting their changelog entries would buy nothing.
        """
        source = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        version = documented_versions()[0]
        row = next(l for l in source.splitlines() if l.startswith(f"| [{version}]("))
        m = re.search(r"\*\*(.+?)\*\*", row)
        assert m, f"{version}: no bold lead to use as a title"
        assert len(m.group(1)) <= 120, (
            f"{version}: bold lead is {len(m.group(1))} chars — too long for a "
            f"release title, shorten it in CHANGELOG.md"
        )
