"""v0.20.0 — the score domains ARE the six on-screen groups, and stay that way.

Until v0.20.0 BOB carried two parallel taxonomies: six display groups
(runner.emit_group + groups.*) and seven score domains (domain_scores.DOMAINS).
A reader saw "Disk Health 10/10" in the score panel while the disk findings had
scrolled under HEALTH & RESILIENCE, and the detection tools had a display group
but no score domain. They are now one: every finding is scored in the box it is
shown under.

This guard is what keeps them aligned. It reads bob/runner.py in source order,
tracks the group each ``emit_group(...)`` opens, and asserts that every section
emitted under it (``emit_section`` / ``_sec``) is scored in that same domain by
``bob.domain_scores.key_to_domain``. Add a section under a group but forget to
map its finding-key prefix, and this fails — the two taxonomies cannot drift
apart silently again.
"""

from __future__ import annotations

import ast
from pathlib import Path

from bob.domain_scores import DOMAINS, key_to_domain

_RUNNER = Path(__file__).resolve().parents[1] / "bob" / "runner.py"

# The six display groups == the six score domains.
_GROUPS = frozenset(DOMAINS)

# Section name → finding-key prefix, for the few sections whose emitted keys do
# not match their section name. `virtualization` emits virt.*; `ufw_logging`
# emits firewall.* (it is the UFW logging level, part of the firewall check).
_SECTION_TO_PREFIX = {
    "virtualization": "virt",
    "ufw_logging": "firewall",
}


def _section_group_pairs() -> list[tuple[int, str, str]]:
    """Walk runner.py; return (lineno, section, group) for every section call,
    the group being the most recent ``emit_group(...)`` above it in source order."""
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))

    events: list[tuple[int, str, str]] = []  # (lineno, kind, arg)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        fn = node.func.id
        if fn not in ("emit_group", "emit_section", "_sec"):
            continue
        if not (node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            continue
        events.append((node.lineno, fn, node.args[0].value))

    events.sort(key=lambda e: e[0])

    pairs: list[tuple[int, str, str]] = []
    current_group: str | None = None
    for lineno, kind, arg in events:
        if kind == "emit_group":
            current_group = arg
        else:  # emit_section / _sec
            assert current_group is not None, (
                f"{arg!r} at runner.py:{lineno} is emitted before any emit_group()"
            )
            pairs.append((lineno, arg, current_group))
    return pairs


def test_the_parser_found_the_sections():
    """A parser that matched nothing would make every assertion below vacuous."""
    pairs = _section_group_pairs()
    assert len(pairs) > 30, f"only {len(pairs)} section calls found — parse broke"


def test_every_group_key_is_a_domain():
    """The group keys used in the runner must be exactly the score domains."""
    groups_in_runner = {g for _, _, g in _section_group_pairs()}
    assert groups_in_runner == _GROUPS, (
        f"runner groups {sorted(groups_in_runner)} != domains {sorted(_GROUPS)}"
    )


def test_every_section_is_scored_in_its_display_group():
    """The core invariant: a section shown under group G is scored in domain G."""
    mismatches = []
    for lineno, section, group in _section_group_pairs():
        prefix = _SECTION_TO_PREFIX.get(section, section)
        domain = key_to_domain(f"{prefix}.some_finding")
        if domain != group:
            mismatches.append(
                f"  runner.py:{lineno}: section {section!r} (prefix {prefix!r}) "
                f"is displayed under {group!r} but scored under {domain!r}"
            )
    assert not mismatches, (
        "display group and score domain disagree — a finding would be scored in "
        "a box other than the one it appears under:\n" + "\n".join(mismatches)
    )
