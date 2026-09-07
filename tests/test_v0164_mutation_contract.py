"""The mutation list must stay wired to the code it describes.

`scripts/mutate.py` is the slow, thorough check: it breaks the code each way
and requires the named guards to go red. This file is the fast one, and it
exists because the slow check's most likely failure is not a surviving
mutation — it is an **anchor that quietly stopped matching** after a refactor.
When that happens the bench stops with an error rather than a verdict, which is
correct but only visible to whoever runs it.

Here it is visible to anyone running the suite: every anchor must appear
exactly once in its file, every named test must exist, and the list must not be
empty. A drifting anchor therefore fails in seconds, in the ordinary test run,
naming the guard whose aim needs re-checking.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from tests.mutations import MUTATIONS      # noqa: E402


def _ids():
    return [m.id for m in MUTATIONS]


def test_there_are_mutations_at_all():
    """An empty list would pass every other check in this file forever."""
    assert len(MUTATIONS) >= 20, f"only {len(MUTATIONS)} mutations declared"


def test_the_ids_are_unique():
    assert len(_ids()) == len(set(_ids())), "duplicate mutation ids"


@pytest.mark.parametrize("mut", MUTATIONS, ids=_ids())
def test_the_anchor_appears_exactly_once(mut):
    """Zero means a refactor moved it; more than one means it is ambiguous.

    Both were caught the first time this bench ran: `profile_default` appeared
    three times, and the `banner_lines` call had moved into `draw_text`. The
    old shell harness would have mutated the first match and reported a verdict.
    """
    target = _ROOT / mut.file
    assert target.is_file(), f"{mut.id}: {mut.file} does not exist"
    seen = target.read_text(encoding="utf-8").count(mut.old)
    assert seen == 1, (
        f"{mut.id}: anchor appears {seen} time(s) in {mut.file} — the guard's "
        f"aim needs re-checking\n  anchor: {mut.old[:100]!r}"
    )


@pytest.mark.parametrize("mut", MUTATIONS, ids=_ids())
def test_the_mutation_changes_something(mut):
    assert mut.old != mut.new, f"{mut.id}: old and new are identical"


@pytest.mark.parametrize("mut", MUTATIONS, ids=_ids())
def test_it_names_the_tests_it_must_break(mut):
    assert mut.kills, f"{mut.id}: names no test to break"
    for node in mut.kills:
        path = _ROOT / node.split("::")[0]
        assert path.is_file(), f"{mut.id}: {node} points at no such file"


@pytest.mark.parametrize("mut", MUTATIONS, ids=_ids())
def test_it_says_why_the_defect_matters(mut):
    assert len(mut.reason.split()) >= 6, (
        f"{mut.id}: the reason is too thin to tell a reader what returns"
    )


def test_every_named_test_node_is_collectable():
    """A node id that pytest cannot resolve makes a mutation unkillable.

    pytest exits 4 on an unrecognised node id, which the runner treats as a
    broken run rather than a verdict — but only when it gets that far.
    """
    nodes = sorted({n for m in MUTATIONS for n in m.kills})
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-header", *nodes],
        cwd=_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        f"pytest cannot collect one of the named nodes:\n"
        f"{proc.stdout[-1500:]}\n{proc.stderr[-1500:]}"
    )


def test_the_runner_still_has_its_own_positive_control():
    """Without the canary, a bench that always says "killed" looks healthy."""
    src = (_ROOT / "scripts" / "mutate.py").read_text(encoding="utf-8")
    assert "_canary_is_discriminating" in src
    assert "if not _canary_is_discriminating():" in src, (
        "the canary is defined but no longer runs before the real mutations"
    )
