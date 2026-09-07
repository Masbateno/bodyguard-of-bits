#!/usr/bin/env python3
"""Prove that each guard actually fails when the defect it guards comes back.

A guard that cannot fail is worse than no guard: it reports safety it does not
provide. The usual way to check one is to break the code on purpose and watch
the guard go red — but that check has, historically in this project, been run
by hand from a shell heredoc, reported in a commit message, and then lost. Nine
commits in v0.16.3 claim "mutation-tested"; one mention of it survives in the
test files. The evidence evaporated.

Worse, the harness itself kept lying. Once it filtered ``*failed*`` in lower
case against pytest's ``FAILED`` and called five live guards inert. Once its
shell wrapper did not forward its arguments to the mutation script at all, so
no mutation was ever applied and all six were reported inert — a clean, plausible
table describing nothing.

Both failures have the same shape: **the bench produced an answer without
having measured anything**, and nothing in the bench objected. So this one
objects. Every step that could silently do nothing asserts that it did
something:

  * the search string must appear **exactly once** in the target — zero means
    the anchor moved, more than one means the mutation is ambiguous;
  * the file's bytes must actually differ after writing;
  * the guard's verdict is the **exit code** of a targeted pytest run, never a
    grep over its output;
  * the file must be byte-identical to the original after restoring;
  * and before any of it, the named tests must pass **unmutated** — the negative
    control, without which "it went red" means nothing.

Usage:
    python3 scripts/mutate.py              # every mutation
    python3 scripts/mutate.py --only tui   # those whose id contains "tui"
    python3 scripts/mutate.py --list

Exit code is 0 only when every mutation killed its guard.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from tests.mutations import MUTATIONS, Mutation      # noqa: E402

#: Where originals live while a mutation is applied, so a killed process can be
#: recovered from instead of leaving the tree broken.
_STASH = pathlib.Path(tempfile.gettempdir()) / "bob-mutate-stash"


class MutationError(RuntimeError):
    """The bench could not do its job — never confused with 'guard is inert'."""


def _recover_leftovers() -> None:
    """Restore files a previous run was killed in the middle of mutating."""
    if not _STASH.is_dir():
        return
    restored = []
    for backup in sorted(_STASH.rglob("*")):
        if backup.is_dir():
            continue
        target = _ROOT / backup.relative_to(_STASH)
        shutil.copy2(backup, target)
        restored.append(str(target.relative_to(_ROOT)))
    shutil.rmtree(_STASH, ignore_errors=True)
    if restored:
        print(f"  recovered {len(restored)} file(s) from an interrupted run: "
              f"{', '.join(restored)}\n")


def _clear_pycache() -> None:
    for cache in _ROOT.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)


def _run_tests(node_ids: "tuple[str, ...]") -> int:
    _clear_pycache()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", *node_ids],
        cwd=_ROOT, capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):
        raise MutationError(
            f"pytest exited {proc.returncode} on {node_ids} — that is a broken "
            f"run, not a verdict:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
        )
    return proc.returncode


def _apply(mut: Mutation) -> bytes:
    """Write the mutated file, returning the original bytes."""
    target = _ROOT / mut.file
    if not target.is_file():
        raise MutationError(f"{mut.id}: {mut.file} does not exist")
    original = target.read_bytes()
    text = original.decode("utf-8")

    seen = text.count(mut.old)
    if seen != 1:
        raise MutationError(
            f"{mut.id}: the anchor appears {seen} time(s) in {mut.file}, "
            f"expected exactly one. The code moved under the mutation; fix the "
            f"anchor rather than deleting the mutation.\n  anchor: {mut.old[:90]!r}"
        )

    mutated = text.replace(mut.old, mut.new, 1).encode("utf-8")
    if mutated == original:
        raise MutationError(
            f"{mut.id}: applying it changed nothing — old and new are the same"
        )

    backup = _STASH / mut.file
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(original)
    target.write_bytes(mutated)

    if target.read_bytes() != mutated:
        raise MutationError(f"{mut.id}: the mutated file did not reach disk")
    return original


def _restore(mut: Mutation, original: bytes) -> None:
    target = _ROOT / mut.file
    target.write_bytes(original)
    if target.read_bytes() != original:
        raise MutationError(f"{mut.id}: {mut.file} was not restored")
    backup = _STASH / mut.file
    backup.unlink(missing_ok=True)


#: A change that cannot alter behaviour: one space inside a module docstring.
#: The bench applies it before doing any real work and requires it to SURVIVE.
_CANARY = Mutation(
    id="canary/whitespace-in-a-docstring",
    file="bob/explain.py",
    old="--explain KEY implementation for BOB.",
    new="--explain KEY  implementation for BOB.",
    kills=("tests/test_explain.py::TestRunExplainUniform",),
    reason="proves the bench can still tell a surviving mutation from a killed one",
)


def _canary_is_discriminating() -> bool:
    """Prove, on every run, that this bench can report a surviving mutation.

    A bench that only ever says "killed" is indistinguishable from a bench that
    is not running, and this project has been burnt by exactly that twice: once
    the verdict was grepped for ``failed`` in lower case against pytest's
    ``FAILED``, once the shell wrapper never forwarded its arguments so no
    mutation was applied at all. Both produced clean tables describing nothing.

    So before judging any guard, the bench breaks something that *cannot*
    matter — a space inside a docstring — and requires the named tests to stay
    green. If they go red, the tests are not measuring what they are pointed
    at, and every verdict after that would be noise.
    """
    print("  positive control — a change that cannot matter ... ", end="", flush=True)
    original = _apply(_CANARY)
    try:
        rc = _run_tests(_CANARY.kills)
    finally:
        _restore(_CANARY, original)
    if rc != 0:
        print("KILLED")
        print("\n  The bench reported a docstring space as a defect. The named "
              "tests are not measuring what they are pointed at, so nothing "
              "this run says about the real mutations would mean anything.")
        return False
    print("survived (as it must)")
    return True


def run(selected: "list[Mutation]") -> int:
    print(f"  {len(selected)} mutation(s)\n")

    control_ids = tuple(sorted({n for m in selected for n in m.kills}))
    print("  negative control — the named guards, unmutated ... ", end="", flush=True)
    rc = _run_tests(control_ids)
    if rc != 0:
        print("RED")
        print("\n  The guards do not pass on unmutated code. Nothing this bench "
              "reports afterwards would mean anything; fix the suite first.")
        return 2
    print("green")

    if not _canary_is_discriminating():
        return 2

    failures = []
    for mut in selected:
        print(f"  {mut.id:<44} ", end="", flush=True)
        original = _apply(mut)
        try:
            rc = _run_tests(mut.kills)
        finally:
            _restore(mut, original)
        if rc == 0:
            print("SURVIVED  ← the guard is inert")
            failures.append(mut)
        else:
            print("killed")

    shutil.rmtree(_STASH, ignore_errors=True)

    print()
    if failures:
        print(f"  {len(failures)} of {len(selected)} mutation(s) survived — those "
              f"guards do not test what they claim:")
        for mut in failures:
            print(f"    {mut.id}\n      {mut.reason}")
        return 1
    print(f"  {len(selected)}/{len(selected)} mutations killed their guard.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", help="run mutations whose id contains this substring")
    ap.add_argument("--list", action="store_true", help="list them and exit")
    args = ap.parse_args()

    _recover_leftovers()

    selected = [m for m in MUTATIONS if not args.only or args.only in m.id]
    if not selected:
        print(f"  no mutation matches {args.only!r}", file=sys.stderr)
        return 2

    if args.list:
        for m in selected:
            print(f"  {m.id:<44} {m.file}")
            print(f"    {m.reason}")
        return 0

    try:
        return run(selected)
    except MutationError as exc:
        print(f"\n  BENCH ERROR — this is the harness failing, not a verdict:\n\n{exc}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
