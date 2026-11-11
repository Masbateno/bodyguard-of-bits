"""v0.32.0 — mutate.py's stash keeps the file's mode.

`_apply` wrote the stash backup with `write_bytes`, so it carried the umask's
default mode; a run killed mid-mutation was then recovered from that backup
and the file lost its mode. Measured on 11 November 2026: ci/arm64_smoke.sh
came back 0644 after a kill, its executable bit gone. The stash is now written
with copy2 and `_recover_leftovers` (already copy2) restores mode and content.

No mutation guards this file: mutating the mutation harness would bend the
bench that proves every other guard.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location(
    "bob_mutate", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "mutate.py")
mutate = importlib.util.module_from_spec(spec)
sys.modules.setdefault("bob_mutate", mutate)
spec.loader.exec_module(mutate)


def _setup(tmp_path, monkeypatch):
    root = tmp_path / "tree"
    (root / "ci").mkdir(parents=True)
    target = root / "ci" / "smoke.sh"
    target.write_text("#!/bin/sh\npip install --no-build-isolation .\n")
    target.chmod(0o755)
    monkeypatch.setattr(mutate, "_ROOT", root)
    monkeypatch.setattr(mutate, "_STASH", tmp_path / "stash")
    mut = mutate.Mutation(id="x/y", file="ci/smoke.sh",
                          old="--no-build-isolation ", new="",
                          kills=("t",), reason="r r r r r r")
    return target, mut


def test_the_stash_carries_the_mode(tmp_path, monkeypatch):
    target, mut = _setup(tmp_path, monkeypatch)
    mutate._apply(mut)
    assert (mutate._STASH / "ci" / "smoke.sh").stat().st_mode & 0o777 == 0o755


def test_a_killed_run_recovers_mode_and_content(tmp_path, monkeypatch):
    target, mut = _setup(tmp_path, monkeypatch)
    original = target.read_bytes()
    mutate._apply(mut)                      # killed here: no _restore
    assert target.read_bytes() != original
    mutate._recover_leftovers()
    assert target.read_bytes() == original
    assert target.stat().st_mode & 0o777 == 0o755


def test_restore_keeps_the_mode_too(tmp_path, monkeypatch):
    target, mut = _setup(tmp_path, monkeypatch)
    original = mutate._apply(mut)
    mutate._restore(mut, original)
    assert target.read_bytes() == original
    assert target.stat().st_mode & 0o777 == 0o755
