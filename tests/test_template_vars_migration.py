"""
Phase 2 migration progress: track how many check modules expose ``template_vars``
alongside their ``message=_t(...)`` calls.

The Phase 2 design (v0.4.1) introduced an additive ``template_vars`` field on
``Finding`` and ``Deduction`` for locale-independent reconstruction. Three
checks were migrated as pilots (ssh, hardening, firewall) and the remaining
~37 checks were left for incremental migration in later releases.

This test makes the migration debt visible (it does NOT enforce a deadline).
When new checks get migrated, the count auto-increases; we just freeze a
lower bound so regressions (a check accidentally losing its template_vars
calls) get caught.

The test prints the current migration ratio when run with ``-v``.
"""

from __future__ import annotations

from pathlib import Path

import pytest


_CHECKS_DIR = Path(__file__).resolve().parents[1] / "bob" / "checks"

# Migrated as of v0.4.2. Module names (without .py) — accepts both legacy
# single-file checks (`ssh.py`) and packages (`ssh/` post v0.6.0 #13 split).
# As more checks are migrated, append to this list — the test verifies the
# count is at least this large but allows growth.
_MIGRATED_CHECKS_V0_4_2 = frozenset({
    "ssh",
    "hardening",
    "firewall",
})


def _module_paths() -> list[Path]:
    """Return one path per check module (file or package directory).

    Skips private helpers (leading underscore) and the package __init__.
    Updated v0.6.0: also returns directory paths for check packages (ssh/).
    """
    out: list[Path] = []
    for p in _CHECKS_DIR.iterdir():
        if p.name.startswith("_") or p.name == "__init__.py":
            continue
        if p.is_file() and p.suffix == ".py":
            out.append(p)
        elif p.is_dir() and (p / "__init__.py").exists():
            out.append(p)
    return out


def _module_has_template_vars(path: Path) -> bool:
    """True if any non-test source file in this module contains `template_vars=`."""
    if path.is_file():
        return "template_vars=" in path.read_text(encoding="utf-8")
    # Package: scan all .py files inside (excluding __pycache__)
    for py in path.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        if "template_vars=" in py.read_text(encoding="utf-8"):
            return True
    return False


def _module_name(path: Path) -> str:
    """Return the canonical check name (stem for files, dirname for packages)."""
    return path.stem if path.is_file() else path.name


class TestTemplateVarsMigration:
    def test_pilot_checks_use_template_vars(self):
        """The 3 pilot checks must keep their `template_vars=` calls."""
        for name in _MIGRATED_CHECKS_V0_4_2:
            file_path = _CHECKS_DIR / f"{name}.py"
            pkg_path = _CHECKS_DIR / name
            if file_path.is_file():
                target = file_path
            elif pkg_path.is_dir():
                target = pkg_path
            else:
                pytest.fail(f"Pilot check {name!r} not found as file or package")
            assert _module_has_template_vars(target), (
                f"Regression: {name} no longer contains a `template_vars=` call. "
                "Phase 2 migration debt would silently grow if this is allowed."
            )

    def test_migration_progress_visible(self, capsys):
        """Print the migration ratio so reviewers can track progress."""
        modules = _module_paths()
        migrated = [m for m in modules if _module_has_template_vars(m)]
        total = len(modules)
        ratio = (len(migrated) / total * 100) if total else 0
        print(f"\n[Phase 2 migration] {len(migrated)}/{total} check modules ({ratio:.1f}%) "
              f"use template_vars=", end="")
        # Always passes — purely informational. The assertion above is the gate.
        assert total > 0

    def test_migration_lower_bound(self):
        """
        Lower bound: at least the v0.4.2 pilot count must be present.
        When new migrations land, bump _MIGRATED_CHECKS_V0_4_2 in the same commit.
        """
        modules = _module_paths()
        migrated = {_module_name(m) for m in modules if _module_has_template_vars(m)}
        missing = _MIGRATED_CHECKS_V0_4_2 - migrated
        assert not missing, (
            f"Pilot checks no longer migrated: {missing}. "
            "Either restore template_vars= in those files or remove them from "
            "_MIGRATED_CHECKS_V0_4_2 (and document the regression)."
        )
