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

# Migrated as of v0.4.2. This list is intentionally a hard-coded subset that
# we know to have at least one `template_vars=` call site. As more checks
# are migrated, append to this list — the test verifies the count is at
# least this large but allows growth.
_MIGRATED_CHECKS_V0_4_2 = frozenset({
    "ssh.py",
    "hardening.py",
    "firewall.py",
})


def _check_modules() -> list[Path]:
    """Return all `.py` files in bob/checks/ except dunders and shared helpers."""
    return [
        p for p in _CHECKS_DIR.glob("*.py")
        if not p.name.startswith("_") and p.name != "__init__.py"
    ]


class TestTemplateVarsMigration:
    def test_pilot_checks_use_template_vars(self):
        """The 3 pilot checks must keep their `template_vars=` calls."""
        for name in _MIGRATED_CHECKS_V0_4_2:
            path = _CHECKS_DIR / name
            content = path.read_text(encoding="utf-8")
            assert "template_vars=" in content, (
                f"Regression: {name} no longer contains a `template_vars=` call. "
                "Phase 2 migration debt would silently grow if this is allowed."
            )

    def test_migration_progress_visible(self, capsys):
        """Print the migration ratio so reviewers can track progress."""
        modules = _check_modules()
        migrated = [m for m in modules if "template_vars=" in m.read_text(encoding="utf-8")]
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
        modules = _check_modules()
        migrated = {m.name for m in modules if "template_vars=" in m.read_text(encoding="utf-8")}
        missing = _MIGRATED_CHECKS_V0_4_2 - migrated
        assert not missing, (
            f"Pilot checks no longer migrated: {missing}. "
            "Either restore template_vars= in those files or remove them from "
            "_MIGRATED_CHECKS_V0_4_2 (and document the regression)."
        )
