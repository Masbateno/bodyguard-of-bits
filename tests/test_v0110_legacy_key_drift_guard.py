"""v0.11.0 — generalised literal key-drift CI guard.

Generalises the v0.10.2 ``TestNoLegacyKeyInLiveCheck`` static guard
(which pinned the single ``iptables_nft.input_accept`` literal) to
EVERY historical rename. The v0.10.2 bug was a string literal in
``bob/scoring.py`` comparing against a finding key whose prefix had
been renamed in v0.9.0 D-1 — the comparison silently stopped matching
and a posture escalation went dead for 3 majors.

This guard sweeps all production ``bob/`` source for string literals
that reference a *renamed-away* key, so the next cross-module rename
drift fails CI instead of shipping silently.

Scope — what counts as "renamed away":

  - The 7 v0.9.0 D-1 section-prefix renames (``SECTION_RENAMES_V090``):
    ``iptables_nft`` → ``firewall_iptables``, ``cron_audit`` → ``cron``,
    etc. Production code is fully migrated to the canonical prefixes,
    so ZERO production literal should start with a legacy prefix + dot.

  - The single v0.10.1 D-4 Rank 1 key ``ssh.x11_forwarding`` (split into
    ``ssh.x11.forwarding.{server,client}``). Live findings emit the
    canonical sub-keys; the legacy name survives only as an
    intentional ``EXPLAIN_KEY_ALIASES`` entry (allowlisted).

Deliberately NOT in scope — the D-4 Rank 2-8 keys
(``ssh.host_key_dsa``, ``ssh.weak_ciphers``, ``auditd.missing_sensitive_rules``,
…). Those ranks were never actually split: the v0.10.0 shim mapped them
in anticipation but the emit sites still produce the monolithic keys, so
those keys are LIVE production keys, not legacy. Flagging them would be
wrong. (v0.11.0 kills the inert Rank 2-8 shim entries — see
``bob/_v100_subcheck_renames.py``.)

Allowlist — modules that legitimately carry a legacy key as part of the
migration contract or an intentional alias:

  - ``_v090_renames.py``        — the ``SECTION_RENAMES_V090`` dict itself
  - ``_v100_subcheck_renames.py`` — the ``SUBCHECK_RENAMES_V100`` dict
  - ``compare.py``              — references the rename in load_baseline
  - ``explain.py``              — ``EXPLAIN_KEY_ALIASES`` legacy → canonical
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from bob._v090_renames import SECTION_RENAMES_V090


_BOB_ROOT = pathlib.Path(__file__).resolve().parent.parent / "bob"

# Modules that legitimately reference a renamed-away key (migration
# contract or intentional alias). Keyed by filename (basename).
_ALLOWLIST = {
    "_v090_renames.py",
    "_v100_subcheck_renames.py",
    "compare.py",
    "explain.py",
}

# Single v0.10.1 D-4 Rank 1 key that was actually renamed away.
_RANK1_LEGACY_KEY = "ssh.x11_forwarding"


def _legacy_prefixes() -> list[str]:
    """The v0.9.0 D-1 legacy section prefixes (data-driven so a future
    rename added to SECTION_RENAMES_V090 is automatically covered)."""
    return list(SECTION_RENAMES_V090.keys())


def _is_renamed_away_literal(value: str) -> str | None:
    """Return a human reason if *value* references a renamed-away key,
    else None."""
    # Exact v0.10.1 Rank 1 legacy key.
    if value == _RANK1_LEGACY_KEY:
        return f"legacy v0.10.1 Rank 1 key {value!r} (renamed → ssh.x11.forwarding.*)"
    # v0.9.0 D-1 legacy prefix + dot (a finding-key reference).
    for prefix in _legacy_prefixes():
        if value.startswith(f"{prefix}."):
            canonical = SECTION_RENAMES_V090[prefix]
            return (
                f"legacy v0.9.0 D-1 prefix in {value!r} "
                f"(renamed {prefix!r} → {canonical!r})"
            )
    return None


def _docstring_node_ids(tree: ast.Module) -> set[int]:
    """Collect id()s of Constant nodes that are module/class/function
    docstrings, so the sweep skips documentation that legitimately
    mentions a legacy name in prose."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def _iter_production_py() -> list[pathlib.Path]:
    return [
        p
        for p in _BOB_ROOT.rglob("*.py")
        if p.is_file() and p.name not in _ALLOWLIST
    ]


def _scan_file(path: pathlib.Path) -> list[str]:
    """Return a list of offending literals found in *path* (code context,
    docstrings excluded)."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    skip = _docstring_node_ids(tree)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in skip:
                continue
            reason = _is_renamed_away_literal(node.value)
            if reason is not None:
                lineno = getattr(node, "lineno", "?")
                try:
                    label = path.relative_to(_BOB_ROOT.parent)
                except ValueError:
                    label = path  # tmp_path self-test files live outside the repo
                offenders.append(f"{label}:{lineno} — {reason}")
    return offenders


class TestLegacyKeyDriftGuard:
    """CI guard: production code must not reference a renamed-away key as
    a string literal (the v0.10.2 I-1 bug class)."""

    def test_no_production_literal_references_renamed_away_key(self):
        offenders: list[str] = []
        for path in _iter_production_py():
            offenders.extend(_scan_file(path))
        assert not offenders, (
            "Production code references a renamed-away key as a string "
            "literal (v0.10.2 I-1 bug class — a rename left a dangling "
            "comparison/emit). Offenders:\n  " + "\n  ".join(offenders)
        )

    def test_guard_is_data_driven_from_v090_map(self):
        """Sanity: the guard derives its legacy-prefix list from the
        shared SECTION_RENAMES_V090 map, so adding a future rename there
        automatically extends coverage."""
        prefixes = _legacy_prefixes()
        assert "iptables_nft" in prefixes
        assert "cron_audit" in prefixes
        assert len(prefixes) == len(SECTION_RENAMES_V090)

    def test_guard_detects_a_planted_offender(self, tmp_path):
        """Self-test: the scanner flags a synthetic file that compares
        against a legacy key, and ignores a clean canonical one."""
        bad = tmp_path / "bad.py"
        bad.write_text(
            "def f(findings):\n"
            "    return any(x.key == 'iptables_nft.input_accept' for x in findings)\n",
            encoding="utf-8",
        )
        assert _scan_file(bad), "scanner failed to flag a planted legacy literal"

        good = tmp_path / "good.py"
        good.write_text(
            "def f(findings):\n"
            "    return any(x.key == 'firewall_iptables.input_accept' for x in findings)\n",
            encoding="utf-8",
        )
        assert not _scan_file(good), "scanner false-positived on a canonical literal"

    def test_docstrings_are_not_flagged(self, tmp_path):
        """A module docstring mentioning a legacy key in prose is allowed
        (documentation, not a live comparison)."""
        doc = tmp_path / "doc.py"
        doc.write_text(
            '"""This module used to emit iptables_nft.input_accept."""\n'
            "VALUE = 1\n",
            encoding="utf-8",
        )
        assert not _scan_file(doc), "scanner flagged a docstring mention"
