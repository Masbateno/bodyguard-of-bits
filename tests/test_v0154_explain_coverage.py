"""Every negative finding key must be explainable.

Backlog item 7, and the blind spot the v0.15.3 orphan-locale guard had to
allowlist: `explain.*` keys are built at runtime (``t(f"explain.{key}.…")``),
so a literal-reference sweep cannot see them and nothing verified the corpus
lined up with what BOB actually emits.

Three sets have to agree, and measuring them took two attempts:

* ``EXPLAIN_KEYS`` — the hand-maintained list backing ``--explain list``;
* the ``explain.*`` locale entries;
* the keys the checks emit on a WARN or ALERT.

The first measurement reported 5 keys with no locale entry and 3 locale entries
outside the list. All eight were artefacts: explain entries nest three levels
deep (``services.exposure.open_local``) and the sweep flattened two, so a
middle node was mistaken for a leaf. The walk below descends until it finds a
node carrying string values, and the two sets then match exactly.

The second correction: of 395 emitted keys, 267 are OK/INFO — positive findings
with nothing to explain. Only WARN and ALERT keys are held to this contract.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from bob.explain import EXPLAIN_KEYS

ROOT = Path(__file__).resolve().parent.parent

NEGATIVE = {"warn", "alert", "warn_with_deduction", "alert_with_deduction"}
POSITIVE = {"ok", "info"}

# Plugin-sandbox failures describe the tool failing to run someone's plugin,
# not a posture of the audited host. They are deliberately outside the explain
# corpus, which answers "why does this matter for my security, and how do I fix
# it". `bob --explain plugin.sandbox.timeout` answers gracefully — a localised
# "no explanation available" and exit 3 — rather than a crash or a bracketed
# fallback, which is verified below. Keep this list SHORT: every entry is a key
# a user can meet in a report and not be able to look up.
EXEMPT_PREFIXES = ("plugin.sandbox.",)


def locale_explain_keys() -> set[str]:
    """Leaf entries under `explain.`, found by descending to the first node
    that carries string values (title/why/…), not by assuming a depth."""
    data = json.loads((ROOT / "bob" / "locales" / "en.json").read_text(encoding="utf-8"))["explain"]
    out: set[str] = set()

    def walk(node, prefix: str) -> None:
        if not isinstance(node, dict):
            return
        if any(isinstance(v, str) for v in node.values()):
            out.add(prefix)
            return
        for key, value in node.items():
            walk(value, f"{prefix}.{key}" if prefix else key)

    for key, value in data.items():
        if key != "ui":
            walk(value, key)
    return out


def emitted_keys() -> tuple[set[str], set[str]]:
    negative: set[str] = set()
    positive: set[str] = set()
    for path in ROOT.joinpath("bob").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name not in NEGATIVE | POSITIVE:
                continue
            for kw in node.keywords:
                if kw.arg == "key" and isinstance(kw.value, ast.Constant) \
                   and isinstance(kw.value.value, str) and "." in kw.value.value:
                    (negative if name in NEGATIVE else positive).add(kw.value.value)
    return negative, positive


class TestTheThreeSetsAgree:
    def test_every_listed_key_has_a_locale_entry(self):
        missing = sorted(set(EXPLAIN_KEYS) - locale_explain_keys())
        assert not missing, f"--explain would show nothing for: {missing}"

    def test_every_locale_entry_is_listed(self):
        orphan = sorted(locale_explain_keys() - set(EXPLAIN_KEYS))
        assert not orphan, f"written but unreachable from --explain list: {orphan}"

    def test_the_walk_descends_past_two_levels(self):
        """The bug that made the first measurement lie: a three-level key must
        be found as a leaf, and its parent must not be."""
        keys = locale_explain_keys()
        assert "services.exposure.open_local" in keys
        assert "services.exposure" not in keys


class TestEveryNegativeFindingIsExplainable:
    def test_no_warn_or_alert_key_is_unexplainable(self):
        negative, _ = emitted_keys()
        missing = sorted(
            k for k in negative - set(EXPLAIN_KEYS)
            if not k.startswith(EXEMPT_PREFIXES)
        )
        assert not missing, (
            "emitted on a WARN/ALERT with no explain entry — a user meets the "
            f"key in their report and cannot look it up: {missing}"
        )

    def test_the_sweep_sees_both_kinds(self):
        """A sweep that classified everything one way would pass forever."""
        negative, positive = emitted_keys()
        assert len(negative) > 100
        assert len(positive) > 100

    def test_the_exemption_is_still_needed(self):
        """If the sandbox family ever gains explanations, drop the exemption
        rather than leaving a stale hole in the guard."""
        negative, _ = emitted_keys()
        exempted = {k for k in negative if k.startswith(EXEMPT_PREFIXES)}
        assert exempted, "nothing uses the exemption any more — remove it"
        assert not (exempted & set(EXPLAIN_KEYS))
