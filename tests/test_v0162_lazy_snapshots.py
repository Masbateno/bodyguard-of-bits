"""v0.16.2 — the lazy-snapshot conversion is complete, and nothing kept it so.

v0.13.3 taught ``_sec`` to accept a zero-argument factory and to call it only
after the ``_section_enabled`` gate, so a section excluded by ``--check`` /
``--skip`` / the profile costs nothing. Five sites were converted then and the
rest followed; measured on this host the whole audit takes ~8.2 s and
``--check=ssh`` ~2.5 s.

But the guard written at the time covers the *mechanism* — that ``_sec`` gates
before it builds — and not the *call sites*. One new section written as
``_sec("x", XxxSnapshot.from_system(), check_x)`` collects eagerly again, is
invisible to every test, and shows up only as an audit that got slower. The
parentheses are the whole difference.

Two guards, then: every ``_sec`` snapshot argument is a factory, and the
snapshots the core does collect eagerly are exactly the ones documented as
always-on. The second exists so that adding an eager collection to the core
pipeline stays a deliberate, visible decision rather than a diff nobody reads.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_RUNNER = Path(__file__).resolve().parent.parent / "bob" / "runner.py"


def _run_checks() -> ast.FunctionDef:
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "run_checks")


def _sec_calls() -> list[ast.Call]:
    return [n for n in ast.walk(_run_checks())
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_sec"]


class TestEverySectionTakesAFactory:

    def test_the_sweep_still_finds_the_sections(self):
        """A guard over an empty list passes for ever. Positive control."""
        calls = _sec_calls()
        assert len(calls) >= 30, f"only {len(calls)} _sec call sites found"

    def test_no_snapshot_is_built_at_the_call_site(self):
        """``XxxSnapshot.from_system()`` runs before ``_sec`` is even entered."""
        eager = []
        for call in _sec_calls():
            if len(call.args) < 2:
                continue
            snapshot = call.args[1]
            if isinstance(snapshot, ast.Call):
                eager.append(f"line {snapshot.lineno}: "
                             f"{ast.unparse(call.args[0])} → {ast.unparse(snapshot)[:50]}")
        assert not eager, (
            "these sections collect their snapshot before the _section_enabled "
            f"gate can skip them — drop the parentheses:\n  " + "\n  ".join(eager)
        )

    def test_a_factory_is_what_it_looks_like(self):
        """Each argument is an attribute, a name or a lambda — something callable.

        Guards the other direction: a literal or a subscript would satisfy "not
        a Call" while giving ``_sec`` something it cannot invoke.
        """
        for call in _sec_calls():
            if len(call.args) < 2:
                continue
            snapshot = call.args[1]
            assert isinstance(snapshot, (ast.Attribute, ast.Name, ast.Lambda)), (
                f"line {snapshot.lineno}: _sec's snapshot argument is "
                f"{type(snapshot).__name__}, which is neither a factory nor a "
                f"snapshot: {ast.unparse(snapshot)[:60]}"
            )


class TestTheEagerCoreIsTheDocumentedOne:
    """The always-on pipeline collects eagerly on purpose — its snapshots feed
    each other and the caller, so they cannot be factories. That list is fixed;
    a twelfth arrival means someone widened the unconditional cost of every
    audit, including ``--check=ssh``.
    """

    #: Documented in the deferred-work note as staying eager permanently.
    ALWAYS_ON = frozenset({
        "FirewallStatus", "PortsSnapshot", "IptablesNftSnapshot",
        "FirewallStackSnapshot", "NetworkContextSnapshot", "IPv6Snapshot",
        "DdnsSnapshot", "LogsSnapshot", "DockerSnapshot", "VirtSnapshot",
        "HardeningSnapshot",
    })

    @staticmethod
    def _eager_classes() -> set[str]:
        fn = _run_checks()
        inside_lambda = {
            sub.lineno
            for node in ast.walk(fn) if isinstance(node, ast.Lambda)
            for sub in ast.walk(node)
            if isinstance(sub, ast.Call) and getattr(sub.func, "attr", "") == "from_system"
        }
        return {
            node.func.value.id
            for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and getattr(node.func, "attr", "") == "from_system"
            and isinstance(getattr(node.func, "value", None), ast.Name)
            and node.lineno not in inside_lambda
        }

    def test_nothing_new_collects_unconditionally(self):
        extra = sorted(self._eager_classes() - self.ALWAYS_ON)
        assert not extra, (
            f"{extra} is collected on every audit, including one narrowed by "
            "--check. Pass the factory to _sec instead, or add it here with the "
            "reason it must be eager."
        )

    def test_the_documented_ones_are_still_there(self):
        """Polarity: the list must not drift into naming snapshots that left."""
        missing = sorted(self.ALWAYS_ON - self._eager_classes())
        assert not missing, (
            f"{missing} no longer collects eagerly — if that is deliberate, "
            "remove it from ALWAYS_ON so the guard keeps meaning something."
        )
