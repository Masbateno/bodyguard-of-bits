"""
v0.15.0 — the always-on core of ``run_checks`` now degrades instead of aborting.

v0.14.1 put a fault barrier on the sections dispatched through ``_sec`` and
documented the always-on core as deliberately excluded: it is "a data pipeline,
not a set of sections", and swallowing a failure there would leave downstream
code reading names that were never bound.

Checked against the real data flow, that argument covers two of the core's
twelve collections. The rest are ordinary sections that merely are not
profile-gated — nothing outside their own block reads them. Injecting a decode
error into each collector, before this change, lost the whole audit in seven of
eight cases, and lost it *late*: the fail2ban snapshot aborted after 29 962
bytes had already reached the operator, who then got exit 3 with no score, no
summary and no JSON.

``fw_status`` and ``ports_snapshot`` stay unguarded, and the reason is not the
NameError cascade — it is verdict honesty. Substituting an empty default for
either would not degrade the audit, it would make it lie: an unreadable port
table renders as "nothing is listening". That line is pinned below so it cannot
be crossed by someone tidying up.
"""

from __future__ import annotations

import ast
import contextlib
import io
import pathlib
import tempfile
from unittest import mock

import pytest

from bob import i18n
from bob.cli import parse_args
from bob.config import UserConfig
from bob.profiles import load_profile
from bob.registry import ServiceRegistry
from bob.runner import init_report, run_checks
from bob.scoring import ScoreEngine

_RUNNER = pathlib.Path(__file__).resolve().parent.parent / "bob" / "runner.py"

# Collections that must abort the audit rather than degrade, because an empty
# default for them would be read as fact by nearly every check below.
_DELIBERATELY_UNGUARDED = {"FirewallStatus", "PortsSnapshot"}


def _run_checks_body() -> ast.FunctionDef:
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "run_checks")


def _core_collections() -> dict[str, bool]:
    """Map each core ``X.from_system()`` call to whether it sits in ``_core``.

    Calls inside the nested ``_sec`` helper are excluded: those already have
    the v0.14.1 barrier.
    """
    fn = _run_checks_body()
    sec = next(n for n in ast.walk(fn)
               if isinstance(n, ast.FunctionDef) and n.name == "_sec")
    sec_lines = set(range(sec.lineno,
                          max(x.lineno for x in ast.walk(sec)
                              if hasattr(x, "lineno")) + 1))

    def _span(node) -> set[int]:
        return set(range(node.lineno,
                         max(x.lineno for x in ast.walk(node)
                             if hasattr(x, "lineno")) + 1))

    guarded_lines: set[int] = set()
    for node in ast.walk(fn):
        # `with _core("section"):` — the barrier added in v0.15.0.
        if isinstance(node, ast.With) and any(
            isinstance(i.context_expr, ast.Call)
            and isinstance(i.context_expr.func, ast.Name)
            and i.context_expr.func.id == "_core"
            for i in node.items
        ):
            guarded_lines |= _span(node)
        # A factory handed to `_sec(...)` — including one wrapped in a lambda,
        # as suid_audit is — is invoked inside the v0.14.1 barrier.
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_sec"):
            guarded_lines |= _span(node)

    found: dict[str, bool] = {}
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not isinstance(f, ast.Attribute) or f.attr != "from_system":
            continue
        if node.lineno in sec_lines:
            continue
        cls = ast.unparse(f.value)
        found[cls] = found.get(cls, False) or node.lineno in guarded_lines
    return found


class TestEveryCoreLeafIsGuarded:
    def test_the_core_is_not_uniformly_a_pipeline(self):
        """Sanity: the sweep finds a core to talk about at all."""
        assert len(_core_collections()) >= 10

    def test_every_core_collection_is_guarded_or_listed(self):
        unguarded = {c for c, g in _core_collections().items() if not g}
        assert unguarded == _DELIBERATELY_UNGUARDED, (
            "the set of unguarded core collections changed.\n"
            f"  now unguarded: {sorted(unguarded)}\n"
            f"  expected:      {sorted(_DELIBERATELY_UNGUARDED)}\n"
            "Adding one means a failure there aborts the whole audit; removing "
            "one means an empty default is read as fact. Both need a reason in "
            "the _core docstring."
        )


@pytest.fixture
def audit_with_broken(tmp_path):
    """Run the real audit with one collector raising, and report the outcome."""
    def _run(target: str):
        def boom(*a, **k):
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

        i18n.init("en")
        config = parse_args(["--offline"])
        uc = UserConfig(path=tmp_path / "config.conf")
        engine = ScoreEngine(profile=load_profile("server"))
        report = init_report(config, uc, i18n.t, "0.0.0-test")
        out = io.StringIO()
        with mock.patch(target, side_effect=boom), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            result = run_checks(
                config, i18n.t, engine, report, ServiceRegistry.load(), "unknown",
                profile=load_profile("server"), prev_recurrence={}, user_config=uc,
            )
        return result, engine
    return _run


class TestTheBarrierActuallyWorks:
    """The static guard above proves the barrier is *written*. This proves it
    *runs* — the distinction that let the v0.14.1 barrier be verified by three
    ast-only test files while half the runner went uncovered."""

    def test_a_broken_leaf_degrades_and_the_audit_completes(self, audit_with_broken):
        result, engine = audit_with_broken(
            "bob.checks.hardening.HardeningSnapshot.from_system")
        assert "hardening" in result.degraded_sections
        assert engine.findings, "the audit produced nothing after degrading one section"
        unavailable = [f for f in engine.findings
                       if f.key == "hardening.unavailable"]
        assert unavailable, "the degraded section left no finding behind"
        assert "[" not in unavailable[0].message[:1], \
            "the degradation message rendered as a bare i18n key"

    def test_an_unguarded_core_collection_still_aborts(self, audit_with_broken):
        """Pinned on purpose: this is the honest failure, not an oversight."""
        with pytest.raises(UnicodeDecodeError):
            audit_with_broken("bob.checks.ports.PortsSnapshot.from_system")
