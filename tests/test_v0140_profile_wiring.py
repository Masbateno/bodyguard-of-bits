"""v0.14.0 E — the audit profile must reach every check result.

Pre-v0.14.0 the caller was responsible for invoking ``apply_profile`` before
``engine.apply``. In ``bob/runner.py`` only 2 of the 14 ``engine.apply()``
sites did: the generic ``_sec`` helper and the plugin path. The 12
hand-rolled always-on sections (firewall, firewall_rules, ufw_logging,
firewall_iptables, firewall_drivers, network_context, services, ports, logs,
ddns, docker, virtualization) never applied it.

Consequence, measured on a live host before the fix: 8 overrides shipped in
desktop.conf and workstation.conf were dead —

    ddns.warn                           = info
    services.exposed.avahi              = info
    services.exposure.open_local        = info
    firewall_drivers.ip_forward_enabled = info

``services.exposure.open_local`` stayed WARN on every profile. Since
``warn_count`` counts by *level* and ``bob/__main__.py`` maps
``warn_count > 0`` to EXIT_WARNINGS, a host running Samba restricted to the
LAN by a UFW rule — the recommended configuration — could never return
exit 0, although 0 is documented as "No issues detected" and the exit codes
are a stable public API.

The fix moves the call into ``ScoreEngine.apply``, the single choke point
every result passes through. These tests pin the behaviour, not the shape:
the previous design was "correct" at every call site that remembered.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from bob.profiles import load_profile
from bob.scoring import CheckResult, FindingLevel, ScoreEngine

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The four overrides that were dead, with the profiles that declare them.
_FORMERLY_DEAD = [
    "ddns.warn",
    "services.exposed.avahi",
    "services.exposure.open_local",
    "firewall_drivers.ip_forward_enabled",
]


class TestEngineCarriesProfile:

    def test_engine_without_profile_leaves_findings_untouched(self):
        r = CheckResult()
        r.warn(message="m", nature="structural", key="services.exposure.open_local")
        e = ScoreEngine()
        e.apply(r)
        assert e.findings[0].level is FindingLevel.WARN

    def test_engine_with_profile_applies_the_override(self):
        r = CheckResult()
        r.warn(message="m", nature="structural", key="services.exposure.open_local")
        e = ScoreEngine(profile=load_profile("desktop"))
        e.apply(r)
        assert e.findings[0].level is FindingLevel.INFO, (
            "the desktop profile declares services.exposure.open_local = info; "
            "engine.apply must honour it"
        )

    def test_server_profile_keeps_the_strict_default(self):
        """server.conf ships zero overrides on purpose — it is the baseline."""
        r = CheckResult()
        r.warn(message="m", nature="structural", key="services.exposure.open_local")
        e = ScoreEngine(profile=load_profile("server"))
        e.apply(r)
        assert e.findings[0].level is FindingLevel.WARN

    def test_downgrade_to_info_drops_the_deduction(self):
        """A profile downgrade must remove the score impact, not just the label."""
        r = CheckResult()
        r.warn(message="m", nature="action", key="services.exposed.avahi")
        r.add_deduction(reason="x", points=2, key="services.exposed.avahi")
        e = ScoreEngine(profile=load_profile("desktop"))
        e.apply(r)
        assert e.findings[0].level is FindingLevel.INFO
        assert not e.breakdown, "deductions must go with the downgraded finding"
        assert e.score == 10

    def test_apply_is_idempotent(self):
        """The old contract allowed a manual apply_profile before engine.apply.
        That combination must not double-punish a result."""
        from bob.profiles import apply_profile
        prof = load_profile("desktop")
        r = CheckResult()
        r.warn(message="m", nature="structural", key="services.exposure.open_local")
        apply_profile(r, prof)
        e = ScoreEngine(profile=prof)
        e.apply(r)
        assert [f.level for f in e.findings] == [FindingLevel.INFO]

    @pytest.mark.parametrize("profile_name", ["desktop", "workstation"])
    @pytest.mark.parametrize("key", _FORMERLY_DEAD)
    def test_formerly_dead_overrides_now_reach_the_engine(self, profile_name, key):
        prof = load_profile(profile_name)
        if prof.override_for(key) is None:
            pytest.skip(f"{profile_name} does not override {key}")
        r = CheckResult()
        r.warn(message="m", nature="action", key=key)
        e = ScoreEngine(profile=prof)
        e.apply(r)
        assert e.findings[0].level is FindingLevel.INFO, (
            f"{profile_name}.conf declares {key} = info but the engine did not "
            "apply it — the v0.14.0 wiring regressed"
        )


class TestRunnerDelegatesToTheEngine:

    def test_runner_does_not_apply_the_profile_itself(self):
        """Re-introducing a call site is how the 12 sections drifted apart.

        A single choke point is the whole point of the fix: if runner.py
        starts calling apply_profile again, the next hand-rolled section will
        be written without it and the class of bug returns.
        """
        src = (_REPO_ROOT / "bob" / "runner.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "apply_profile"
        ]
        assert not calls, (
            "bob/runner.py must not call apply_profile — ScoreEngine.apply "
            "does it for every result, including the always-on sections"
        )

    def test_every_scoreengine_construction_passes_a_profile(self):
        """Both live construction sites must hand the profile over, or the
        sections they feed silently lose their overrides again."""
        offenders = []
        for rel in ("bob/__main__.py", "bob/watch.py"):
            src = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(src)):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "ScoreEngine"):
                    kw = {k.arg for k in node.keywords}
                    if "profile" not in kw:
                        offenders.append(f"{rel}:{node.lineno}")
        assert not offenders, (
            "ScoreEngine built without profile= at: " + ", ".join(offenders)
        )
