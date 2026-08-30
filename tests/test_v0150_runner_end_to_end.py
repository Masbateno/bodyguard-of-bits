"""
v0.15.0 — the first test that actually *executes* ``run_checks``.

Until now the suite reached this function only through ``ast``: three files
parse it and assert things about its source. Nothing ran it. That left the
audit's main loop — 38 section call sites, the v0.14.1 fault barrier, and the
snapshot factories feeding every check — covered by inspection alone, which is
how a barrier can be verified to *exist* while never being verified to *work*.

The run is deliberately unprivileged. That is the harsher case: most checks
hit EACCES on /etc/shadow, /root and friends, which is precisely the condition
the barrier and the per-check degradation paths are for. It is also the only
case a test can create without root.

Nothing here asserts a particular finding — the verdicts depend on the host.
What is asserted is what must hold on *any* host.
"""

from __future__ import annotations

import contextlib
import io
import re

import pytest

from bob import i18n
from bob.cli import parse_args
from bob.config import UserConfig
from bob.profiles import load_profile
from bob.registry import ServiceRegistry
from bob.runner import ChecksResult, init_report, run_checks
from bob.scoring import ScoreEngine

# A translation miss renders as the bracketed key itself. This is not
# hypothetical: v0.9.1 was a hotfix for exactly one such string reaching users
# as `[cli.error.json_v1_retired]`, found in a field test after the static
# locale guards had passed.
_BRACKETED_KEY_RE = re.compile(r"\[[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+\]")


@pytest.fixture
def audit(tmp_path):
    """Run the real audit once, isolated from the user's own config."""
    def _run(lang: str):
        i18n.init(lang)
        config = parse_args(["--offline"])
        user_config = UserConfig(path=tmp_path / "config.conf")
        registry = ServiceRegistry.load()
        profile = load_profile("server")
        engine = ScoreEngine(profile=profile)
        report = init_report(config, user_config, i18n.t, "0.0.0-test")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = run_checks(
                config, i18n.t, engine, report, registry, "unknown",
                profile=profile, prev_recurrence={}, user_config=user_config,
            )
        return result, engine, out.getvalue(), err.getvalue()
    yield _run
    i18n.init("en")


class TestRunChecksActuallyRuns:
    def test_it_completes_and_returns_the_documented_shape(self, audit):
        result, engine, _, _ = audit("en")
        assert isinstance(result, ChecksResult)
        assert isinstance(result.degraded_sections, tuple)
        assert all(isinstance(s, str) for s in result.degraded_sections)
        assert isinstance(result.fw_active, bool)
        assert engine.findings, "a full audit produced no finding at all"

    def test_every_finding_carries_a_key(self, audit):
        """The key is what `--explain`, `--ignore` and the JSON output are all
        addressed by; a keyless finding is unreachable by every one of them."""
        _, engine, _, _ = audit("en")
        keyless = [f.message[:70] for f in engine.findings if not f.key]
        assert not keyless, f"findings with no key: {keyless}"

    def test_nothing_is_written_to_stderr(self, audit):
        _, _, _, err = audit("en")
        assert err == "", f"run_checks wrote to stderr: {err[:400]!r}"


class TestNoUntranslatedKeyReachesTheUser:
    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_no_finding_renders_as_a_bare_key(self, audit, lang):
        _, engine, _, _ = audit(lang)
        blob = "\n".join(
            f"{f.message}\n{f.detail}\n{f.note}\n{f.cmd}" for f in engine.findings
        )
        leaked = sorted(set(_BRACKETED_KEY_RE.findall(blob)))
        assert not leaked, f"untranslated keys in {lang}: {leaked}"

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_no_printed_line_renders_as_a_bare_key(self, audit, lang):
        _, _, out, _ = audit(lang)
        leaked = sorted(set(_BRACKETED_KEY_RE.findall(out)))
        assert not leaked, f"untranslated keys printed in {lang}: {leaked}"

    def test_the_two_locales_really_differ(self, audit):
        """Guards the guard: if i18n.init() silently failed, both runs would
        return English and the parametrised tests above would pass for the
        wrong reason."""
        _, en_engine, _, _ = audit("en")
        en = {f.key: f.message for f in en_engine.findings if f.key}
        _, fr_engine, _, _ = audit("fr")
        fr = {f.key: f.message for f in fr_engine.findings if f.key}
        shared = en.keys() & fr.keys()
        assert shared, "no key in common between the two runs"
        assert any(en[k] != fr[k] for k in shared), \
            "every message is identical in both locales — i18n did not switch"


class TestEveryFindingIsAddressableByConstruction:
    """The live audit above can only see the findings *this* host produces.

    Five keyless findings existed when that test was written, and the run
    surfaced exactly one of them — the other four sit on code paths this
    machine does not take. So the runtime check is the discovery tool and this
    static one is the guard: 275 of 280 construction sites passed a key, which
    is the signature of an invariant held by convention rather than by
    construction, and conventions drift one call site at a time.
    """

    _FINDING_METHODS = frozenset({"ok", "info", "warn", "alert", "add_finding"})

    def test_no_finding_is_constructed_without_a_key(self):
        import ast
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "bob"
        offenders = []
        for f in sorted(root.rglob("*.py")):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                if not isinstance(fn, ast.Attribute):
                    continue
                if fn.attr not in self._FINDING_METHODS:
                    continue
                if "result" not in ast.unparse(fn.value):
                    continue
                if any(k.arg == "key" for k in node.keywords):
                    continue
                offenders.append(
                    f"{f.relative_to(root.parent)}:{node.lineno} "
                    f"{ast.unparse(node)[:70]}"
                )
        assert not offenders, (
            "findings constructed without a key — unreachable by --explain, "
            "not suppressible by --ignore, and anonymous in the JSON output:\n  "
            + "\n  ".join(offenders)
        )
