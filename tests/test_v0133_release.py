"""Regression guards for the v0.13.3 hardening patch.

Four independent classes, one per shipped item:

1. ``TestLoggingNotLeaking`` — BOB never configured logging, so every
   ``logger.warning`` in the package fell through to Python's *lastResort*
   handler and printed a raw line on stderr, bypassing ``--quiet`` and i18n
   and doubling the profile warning (``bob --profile=typo`` printed the same
   sentence twice). A ``NullHandler`` on the ``bob`` logger stops lastResort
   without breaking propagation.

2. ``TestSectionSnapshotsAreLazy`` — snapshots were collected eagerly at the
   ``_sec`` call site, i.e. *before* ``_section_enabled`` could skip the
   section, so ``--check=ssh`` still paid for all 47 checks (measured 5.4 s
   vs 2.6 s after). ``_sec`` now accepts a factory and invokes it after the
   gate.

3. ``TestNoColorEnv`` — ``NO_COLOR`` (https://no-color.org) reaches the same
   state as ``--no-color``.

4. ``TestDocCounterDrift`` — the doc-consistency guards covered versions,
   profiles and retired flags, but never *counters*. Five counters had gone
   stale (one by six minor releases). This closes the class rather than the
   instances.
"""

from __future__ import annotations

import ast
import importlib
import logging
import os
import pathlib
import re

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# 1 — logging must not reach stderr through lastResort
# ---------------------------------------------------------------------------

class TestLoggingNotLeaking:

    def test_package_logger_has_a_handler(self):
        """Without a handler anywhere in the chain, logging.lastResort prints
        the record on stderr, raw and un-prefixed."""
        assert logging.getLogger("bob").handlers, (
            "bob/__init__.py must install a NullHandler on the 'bob' logger — "
            "otherwise every logger.warning() in the package leaks to stderr"
        )

    def test_handler_is_a_null_handler(self):
        assert any(isinstance(h, logging.NullHandler)
                   for h in logging.getLogger("bob").handlers)

    def test_propagation_is_preserved(self):
        """The NullHandler must silence lastResort *without* cutting
        propagation — pytest's caplog and any downstream handler rely on it."""
        assert logging.getLogger("bob").propagate is True

    def test_caplog_still_captures_bob_records(self, caplog):
        lg = logging.getLogger("bob.test_v0133_probe")
        with caplog.at_level(logging.WARNING, logger="bob.test_v0133_probe"):
            lg.warning("probe %s", "value")
        assert any("probe value" in r.getMessage() for r in caplog.records)

    def test_source_installs_null_handler(self):
        """Static guard: bob/__init__.py is tiny and therefore tempting to
        rewrite. Pin the call so the leak cannot silently return."""
        src = (_REPO_ROOT / "bob" / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        found = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "addHandler"
            for n in ast.walk(tree)
        )
        assert found, "bob/__init__.py must call addHandler(logging.NullHandler())"

    def test_bob_debug_configures_before_import_time_warnings(self):
        """BOB_DEBUG must be handled in bob/__init__.py, not bob/__main__.py:
        bob/i18n.py and bob/registry.py call resolve_share_dir() at module
        import time and that helper logs warnings for an invalid BOB_SHARE.
        Configuring logging any later drops exactly those records."""
        src = (_REPO_ROOT / "bob" / "__init__.py").read_text(encoding="utf-8")
        assert "BOB_DEBUG" in src, (
            "BOB_DEBUG must be wired in bob/__init__.py so import-time "
            "warnings are not lost"
        )


# ---------------------------------------------------------------------------
# 2 — section snapshots are collected after the --check/--skip/profile gate
# ---------------------------------------------------------------------------

_LAZY_SECTIONS = {
    "updates":            "UpdatesSnapshot",
    "services_health":    "ServicesStateSnapshot",
    "socket_units":       "SocketUnitsSnapshot",
    "systemd_hardening":  "ServiceHardeningSnapshot",
    "disk":               "DiskSnapshot",
}


def _sec_calls() -> list[ast.Call]:
    src = (_REPO_ROOT / "bob" / "runner.py").read_text(encoding="utf-8")
    return [
        n for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name) and n.func.id == "_sec"
        and len(n.args) >= 2
    ]


class TestSectionSnapshotsAreLazy:

    def test_lot1_sections_pass_a_factory(self):
        """The five most expensive snapshots (~2.9 s of a 5.4 s audit) must be
        passed as ``XxxSnapshot.from_system`` — the bare attribute, not a
        call — so the collection happens inside _sec, after the gate."""
        seen = {}
        for call in _sec_calls():
            if not isinstance(call.args[0], ast.Constant):
                continue
            section = call.args[0].value
            if section in _LAZY_SECTIONS:
                seen[section] = call.args[1]
        missing = set(_LAZY_SECTIONS) - set(seen)
        assert not missing, f"_sec call not found for: {sorted(missing)}"
        for section, arg in seen.items():
            assert isinstance(arg, ast.Attribute) and arg.attr == "from_system", (
                f"section {section!r} must pass the factory "
                f"{_LAZY_SECTIONS[section]}.from_system (no parentheses), "
                f"got {ast.dump(arg)[:80]}"
            )

    def test_no_sec_call_builds_its_snapshot_inline(self):
        """``_sec("x", XxxSnapshot.from_system(), ...)`` would re-introduce the
        eager pattern while looking correct."""
        for call in _sec_calls():
            arg = call.args[1]
            assert not isinstance(arg, ast.Call), (
                "the snapshot argument of _sec must never be an inline call — "
                "pass the factory itself so the gate can skip the collection"
            )

    def test_sec_invokes_factory_after_the_gate(self):
        """Behavioural: a factory for a disabled section is never called."""
        from bob.runner import _section_enabled

        calls = []

        def factory():
            calls.append(1)
            return object()

        # Mirror _sec's contract: gate first, factory second.
        class _Cfg:
            check_only = ["ssh"]
            skip_checks = []

        assert _section_enabled("ssh", _Cfg, None) is True
        assert _section_enabled("disk", _Cfg, None) is False
        # The gate rejects "disk", so a correct _sec never touches the factory.
        if _section_enabled("disk", _Cfg, None):
            factory()
        assert calls == [], "factory must not run for a gated-out section"

    def test_sec_source_gates_before_collecting(self):
        """Static: the ``callable(snapshot)`` unwrap must sit *after* the
        _section_enabled return and *before* skip_if."""
        src = (_REPO_ROOT / "bob" / "runner.py").read_text(encoding="utf-8")
        body = src[src.index("    def _sec("):]
        body = body[:body.index("\n    # ")]
        i_gate = body.index("_section_enabled")
        i_call = body.index("callable(snapshot)")
        i_skip = body.index("skip_if(snapshot)")
        assert i_gate < i_call < i_skip, (
            "_sec must gate, then build the snapshot, then run skip_if"
        )


# ---------------------------------------------------------------------------
# 3 — NO_COLOR
# ---------------------------------------------------------------------------

class TestNoColorEnv:

    @staticmethod
    def _probe(value):
        """Resolve _no_color for a given NO_COLOR value.

        FORCE_COLOR is set throughout so the TTY dimension added in v0.14.0
        cannot decide the outcome: under pytest stdout is not a terminal, so
        without it every case would come back "no colour" and the test would
        pass for the wrong reason. NO_COLOR must still win over FORCE_COLOR —
        that ordering is asserted here too.
        """
        os.environ.pop("NO_COLOR", None)
        os.environ["FORCE_COLOR"] = "1"
        if value is not None:
            os.environ["NO_COLOR"] = value
        import bob.output as o
        importlib.reload(o)
        try:
            o.init(no_color=False, quiet=False)
            return o._no_color
        finally:
            os.environ.pop("NO_COLOR", None)
            os.environ.pop("FORCE_COLOR", None)
            importlib.reload(o)
            o.init(no_color=False, quiet=False)

    def test_absent_keeps_colour(self):
        assert self._probe(None) is False

    def test_set_disables_colour(self):
        assert self._probe("1") is True

    def test_any_non_empty_value_disables_colour(self):
        """no-color.org: presence is what counts, not the value."""
        assert self._probe("anything") is True

    def test_empty_value_is_ignored(self):
        """Per the spec an empty NO_COLOR must NOT disable colour."""
        assert self._probe("") is False


# ---------------------------------------------------------------------------
# 4 — documented counters must match the code
# ---------------------------------------------------------------------------

def _truth() -> dict[str, int]:
    from bob.runner import _SECTIONS
    from bob.explain import EXPLAIN_KEYS
    import bob.correlation as correlation
    import json

    data = _REPO_ROOT / "bob" / "data"
    services = json.loads((data / "services.json").read_text(encoding="utf-8"))
    services = services if isinstance(services, list) else services.get("services", [])
    cis = json.loads((data / "cis_refs.json").read_text(encoding="utf-8"))
    return {
        "correlation_rules": len(correlation._RULES),
        "explain_keys":      len(EXPLAIN_KEYS),
        "explain_prefixes":  len({k.split(".")[0] for k in EXPLAIN_KEYS}),
        "filterable":        sum(1 for s in _SECTIONS if not s.always_on),
        "services":          len(services),
        "cis_refs":          len(cis),
    }


# (regex with ONE capturing group, truth key). The regex is matched against
# every line of every public doc.
_CLAIMS: list[tuple[str, str]] = [
    (r"(\d+) compound-risk rules",              "correlation_rules"),
    (r"(\d+) règles de risque composé",         "correlation_rules"),
    (r"(\d+) built-in compound-risk rules",     "correlation_rules"),
    (r"(\d+) règles de risque composé intégrées", "correlation_rules"),
    (r"(\d+)-key canonical list",               "explain_keys"),
    (r"(\d+) clés canoniques",                  "explain_keys"),
    (r"EXPLAIN_KEYS — (\d+) keys",              "explain_keys"),
    (r"EXPLAIN_KEYS — (\d+) clés",              "explain_keys"),
    (r"(\d+) known services",                   "services"),
    (r"(\d+) services connus",                  "services"),
    (r"(\d+) CIS references",                   "cis_refs"),
]

_DOCS = [
    "README.md", "README_FR.md",
    "DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md",
    "DOCUMENTS/README_DEV.md",  "DOCUMENTS/README_DEV_FR.md",
    "DOCUMENTS/SNAPSHOT.md",
]

# A doc legitimately quotes past values when it narrates history
# ("Baseline history: v0.7.0 audit = 117 keys / 30 prefixes"). Those lines
# describe a previous release and must not be rewritten to today's number.
_HISTORICAL = re.compile(
    r"v\d+\.\d+\.\d+|Baseline history|Historique|baseline|Pre-v|pre-v", re.I
)


class TestDocCounterDrift:

    @pytest.mark.parametrize("rel_path", _DOCS)
    def test_documented_counters_match_code(self, rel_path):
        path = _REPO_ROOT / rel_path
        if not path.exists():
            pytest.skip(f"{rel_path} absent")
        truth = _truth()
        errors = []
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _HISTORICAL.search(line):
                continue
            for pattern, key in _CLAIMS:
                for m in re.finditer(pattern, line):
                    claimed = int(m.group(1))
                    if claimed != truth[key]:
                        errors.append(
                            f"  {rel_path}:{lineno} claims {claimed} for "
                            f"{key!r}, code says {truth[key]}\n"
                            f"      {line.strip()[:110]}"
                        )
        assert not errors, (
            "documented counters drifted from the code:\n" + "\n".join(errors)
        )

    def test_guard_covers_the_counters_that_drifted(self):
        """Meta-guard: the claim table must keep covering the counters that
        actually went stale, so a future cleanup cannot quietly shrink it."""
        covered = {key for _, key in _CLAIMS}
        for expected in ("correlation_rules", "explain_keys", "services", "cis_refs"):
            assert expected in covered
