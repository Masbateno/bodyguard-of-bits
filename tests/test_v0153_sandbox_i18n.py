"""v0.15.3 — plugin sandbox messages escaped localisation.

Found by sweeping a surface that had been named as unswept for several
releases and never actually swept: locale keys that no code references.
2151 keys, three genuine orphans — plugin.sandbox.missing_run_check,
bad_return and crashed — translated in both locales and called by nobody.

They were orphans because the conditions they describe were reported with
hardcoded English instead: the worker put a rendered English sentence on the
queue, and SandboxRejected carried English text, both interpolated verbatim
into the ``{error}`` slot of a translated wrapper. A French user read

    Le plugin 'x.py' rejeté : Plugin 'x.py' missing required run_check function

— half English, with the plugin name twice. Same class as the v0.11.2 F8/F8b
pass, on a surface that pass did not cover.

The orphan guard at the bottom is the durable half.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from bob import i18n
from bob._sandbox import _WORKER_FALLBACKS, SandboxRejected, _worker_error
from bob.plugin_checks import PluginCheck

ROOT = Path(__file__).resolve().parent.parent
LOCALES = ("en", "fr")

# Prefixes whose keys are built at runtime, e.g. t(f"explain.{key}.server.why").
# A literal-reference sweep cannot see them; their coverage is a separate
# question (EXPLAIN_KEYS completeness), deliberately not conflated with this
# guard. Keep this list SHORT — every entry is a blind spot.
DYNAMIC_PREFIXES = ("explain.",)


def flat_keys(loc: str) -> set[str]:
    data = json.loads((ROOT / "bob" / "locales" / f"{loc}.json").read_text(encoding="utf-8"))
    out: set[str] = set()

    def walk(node, pre=""):
        for k, v in node.items():
            if isinstance(v, dict):
                walk(v, f"{pre}{k}.")
            else:
                out.add(f"{pre}{k}")

    walk(data)
    return out


def source_blob() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in ROOT.joinpath("bob").rglob("*.py"))


class TestSandboxMessagesAreLocalised:
    @pytest.mark.parametrize(
        "source, expect_key",
        [
            ("X = 1\n", "plugin.sandbox.missing_run_check"),
            ("def run_check(:\n", "plugin.sandbox.syntax_error"),
        ],
    )
    def test_static_rejection_reports_the_specific_key(self, tmp_path, source, expect_key):
        f = tmp_path / "p.py"
        f.write_text(source)
        i18n.init(lang="en")
        res = PluginCheck(f.stem, f).run(t=i18n.t)
        assert [x.key for x in res.findings] == [expect_key]

    @pytest.mark.parametrize(
        "source", ["X = 1\n", "def run_check(:\n"]
    )
    def test_the_french_message_is_actually_french(self, tmp_path, source):
        f = tmp_path / "p.py"
        f.write_text(source)

        def msg(lang):
            i18n.init(lang=lang)
            return PluginCheck(f.stem, f).run(t=i18n.t).findings[0].message

        en, fr = msg("en"), msg("fr")
        assert en != fr, "the message did not change with the locale"
        assert "Le plugin" in fr

    def test_the_plugin_name_is_not_repeated(self, tmp_path):
        """The old wrapper produced "Le plugin 'x.py' rejeté : Plugin 'x.py' …"."""
        f = tmp_path / "twice.py"
        f.write_text("X = 1\n")
        i18n.init(lang="fr")
        assert PluginCheck(f.stem, f).run(t=i18n.t).findings[0].message.count("twice.py") == 1


class TestSandboxRejectedCarriesAKey:
    def test_a_plain_raise_still_works(self):
        """Back-compat: a raise with no key falls back to the generic wrapper."""
        exc = SandboxRejected("something went wrong")
        assert exc.locale_key == ""
        assert exc.params == {}
        assert str(exc) == "something went wrong"

    def test_a_keyed_raise_carries_its_params(self):
        exc = SandboxRejected("boom", locale_key="plugin.sandbox.unreadable",
                              plugin="'p.py'", error="EACCES")
        assert exc.locale_key == "plugin.sandbox.unreadable"
        assert exc.params == {"plugin": "'p.py'", "error": "EACCES"}


class TestWorkerShipsKeysNotSentences:
    def test_worker_error_is_structured(self):
        status, payload = _worker_error(
            "/plugins/foo.py", "plugin.sandbox.bad_return", actual_type="int"
        )
        assert status == "error"
        assert payload["key"] == "plugin.sandbox.bad_return"
        assert payload["params"]["plugin"] == "'foo.py'"
        assert payload["params"]["actual_type"] == "int"
        assert payload["fallback"] == "Plugin 'foo.py' returned int, not CheckResult"

    def test_only_primitives_cross_the_process_boundary(self):
        """Same constraint as the C-2 sanitized result payload."""
        _, payload = _worker_error("/p/x.py", "plugin.sandbox.crashed", error="ValueError: b")
        for value in payload["params"].values():
            assert isinstance(value, (str, int, float, bool, type(None)))

    def test_no_rendered_english_sentence_is_queued(self):
        """The defect itself: a put(("error", "<English sentence>")) call."""
        src = (ROOT / "bob" / "_sandbox.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        offenders = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "put" or not node.args:
                continue
            arg = node.args[0]
            if not (isinstance(arg, ast.Tuple) and len(arg.elts) == 2):
                continue
            first, second = arg.elts
            if not (isinstance(first, ast.Constant) and first.value == "error"):
                continue
            if isinstance(second, (ast.Constant, ast.JoinedStr)):
                offenders.append(node.lineno)
        assert not offenders, f"rendered English queued at lines {offenders}"

    def test_fallbacks_match_the_english_locale(self):
        """The table duplicates en.json because _sandbox_msg needs it when t is
        None; the duplication is guarded rather than trusted."""
        en = json.loads((ROOT / "bob" / "locales" / "en.json").read_text(encoding="utf-8"))
        for key, template in _WORKER_FALLBACKS.items():
            node = en
            for part in key.split("."):
                node = node[part]
            assert node == template, f"{key}: locale says {node!r}, table says {template!r}"


class TestNoOrphanLocaleKeys:
    """The durable half: a locale key nobody references is a promise nobody keeps.

    Three such keys existed here, each masking a hardcoded English string.
    """

    @staticmethod
    def _orphans(loc: str) -> list[str]:
        """Keys with no literal reference and no dynamic construction.

        Dynamic keys are assembled two ways in this codebase, and both must be
        recognised at ANY depth of the path, not just the last parent:

            t(f"service_risk.{svc_id}.level")   -> stem followed by ".{"
            t('help.section.' + key)            -> stem quoted, then concatenated

        Missing either form is how a sweep produces a wall of false positives.
        """
        src = source_blob()
        orphans = []
        for key in sorted(flat_keys(loc)):
            if key.startswith(DYNAMIC_PREFIXES) or key in src:
                continue
            parts = key.split(".")
            if any(
                f"{stem}.{{" in src or f'"{stem}."' in src or f"'{stem}.'" in src
                for stem in (".".join(parts[:i]) for i in range(1, len(parts)))
            ):
                continue
            orphans.append(key)
        return orphans

    @pytest.mark.parametrize("loc", LOCALES)
    def test_no_key_is_defined_and_never_referenced(self, loc):
        orphans = self._orphans(loc)
        assert not orphans, f"{loc}.json defines keys nothing uses: {orphans}"

    def test_the_guard_would_notice_a_new_orphan(self):
        """A sweep that matches everything proves nothing."""
        assert "plugin.sandbox.crashed" in flat_keys("en")
        assert "plugin.sandbox.crashed" in source_blob()
