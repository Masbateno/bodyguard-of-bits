"""
Locale key coverage — guard against the v0.4.3 regression where `logs.attempts`
was removed from both locale files but still referenced by 7 call sites in
display.py. The terrain test caught it as `[logs.attempts]` sentinel output.

This test scans every ``.py`` file in ``bob/`` for ``t("KEY")`` and ``_t("KEY")``
calls, collects the keys, and asserts each one resolves in both en.json AND
fr.json. Locale parity prevents the "translated to English on French system"
silent fallback.

Allowlist mechanism: keys constructed dynamically (e.g.
``_t(f"services.exposure.{exposure.value}")``) are detected as patterns and
expanded via ``_DYNAMIC_PATTERNS`` below — extend the list when you add a new
dynamic call site.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_BOB_DIR   = _REPO_ROOT / "bob"
_LOCALES   = _BOB_DIR / "locales"

# t("foo.bar") or _t("foo.bar") or _t('foo.bar').
# The negative lookbehind excludes [A-Za-z0-9_.] before the (optional) leading
# underscore — the dot stops `obj._t(...)` matching, while still accepting
# bare ``t(...)`` and ``_t(...)`` at start-of-line or after whitespace.
_T_CALL_RE = re.compile(
    r"""(?<![A-Za-z0-9_.])
        _?t                       # t( or _t(
        \(\s*
        (?:["']                   # opening quote
           ([A-Za-z_][A-Za-z0-9_.]*)   # the key
        ["'])
    """,
    re.VERBOSE,
)

# Keys we exclude because they're either passed dynamically through an alias
# table, built at runtime, or appear only as docstring examples in i18n.py.
_KEY_EXCLUSIONS: frozenset[str] = frozenset({
    # Docstring example in bob/i18n.py demonstrating t() usage.
    "samba.open_world",
    # Docstring example in bob/i18n.py demonstrating t() with placeholders.
    "log.blocked_attempts",
})

# Dynamic key prefixes: every key starting with one of these is presumed to
# have its values declared as a nested dict (e.g. ``services.exposure.*``) and
# we verify the parent prefix exists rather than each leaf. Each entry is
# (prefix, locale_path_in_dot_notation) — at audit time the resolver will
# emit any leaf-key dynamically based on enum/runtime values.
#
# Note: ``explain.*`` is NOT bypassed here — it is exhaustively covered by
# ``test_explain_keys_have_full_locale_content`` below, which generates the
# expected leaves from the frozen ``EXPLAIN_KEYS`` list.
_DYNAMIC_PREFIXES: tuple[tuple[str, str], ...] = (
    # services.exposure.{OPEN_WORLD,DENY,NO_RULE,LOOPBACK,...}
    ("services.exposure.", "services.exposure"),
    # services.state.{ACTIVE_ENABLED,INACTIVE_DISABLED,...} — already partly
    # covered by static t() calls but the suffix is also used dynamically.
    ("services.state.", "services.state"),
)


def _all_t_keys() -> set[str]:
    """Collect every static literal key used in t()/_t() across bob/."""
    keys: set[str] = set()
    for py in _BOB_DIR.rglob("*.py"):
        if py.name.startswith("_test") or "tests" in py.parts:
            continue
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in _T_CALL_RE.finditer(text):
            key = m.group(1)
            if key and "." in key and key not in _KEY_EXCLUSIONS:
                keys.add(key)
    return keys


def _resolve_dotted(d: dict, dotted: str):
    """Walk a nested dict by dotted path. Return None if any segment missing."""
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _load_locale(name: str) -> dict:
    return json.loads((_LOCALES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def en_data() -> dict:
    return _load_locale("en.json")


@pytest.fixture(scope="module")
def fr_data() -> dict:
    return _load_locale("fr.json")


@pytest.fixture(scope="module")
def static_keys() -> set[str]:
    return _all_t_keys()


def _is_dynamic_prefix_match(key: str) -> bool:
    return any(key.startswith(prefix) for prefix, _ in _DYNAMIC_PREFIXES)


class TestLocaleCoverage:
    def test_every_static_key_resolves_in_english(self, static_keys, en_data):
        """Every literal t("...") key in bob/ must exist in en.json."""
        missing: list[str] = []
        for key in sorted(static_keys):
            if _is_dynamic_prefix_match(key):
                continue
            if _resolve_dotted(en_data, key) is None:
                missing.append(key)
        assert not missing, (
            "Keys referenced by t(...) but missing from en.json:\n  "
            + "\n  ".join(missing)
        )

    def test_every_static_key_resolves_in_french(self, static_keys, fr_data):
        """Every literal t("...") key in bob/ must exist in fr.json."""
        missing: list[str] = []
        for key in sorted(static_keys):
            if _is_dynamic_prefix_match(key):
                continue
            if _resolve_dotted(fr_data, key) is None:
                missing.append(key)
        assert not missing, (
            "Keys referenced by t(...) but missing from fr.json:\n  "
            + "\n  ".join(missing)
        )

    def test_locale_parity_en_fr(self, en_data, fr_data):
        """en.json and fr.json must have identical key sets (regardless of value).

        This catches one-sided locale additions/removals at the structural
        level. The two .test_every_static_key_resolves_in_* tests above catch
        the "key in code but missing from locale" direction.
        """
        en_keys = _flatten(en_data)
        fr_keys = _flatten(fr_data)
        only_en = en_keys - fr_keys
        only_fr = fr_keys - en_keys
        assert not (only_en or only_fr), (
            f"Locale parity broken.\n"
            f"In en.json only ({len(only_en)}): {sorted(only_en)[:10]}\n"
            f"In fr.json only ({len(only_fr)}): {sorted(only_fr)[:10]}"
        )

    def test_dynamic_prefixes_have_locale_sections(self, en_data, fr_data):
        """Each declared dynamic prefix must have its parent dict in both locales."""
        for prefix, locale_path in _DYNAMIC_PREFIXES:
            assert _resolve_dotted(en_data, locale_path) is not None, (
                f"Dynamic prefix '{prefix}' expects en.json[{locale_path}] "
                "to be a nested dict — missing."
            )
            assert _resolve_dotted(fr_data, locale_path) is not None, (
                f"Dynamic prefix '{prefix}' expects fr.json[{locale_path}] "
                "to be a nested dict — missing."
            )

    def test_static_key_corpus_size_baseline(self, static_keys):
        """Sanity: we collected a meaningful number of keys from bob/.

        Below 200 means our regex broke or bob/ shrank dramatically; either
        way investigate before trusting the other tests.
        """
        assert len(static_keys) >= 200, (
            f"Static key collection looks broken: only {len(static_keys)} keys. "
            "Did the regex break or did bob/ shrink?"
        )


# ---------------------------------------------------------------------------
# Exhaustive coverage of the explain.* namespace (v0.4.4 — closes the blind
# spot the previous _DYNAMIC_PREFIXES had on this subtree).
#
# bob/explain.py builds keys dynamically as ``f"explain.{norm}.title"`` etc.,
# so the regex-based scanner above never sees them. Instead of bypassing the
# whole namespace (which previously made the test silently ignore any missing
# explain entry), we generate the expected leaf paths from the frozen
# EXPLAIN_KEYS list itself.
# ---------------------------------------------------------------------------

class TestExplainNamespaceCoverage:
    @pytest.fixture(scope="class")
    def explain_leaves(self) -> list[str]:
        """Expected dotted paths in en.json / fr.json for every explain entry."""
        from bob.explain import EXPLAIN_KEYS
        leaves: list[str] = []
        for key in EXPLAIN_KEYS:
            for suffix in ("title", "why", "how"):
                leaves.append(f"explain.{key}.{suffix}")
        return leaves

    def test_explain_keys_have_full_locale_content_en(self, explain_leaves, en_data):
        missing = [p for p in explain_leaves if _resolve_dotted(en_data, p) is None]
        assert not missing, (
            f"Missing explain entries in en.json ({len(missing)}):\n  "
            + "\n  ".join(missing[:20])
            + ("\n  ..." if len(missing) > 20 else "")
        )

    def test_explain_keys_have_full_locale_content_fr(self, explain_leaves, fr_data):
        missing = [p for p in explain_leaves if _resolve_dotted(fr_data, p) is None]
        assert not missing, (
            f"Missing explain entries in fr.json ({len(missing)}):\n  "
            + "\n  ".join(missing[:20])
            + ("\n  ..." if len(missing) > 20 else "")
        )

    def test_explain_leaves_are_non_empty_strings(self, explain_leaves, en_data, fr_data):
        """Defence in depth: not just present, but actually translated."""
        for path in explain_leaves:
            for locale_name, data in (("en", en_data), ("fr", fr_data)):
                val = _resolve_dotted(data, path)
                assert isinstance(val, str) and val.strip(), (
                    f"{locale_name}.json[{path}] must be a non-empty string, "
                    f"got {val!r}"
                )


# ---------------------------------------------------------------------------
# Placeholder parity (v0.4.4 — guards against the runtime crash class where
# en.json says "{count}" but fr.json says "{cnt}" or omits the placeholder).
#
# A string-style placeholder is anything matching ``{name}`` (Python format
# spec). The test asserts that for every key present in both locales as a
# string, the *set* of placeholder names is identical. We don't care about
# order — argument-style str.format is name-based.
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _common_string_leaves(en: dict, fr: dict) -> list[tuple[str, str, str]]:
    """Yield (dotted_path, en_value, fr_value) for every key string-in-both.

    Skip leaves that aren't strings on at least one side — the parity test
    above catches those separately.
    """
    en_flat = _flatten_with_values(en)
    fr_flat = _flatten_with_values(fr)
    common = en_flat.keys() & fr_flat.keys()
    out: list[tuple[str, str, str]] = []
    for path in common:
        ev, fv = en_flat[path], fr_flat[path]
        if isinstance(ev, str) and isinstance(fv, str):
            out.append((path, ev, fv))
    return out


def _flatten_with_values(d: dict, prefix: str = "") -> dict[str, object]:
    """Flatten nested dict; preserve leaf values (not just keys)."""
    out: dict[str, object] = {}
    for k, v in d.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_with_values(v, full))
        else:
            out[full] = v
    return out


class TestPlaceholderParity:
    """Reject ``{count}`` vs ``{cnt}`` divergence between en.json and fr.json.

    Mismatches here surface as ``KeyError`` at runtime when ``str.format`` is
    called with the kwargs the call site supplies. That's a hard crash on a
    French audit — exactly the silent-fallback class of bug we got bitten by
    in v0.4.3 with ``logs.attempts``.
    """

    def test_every_common_string_has_matching_placeholders(self, en_data, fr_data):
        mismatches: list[str] = []
        for path, en_val, fr_val in _common_string_leaves(en_data, fr_data):
            en_phs = set(_PLACEHOLDER_RE.findall(en_val))
            fr_phs = set(_PLACEHOLDER_RE.findall(fr_val))
            if en_phs != fr_phs:
                only_en = en_phs - fr_phs
                only_fr = fr_phs - en_phs
                mismatches.append(
                    f"{path}: only EN={sorted(only_en)} only FR={sorted(only_fr)}"
                )
        assert not mismatches, (
            "Placeholder set mismatch between en.json and fr.json:\n  "
            + "\n  ".join(mismatches)
        )


def _flatten(d: dict, prefix: str = "") -> set[str]:
    """Flatten nested dict to dotted-key set."""
    out: set[str] = set()
    for k, v in d.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out |= _flatten(v, full)
        else:
            out.add(full)
    return out
