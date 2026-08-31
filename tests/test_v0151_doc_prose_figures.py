"""
v0.15.1 — the documentation states figures no guard was checking.

The existing doc guards cover version consistency, relative links, EN/FR parity
and the test count. None of them reads a sentence like *"the file contains
exactly 2008 keys"* and compares it to the file. Six such claims had drifted,
two of them asserted as verified:

    README_DEV      "contains exactly 2008 keys"      -> 2034
    TUTORIAL        "1941 keys × 2 locales"           -> 2034
    TUTORIAL        "168 keys at v0.8.x"              -> 169, and seven
                                                        versions out of date
    README_DEV      "profile variants (19 keys × 3)"  -> 70
    README_TECH     "19 keys"                         -> 70
    README_DEV      file tree                          -> no bob/checks/_ufw.py

The last one is the reason the tree matters: `_ufw.py` is where the UFW rule
grammar lives after v0.15.1 unified five copies of it, and a developer reading
the tree would not have known it existed.

Historical figures are left alone. `README_TECH` says "Baseline history: v0.7.0
audit = 117 keys / 30 prefixes", which is a statement about v0.7.0 and is
correct as such — this guard only reads claims phrased in the present tense.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _locale_key_count() -> int:
    def flatten(d, prefix=""):
        out = {}
        for k, v in d.items():
            full = f"{prefix}.{k}" if prefix else k
            out.update(flatten(v, full)) if isinstance(v, dict) else out.setdefault(full, v)
        return out
    return len(flatten(json.loads(
        (_ROOT / "bob" / "locales" / "en.json").read_text(encoding="utf-8"))))


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


class TestLocaleKeyCount:
    @pytest.mark.parametrize("rel,pattern", [
        ("DOCUMENTS/README_DEV.md",    r"contains exactly (\d{3,5}) keys"),
        ("DOCUMENTS/README_DEV_FR.md", r"contient exactement (\d{3,5}) clés"),
        ("DOCUMENTS/TUTORIAL.md",      r"(\d{3,5}) keys × 2 locales"),
        ("DOCUMENTS/TUTORIAL_FR.md",   r"(\d{3,5}) clés × 2 locales"),
    ])
    def test_the_documented_count_matches_the_file(self, rel, pattern):
        m = re.search(pattern, _read(rel))
        assert m, f"{rel}: no locale-key figure matching {pattern!r}"
        assert int(m.group(1)) == _locale_key_count(), (
            f"{rel} states {m.group(1)} locale keys, en.json holds "
            f"{_locale_key_count()}")


class TestExplainFigures:
    def _counts(self):
        from bob.explain import EXPLAIN_KEYS
        return len(EXPLAIN_KEYS), len({k.split(".")[0] for k in EXPLAIN_KEYS})

    @pytest.mark.parametrize("rel", ["DOCUMENTS/README_DEV.md",
                                     "DOCUMENTS/README_DEV_FR.md",
                                     "DOCUMENTS/README_TECH.md",
                                     "DOCUMENTS/README_TECH_FR.md",
                                     "DOCUMENTS/TUTORIAL.md",
                                     "DOCUMENTS/TUTORIAL_FR.md"])
    def test_the_key_count_is_current(self, rel):
        keys, _ = self._counts()
        text = _read(rel)
        stated = {int(n) for n in re.findall(r"(\d{2,4})[ -](?:explainable )?(?:keys|clés)", text)}
        # Only figures in the same order of magnitude are claims about
        # EXPLAIN_KEYS; the locale count and profile-variant count are checked
        # by their own tests above and below.
        candidates = {n for n in stated if 100 <= n < 1000}
        stale = {n for n in candidates if n != keys}
        # 117 is the documented v0.7.0 baseline and is historical.
        stale -= {117}
        assert not stale, f"{rel} states {sorted(stale)} explain keys, there are {keys}"

    @pytest.mark.parametrize("rel", ["DOCUMENTS/README_DEV.md",
                                     "DOCUMENTS/README_TECH.md"])
    def test_the_prefix_count_is_current(self, rel):
        _, prefixes = self._counts()
        stated = {int(n) for n in re.findall(r"(\d{2,3}) prefixes", _read(rel))}
        stale = {n for n in stated if n != prefixes} - {30}   # 30 = v0.7.0 baseline
        assert not stale, f"{rel} states {sorted(stale)} prefixes, there are {prefixes}"


class TestProfileVariantCount:
    @pytest.mark.parametrize("rel,pattern", [
        ("DOCUMENTS/README_DEV.md",    r"profile variants \((\d+) keys × 3 profiles\)"),
        ("DOCUMENTS/README_DEV_FR.md", r"variantes par profil \((\d+) clés × 3 profils\)"),
    ])
    def test_it_matches_the_real_mechanism(self, rel, pattern):
        from bob import i18n
        from bob.explain import EXPLAIN_KEYS, _has_profile_variants
        i18n.init("en")
        real = sum(1 for k in EXPLAIN_KEYS if _has_profile_variants(k, i18n.t))
        m = re.search(pattern, _read(rel))
        assert m, f"{rel}: no profile-variant figure matching {pattern!r}"
        assert int(m.group(1)) == real, (
            f"{rel} states {m.group(1)} keys with profile variants, "
            f"the mechanism reports {real}")


class TestServiceRegistryCount:
    @pytest.mark.parametrize("rel", ["README.md", "README_FR.md",
                                     "DOCUMENTS/README_DEV.md",
                                     "DOCUMENTS/README_DEV_FR.md"])
    def test_the_documented_service_count_is_current(self, rel):
        registry = json.loads((_ROOT / "bob" / "data" / "services.json")
                              .read_text(encoding="utf-8"))
        real = len(registry if isinstance(registry, list)
                   else registry.get("services", []))
        stated = {int(n) for n in re.findall(r"(\d{2}) services", _read(rel))}
        stale = {n for n in stated if n != real}
        assert not stale, f"{rel} states {sorted(stale)} services, the registry holds {real}"


class TestFileTreeInventory:
    @pytest.mark.parametrize("rel", ["DOCUMENTS/README_DEV.md",
                                     "DOCUMENTS/README_DEV_FR.md"])
    def test_every_shared_checks_helper_appears_in_the_tree(self, rel):
        text = _read(rel)
        helpers = sorted(p.name for p in (_ROOT / "bob" / "checks").glob("_*.py")
                         if p.name != "__init__.py")
        missing = [h for h in helpers if h not in text]
        assert not missing, (
            f"{rel} does not list {missing} — a developer reading the tree "
            "would not know the module exists")
