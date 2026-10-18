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
    """The sentence names which profile sections exist, and for how many keys.

    It used to say "71 keys × 3 profiles" while two of the 71 had no container
    section (v0.25.1). The figure was right and the multiplication was not, so
    the guard reads every number in the sentence and the mix it names. Since
    v0.25.1 the two keys whose only prose is `container` are rendered too
    (after the generic text), so they are counted.
    """

    @pytest.mark.parametrize("rel,pattern", [
        ("DOCUMENTS/README_DEV.md",
         r"per-profile prose for (\d+) keys \(server, desktop and container "
         r"sections for (\d+) of them, server and desktop for (\d+), "
         r"container only for (\d+)"),
        ("DOCUMENTS/README_DEV_FR.md",
         r"prose par profil pour (\d+) clés \(sections server, desktop et "
         r"container pour (\d+) d'entre elles, server et desktop pour (\d+), "
         r"container seule pour (\d+)"),
    ], ids=["en", "fr"])
    def test_it_matches_the_real_mechanism(self, rel, pattern):
        from bob import i18n
        from bob.explain import EXPLAIN_KEYS
        i18n.init("en")

        def written(key, profile):
            path = f"explain.{key}.{profile}.why"
            return i18n.t(path) not in (path, f"[{path}]")

        profiles = ("server", "desktop", "workstation", "container")
        mixes = {k: tuple(p for p in profiles if written(k, p)) for k in EXPLAIN_KEYS}
        mixes = {k: m for k, m in mixes.items() if m}
        named = {("server", "desktop", "container"): 1, ("server", "desktop"): 2, ("container",): 3}
        unnamed = sorted(k for k, m in mixes.items() if m not in named)
        assert not unnamed, (
            f"{unnamed} carry a mix of profile sections the sentence does not name")
        real = (len(mixes),) + tuple(
            sum(1 for m in mixes.values() if named[m] == i) for i in (1, 2, 3))
        m = re.search(pattern, _read(rel))
        assert m, f"{rel}: no profile-variant figure matching {pattern!r}"
        stated = tuple(int(g) for g in m.groups())
        assert stated == real, (
            f"{rel} states {stated} (keys with prose; three sections; server and "
            f"desktop; container only), the mechanism reports {real}")

    def test_container_only_prose_is_rendered(self, capsys):
        from bob import i18n
        from bob.explain import run_explain
        i18n.init("en")
        run_explain("hardening.protected_fifos_disabled", i18n.t)
        assert "Host kernel setting" in capsys.readouterr().out


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
