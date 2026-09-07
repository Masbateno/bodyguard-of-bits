"""README_TECH{,_FR}.md must agree with the code on everything countable.

An agent audit of README_TECH.md in v0.16.3 returned 20 verified defects. None
of them could have been caught by the guards that existed: those check numbers
that someone thought to pin, and every one of these was a number, a name or a
list that nobody had.

What is enumerable is guarded here — JSON keys, CLI options, services,
prefixes, counts. What is prose ("--fix proposes and applies corrections",
against a dry run) is not, and stays a reading job. The line between the two is
the point of this file: it exists so the countable half never drifts again.

Both locales, always. Four of the twenty were present in EN and FR alike,
because a correction pass had touched one file and not the other.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DOCS = {
    "en": _ROOT / "DOCUMENTS" / "README_TECH.md",
    "fr": _ROOT / "DOCUMENTS" / "README_TECH_FR.md",
}
LOCALES = sorted(_DOCS)


def _doc(lang: str) -> str:
    return _DOCS[lang].read_text(encoding="utf-8")


def _table_keys(text: str) -> set[str]:
    """Every ``| `key` |`` cell opening a table row.

    ``[a-z0-9_]`` and not ``[a-z_]``: the first version of this helper silently
    dropped ``ipv6`` and ``fail2ban`` because their names carry a digit, and
    reported two keys as undocumented that were documented all along.
    """
    return set(re.findall(r"^\|\s*`([a-z0-9_]+)`\s*\|", text, re.M))


# ---------------------------------------------------------------------------
# JSON schema v3
# ---------------------------------------------------------------------------

class TestEveryPublishedJsonKeyIsDocumented:
    """Five required keys were absent: a consumer cannot read what it cannot find."""

    @pytest.mark.parametrize("lang", LOCALES)
    def test_required_keys(self, lang):
        from bob.json_output import SCHEMA_V3_REQUIRED_KEYS as REQ
        missing = sorted(k for k in REQ if k not in _table_keys(_doc(lang)))
        assert not missing, f"{lang}: required v3 keys with no table row: {missing}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_full_mode_keys(self, lang):
        from bob.json_output import SCHEMA_V3_FULL_KEYS as FULL
        missing = sorted(k for k in FULL if k not in _table_keys(_doc(lang)))
        assert not missing, f"{lang}: --json-full keys with no table row: {missing}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_no_schema_row_names_a_key_the_payload_never_emits(self, lang):
        """`firewall_stack` was a documented row for three majors after the rename.

        It became `firewall_drivers` in v0.9.0; a consumer following the
        document took a KeyError. Scoped to the two schema tables on purpose —
        run over the whole file this needs a whitelist of exit codes and
        enum values, and a guard maintained by widening its whitelist stops
        being a guard.

        The old name survives as prose inside the replacement row, so this
        reads the row *opener*, which is the part a consumer copies.
        """
        from bob.json_output import (
            SCHEMA_V3_REQUIRED_KEYS as REQ, SCHEMA_V3_FULL_KEYS as FULL,
        )
        doc = _doc(lang)
        emitted = REQ | FULL | {"schema_version"}
        ghosts = []
        for anchor in ("| `score_is_upper_bound` |", "| `open_ports_all` |"):
            i = doc.index(anchor)
            first = doc.rindex("\n|---", 0, i)
            last  = doc.index("\n\n", i)
            for row in doc[first:last].splitlines():
                m = re.match(r"\|\s*`([a-z0-9_]+)`\s*\|", row)
                if m and m.group(1) not in emitted:
                    ghosts.append(m.group(1))
        assert not ghosts, (
            f"{lang}: schema table rows for keys the payload never emits: "
            f"{sorted(set(ghosts))}"
        )


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

def _advertised_options() -> set[str]:
    out = subprocess.run(
        [sys.executable, "-m", "bob", "--help"],
        capture_output=True, text=True, cwd=str(_ROOT),
    ).stdout
    found = set(re.findall(r"(--[a-z0-9][a-z0-9-]+)", out))
    assert len(found) > 30, f"only {len(found)} options scraped — the regex broke"
    return found


class TestTheOptionsReferenceIsComplete:
    """19 of 43 options were missing — undiscoverable to a reader of the reference."""

    @pytest.mark.parametrize("lang", LOCALES)
    def test_every_option_has_a_row(self, lang):
        doc = _doc(lang)
        heading = "## Options reference" if "## Options reference" in doc else "## Référence des options"
        start = doc.index(heading)
        end   = doc.index("\n## ", start + 5)
        section = doc[start:end]
        # Word-bounded: a plain `in` test is satisfied by `--targetXX`, so a
        # renamed row would keep the guard green while the option it documents
        # no longer exists. The boundary class must include A-Z — the first
        # version used [a-z0-9-] and `--targetXX` sailed through it, which the
        # mutation bench caught and a green run would not have.
        missing = sorted(
            o for o in _advertised_options()
            if not re.search(rf"(?<![A-Za-z0-9-]){re.escape(o)}(?![A-Za-z0-9-])", section)
        )
        assert not missing, f"{lang}: options absent from the reference table: {missing}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_no_row_invents_an_option(self, lang):
        doc = _doc(lang)
        heading = "## Options reference" if "## Options reference" in doc else "## Référence des options"
        start = doc.index(heading)
        end   = doc.index("\n## ", start + 5)
        listed = set(re.findall(r"(--[a-z0-9][a-z0-9-]+)", doc[start:end]))
        ghosts = sorted(listed - _advertised_options())
        assert not ghosts, f"{lang}: reference rows for options --help does not offer: {ghosts}"


# ---------------------------------------------------------------------------
# Enumerable catalogues
# ---------------------------------------------------------------------------

class TestTheCataloguesMatch:

    @pytest.mark.parametrize("lang", LOCALES)
    def test_every_service_has_a_row(self, lang):
        """The table carried 31 rows for 38 shipped services.

        Matched on the service *id* at word boundaries, not as a substring:
        the first version of this guard accepted a row renamed to "OllamaXX"
        because "ollama" is still in there, and a guard that a rename slips
        past is not one. Ids rather than labels because the French table
        translates the labels.
        """
        raw = json.loads((_ROOT / "bob" / "data" / "services.json").read_text(encoding="utf-8"))
        entries = raw if isinstance(raw, list) else list(raw.values())
        doc = _doc(lang)
        i = doc.index("| RDP / xRDP")
        table = doc[doc.rindex("\n## ", 0, i):doc.index("\n## ", i)].lower()
        missing = []
        for e in entries:
            # Either the id (`adguard_home`) or the proper-noun part of the
            # label (`Home Assistant`, whose id is `homeassistant`). The French
            # table translates the descriptive half but keeps the proper noun.
            candidates = [re.escape(e["id"]).replace("_", "[ _-]?")]
            label = (e.get("label") or "").split("(")[0].strip().lower()
            if label:
                candidates.append(re.escape(label))
            if not any(re.search(rf"\b{c}\b", table) for c in candidates):
                missing.append(e["id"])
        assert not missing, f"{lang}: services with no table row: {missing}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_prefix_vocabulary_is_exact(self, lang):
        """Six prefixes named there did not exist; ten that did were absent."""
        from bob.explain import EXPLAIN_KEYS
        real = {k.split(".", 1)[0] for k in EXPLAIN_KEYS}
        pattern = (r"Prefix vocabulary \((\d+) prefixes, alphabetically\): `([^`]+)`"
                   if lang == "en" else
                   r"Vocabulaire des préfixes \((\d+) préfixes, alphabétique\) : `([^`]+)`")
        m = re.search(pattern, _doc(lang))
        assert m, f"{lang}: the prefix vocabulary sentence is gone or reshaped"
        listed = {x.strip() for x in m.group(2).split(",")}
        assert listed == real, (
            f"{lang}: ghosts={sorted(listed - real)} missing={sorted(real - listed)}"
        )
        assert int(m.group(1)) == len(real), (
            f"{lang}: the sentence says {m.group(1)} prefixes, there are {len(real)}"
        )

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_cis_reference_counts(self, lang):
        """"174 entries (107 CIS, 60 best-practice, 7 Docker)" against 192 (108/77/7)."""
        raw = json.loads((_ROOT / "bob" / "data" / "cis_refs.json").read_text(encoding="utf-8"))
        total = len(raw)
        pattern = (r"(\d+) entries \((\d+) formal CIS, (\d+) best-practice, (\d+) Docker\)"
                   if lang == "en" else
                   r"(\d+) entrées \((\d+) CIS formels, (\d+) best-practice, (\d+) Docker\)")
        m = re.search(pattern, _doc(lang))
        assert m, f"{lang}: the CIS reference count sentence is gone or reshaped"
        assert int(m.group(1)) == total, (
            f"{lang}: the document says {m.group(1)} CIS entries, the file holds {total}"
        )
        parts = sum(int(m.group(i)) for i in (2, 3, 4))
        assert parts == total, f"{lang}: the breakdown sums to {parts}, not {total}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_explain_key_and_prefix_counts(self, lang):
        from bob.explain import EXPLAIN_KEYS
        n_keys = len(EXPLAIN_KEYS)
        n_pref = len({k.split(".", 1)[0] for k in EXPLAIN_KEYS})
        pattern = (r"(\d+) explainable keys across (\d+) prefixes"
                   if lang == "en" else r"(\d+) clés sur (\d+) préfixes")
        m = re.search(pattern, _doc(lang))
        assert m, f"{lang}: the --explain figures sentence is gone or reshaped"
        assert (int(m.group(1)), int(m.group(2))) == (n_keys, n_pref), (
            f"{lang}: document says {m.group(1)} keys / {m.group(2)} prefixes; "
            f"code has {n_keys} / {n_pref}"
        )

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_profile_differentiated_key_counts(self, lang):
        """The pair must sum to the whole, or one of the two is stale.

        Counted the way the page branches: a key renders per-profile sections
        when prose exists for it *or* when a profile file overrides it. The
        first version of this counted overrides alone and pinned 75/112, which
        described neither branch — the 71 prose keys render per-profile
        sections too.
        """
        from bob import i18n
        from bob.explain import EXPLAIN_KEYS, _has_profile_variants, profile_override_notes
        assert not i18n.t("explain.clamav.db_very_outdated.server.why").startswith("["), (
            "the locale is not loaded — this count would measure sentinels"
        )
        diff = sum(
            1 for k in EXPLAIN_KEYS
            if _has_profile_variants(k, i18n.t) or profile_override_notes(k, i18n.t)
        )
        uniform = len(EXPLAIN_KEYS) - diff
        pattern = (r"(\d+) of them render a section per profile[^—]*— (\d+) with prose"
                   if lang == "en" else
                   r"(\d+) d\'entre elles rendent une section par profil[^—]*— (\d+) avec une prose")
        m = re.search(pattern, _doc(lang))
        assert m, f"{lang}: the per-profile key counts sentence is gone or reshaped"
        assert int(m.group(1)) == diff, (
            f"{lang}: document says {m.group(1)} differentiated keys; code has {diff}"
        )
        prose = sum(1 for k in EXPLAIN_KEYS if _has_profile_variants(k, i18n.t))
        assert int(m.group(2)) == prose, (
            f"{lang}: document says {m.group(2)} prose keys; code has {prose}"
        )
        assert str(uniform) in _doc(lang), f"{lang}: the uniform count {uniform} is not stated"

# ---------------------------------------------------------------------------
# Names and shapes the document commits to
# ---------------------------------------------------------------------------

class TestTheNamesAreReal:

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_plugin_sandbox_key_family_is_complete(self, lang):
        """The document named one of twelve keys, so an --ignore missed eleven."""
        src = "\n".join(
            p.read_text(encoding="utf-8")
            for p in sorted((_ROOT / "bob").rglob("*.py"))
        )
        real = set(re.findall(r'"(plugin\.sandbox\.[a-z_]+)"', src))
        assert len(real) >= 10, f"only {len(real)} sandbox keys found — the scrape broke"
        doc = _doc(lang)
        suffixes = {k.rsplit(".", 1)[1] for k in real}
        missing = sorted(s for s in suffixes if f"`{s}`" not in doc)
        assert not missing, f"{lang}: plugin.sandbox suffixes never named: {missing}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_network_context_values_are_the_produced_ones(self, lang):
        """`"private"` was offered as a value; nothing has ever produced it."""
        doc = _doc(lang)
        assert '"private"' not in doc, (
            f'{lang}: network_context is still documented as producing "private", '
            f"which no code path emits"
        )
        for value in ('"local"', '"public"', '"ddns"'):
            assert value in doc, f"{lang}: network_context value {value} is undocumented"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_banner_example_carries_the_current_version(self, lang):
        from bob import __version__
        m = re.search(r"║\s+BOB v([0-9.]+)\s+│", _doc(lang))
        assert m, f"{lang}: the sample banner is gone or reshaped"
        assert m.group(1) == __version__, (
            f"{lang}: the sample banner shows v{m.group(1)}, the package is v{__version__}"
        )

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_cron_wrapper_path_is_not_the_pre_v012_fixed_name(self, lang):
        """`--install-cron` writes `bob-<name>`; `bob-nightly` is the legacy name."""
        doc = _doc(lang)
        m = re.search(r"^\| `/usr/local/bin/(bob-[a-z<>é]+)`", doc, re.M)
        assert m, f"{lang}: the wrapper script row is gone or reshaped"
        assert m.group(1) != "bob-nightly", (
            f"{lang}: the Files table still names bob-nightly as the script "
            f"--install-cron creates; it writes bob-<name> since v0.12"
        )
