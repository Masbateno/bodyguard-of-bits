"""v0.11.2 — i18n completeness: Best-practice refs (F8) + cmd comments (F8b).

Both surfaced by deep bilingual live audits of v0.11.1:

F8 — the 60 BOB-authored "Best practice — …" reference lines in
  bob/data/cis_refs.json (entries with ``code: null``) were English-only,
  so they appeared in English in a French audit. Each now carries a French
  ``ref_fr`` translation; get_cis_ref() is locale-aware and returns it when
  the active locale is French. CIS-coded entries (real benchmark titles)
  keep their canonical English ``ref`` in every locale by design.

F8b — two inline ``# …`` comments in cmd= command suggestions
  (bob/checks/ipv6.py, bob/checks/log_rotation.py) were hardcoded English,
  leaking English into French audits — the same class as the v0.11.1
  disk.py fix, which was incomplete. Both are now locale keys.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from bob import i18n
from bob.cis_refs import get_cis_ref, _load


_REPO = pathlib.Path(__file__).resolve().parent.parent
_CIS_REFS = _REPO / "bob" / "data" / "cis_refs.json"


@pytest.fixture(autouse=True)
def _restore_locale():
    yield
    i18n.init("en")  # leave global locale state clean for other tests


# ---------------------------------------------------------------------------
# F8 — Best-practice refs are localised
# ---------------------------------------------------------------------------


def _bp_keys() -> list[str]:
    d = json.loads(_CIS_REFS.read_text(encoding="utf-8"))
    return [k for k, v in d.items() if isinstance(v, dict) and not v.get("code")]


def _cis_coded_keys() -> list[str]:
    d = json.loads(_CIS_REFS.read_text(encoding="utf-8"))
    return [k for k, v in d.items() if isinstance(v, dict) and v.get("code")]


class TestBestPracticeRefsLocalised:
    def test_every_best_practice_entry_has_ref_fr(self):
        d = json.loads(_CIS_REFS.read_text(encoding="utf-8"))
        missing = [k for k in _bp_keys() if not d[k].get("ref_fr")]
        assert not missing, f"Best-practice entries without ref_fr: {missing}"

    def test_ref_fr_is_actually_french_not_a_copy(self):
        """ref_fr must differ from the English ref (a copy = untranslated)."""
        d = json.loads(_CIS_REFS.read_text(encoding="utf-8"))
        copies = [k for k in _bp_keys() if d[k].get("ref_fr") == d[k].get("ref")]
        assert not copies, f"ref_fr identical to EN ref (untranslated): {copies}"

    def test_ref_fr_uses_french_prefix(self):
        d = json.loads(_CIS_REFS.read_text(encoding="utf-8"))
        bad = [k for k in _bp_keys() if not d[k]["ref_fr"].startswith("Bonne pratique")]
        assert not bad, f"ref_fr not starting with 'Bonne pratique': {bad}"

    def test_cis_coded_entries_have_no_ref_fr(self):
        """CIS benchmark titles stay English in every locale — no ref_fr."""
        d = json.loads(_CIS_REFS.read_text(encoding="utf-8"))
        leaked = [k for k in _cis_coded_keys() if d[k].get("ref_fr")]
        assert not leaked, f"CIS-coded entries should not have ref_fr: {leaked}"

    def test_get_cis_ref_returns_french_in_fr_locale(self):
        i18n.init("fr")
        ref = get_cis_ref("backup.no_backup")
        assert ref.startswith("Bonne pratique"), ref

    def test_get_cis_ref_returns_english_in_en_locale(self):
        i18n.init("en")
        ref = get_cis_ref("backup.no_backup")
        assert ref.startswith("Best practice"), ref

    def test_get_cis_ref_cis_coded_stays_english_in_fr(self):
        i18n.init("fr")
        ref = get_cis_ref("auditd.missing_sensitive_rules")
        assert ref.startswith("CIS "), ref

    def test_explicit_lang_param_overrides_locale(self):
        i18n.init("en")
        assert get_cis_ref("backup.no_backup", lang="fr").startswith("Bonne pratique")
        assert get_cis_ref("backup.no_backup", lang="en").startswith("Best practice")

    def test_unknown_key_returns_none(self):
        assert get_cis_ref("does.not.exist") is None


# ---------------------------------------------------------------------------
# F8b — cmd inline comments are localised (and an anti-drift guard)
# ---------------------------------------------------------------------------


class TestCmdCommentsLocalised:
    @pytest.mark.parametrize(
        "key",
        ["ipv6.cmd_comment_enable", "log_rotation.cmd_comment_maxuse"],
    )
    def test_cmd_comment_keys_present_both_locales(self, key):
        i18n.init("en"); en = i18n.t(key)
        i18n.init("fr"); fr = i18n.t(key)
        assert not en.startswith("["), f"EN {key} missing"
        assert not fr.startswith("["), f"FR {key} missing"
        assert en != fr, f"{key} identical EN/FR (untranslated)"

    def test_no_hardcoded_inline_cmd_comment_in_checks(self):
        """Anti-drift: no check may build a ``cmd=`` literal with a hardcoded
        ``  # <text>`` shell comment (the disk.py / ipv6 / log_rotation leak
        class). Localised comments use f-strings with ``# {_t(...)}`` and are
        not matched by this pattern."""
        import re
        offenders: list[str] = []
        # cmd= followed by a plain (non-f) string literal containing '  # word'
        pat = re.compile(r"""cmd\s*=\s*"[^"]*  # [A-Za-z]""")
        for path in (_REPO / "bob" / "checks").rglob("*.py"):
            src = path.read_text(encoding="utf-8")
            for m in pat.finditer(src):
                offenders.append(f"{path.relative_to(_REPO)}: {m.group(0)[:60]}")
        assert not offenders, (
            "hardcoded inline cmd comment(s) — localise via _t():\n  "
            + "\n  ".join(offenders)
        )
