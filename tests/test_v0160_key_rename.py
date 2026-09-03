"""
v0.16.0 — logs.brute_found renamed, and the three surfaces that must not break.

The key named an authentication attack from evidence that cannot carry one: a
UFW BLOCK is a packet the firewall discarded, so no credential was ever
offered. v0.15.5 fixed everything the operator *sees* — the message states the
measurement, local and UDP sources are reported without a deduction — and
deliberately left the key alone, because renaming it breaks baselines,
``ignore.yml`` and ``--explain``. Those belong in a planned bundle. This is it.

The new name joins the two siblings the same fix created, so the family reads
as one: ``blocked_repeat_local`` (a device on the operator's own network),
``blocked_repeat_udp`` (no handshake, no credential to guess), and
``blocked_repeat_public`` — the chargeable case.

Each surface fails differently when forgotten, which is why each has its own
test rather than one covering "the rename happened":

  - a baseline that is not remapped reports the same physical issue as both
    *resolved* (old key) and *new* (new key) on the first audit after the
    upgrade — field-reproduced in v0.9.1 for the D-1 section renames;
  - an ignore.yml that is not consulted silently stops working, and a finding
    the operator had waived comes back;
  - an --explain alias that is missing turns a script piping a key out of an
    older report into exit 3.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bob._v0160_renames import (
    FINDING_RENAMES_V0160,
    legacy_ignore_matches,
    remap_finding_key,
)
from bob.explain import EXPLAIN_KEY_ALIASES, EXPLAIN_KEYS
from bob.scoring import CheckResult, ScoreEngine

_ROOT = Path(__file__).resolve().parent.parent
_OLD = "logs.brute_found"
_NEW = "logs.blocked_repeat_public"


class TestTheKeyMoved:

    def test_the_check_emits_the_new_key(self):
        source = (_ROOT / "bob" / "checks" / "logs.py").read_text(encoding="utf-8")
        assert f'key="{_NEW}"' in source
        assert f'key="{_OLD}"' not in source

    def test_the_old_key_is_gone_from_the_contract_lists(self):
        assert _NEW in EXPLAIN_KEYS
        assert _OLD not in EXPLAIN_KEYS
        completion = (_ROOT / "bob" / "data" / "bob.bash-completion").read_text(encoding="utf-8")
        assert _NEW in completion
        assert f"{_OLD} " not in completion

    def test_auth_log_brute_force_is_untouched(self):
        """
        A different key, in a different module, reading real failed logins from
        auth.log. It is the one whose evidence *does* support the word, and a
        careless rename sweep would have taken it too.
        """
        completion = (_ROOT / "bob" / "data" / "bob.bash-completion").read_text(encoding="utf-8")
        assert "auth_log.brute_force" in completion

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_both_locales_moved_message_reason_and_explain(self, locale):
        data = json.loads((_ROOT / "bob" / "locales" / f"{locale}.json").read_text(encoding="utf-8"))
        assert data["logs"]["blocked_repeat_public"]
        assert data["deduction"]["blocked_repeat_public"]
        assert data["explain"]["logs"]["blocked_repeat_public"]["title"]
        assert "brute_found" not in data["logs"]


class TestBaselinesFromBeforeTheRenameStillCompare:

    def test_the_old_key_is_remapped(self):
        assert remap_finding_key(_OLD) == _NEW

    def test_an_unmapped_key_passes_through(self):
        """Total on purpose — called for every key in a loaded baseline."""
        assert remap_finding_key("ssh.password_auth") == "ssh.password_auth"

    def test_load_remaps_a_baseline_written_before_the_rename(self, tmp_path):
        from bob.compare import load_baseline

        path = tmp_path / "last_baseline.json"
        path.write_text(json.dumps({
            "timestamp": "t0", "score": 7,
            "alert_count": 0, "warn_count": 1, "info_count": 0,
            "finding_keys": [_OLD, "ssh.password_auth"],
        }), encoding="utf-8")
        baseline = load_baseline(path)
        assert baseline is not None
        assert _NEW in baseline.finding_keys
        assert _OLD not in baseline.finding_keys


class TestAWaivedFindingStaysWaived:

    def test_the_legacy_ignore_entry_still_matches(self):
        assert legacy_ignore_matches(_NEW, {_OLD}) is True

    def test_an_unrelated_ignore_entry_does_not(self):
        assert legacy_ignore_matches(_NEW, {"ssh.password_auth"}) is False

    def test_the_engine_honours_it_end_to_end(self):
        """The operator waived the old name and never edited ignore.yml."""
        result = CheckResult()
        result.warn_with_deduction(key=_NEW, message="x", reason="x",
                                   points=1, nature="action")
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({_OLD})
        engine.apply(result)
        assert [f.key for f in engine.findings] == []
        assert [f.key for f in engine.ignored_findings] == [_NEW]


class TestExplainStillAnswersTheOldName:

    def test_the_alias_resolves(self):
        assert EXPLAIN_KEY_ALIASES.get(_OLD) == _NEW

    def test_every_rename_has_an_alias(self):
        """A rename added to the map later must not forget --explain."""
        for legacy, canonical in FINDING_RENAMES_V0160.items():
            assert EXPLAIN_KEY_ALIASES.get(legacy) == canonical, (
                f"{legacy} is remapped for baselines and ignore.yml but "
                f"`bob --explain {legacy}` would exit 3"
            )
