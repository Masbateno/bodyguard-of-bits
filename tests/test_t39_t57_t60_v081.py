"""
T39 + T57 + T60 (v0.8.1) regression pins.

T39 — orphan ``service_risk.ollama_llm_server`` cleanup.
The v0.8.0 T2 ship added Ollama as a tracked service under the canonical
``ollama_local_llm`` subkey (from label "Ollama (local LLM)") but left the
pre-T2 ``ollama_llm_server`` block behind. v0.8.1 removes the orphan so the
service_risk catalogue contains only entries that match a registered
service ID.

T57 — ``--unignore=KEY`` CLI path (mirror of ``--ignore``).
Pre-T57 users could add an ignored key via CLI but had to edit
``~/.config/bob/ignore.yml`` by hand to remove it. v0.8.1 ships the missing
half: ``remove_ignore_key()`` in ``bob/ignore.py`` + ``--unignore=KEY``
parse in ``bob/cli.py`` + handler in ``bob/__main__.py`` + 2 locale keys
``cli.ignore.removed`` / ``cli.ignore.not_present``.

T60 — wire ``cli.error.fatal_prefix`` / ``bob_debug_hint`` / ``prefix``.
The T10 v0.8.1 ship added the locale entries but the ``main()`` catch-all
+ ``parse_args`` error path kept their hardcoded English strings because
i18n may not be initialised at those points. v0.8.1 adds an
``_t_or_hardcoded`` helper that gates ``i18n.t`` on ``i18n._initialized``
so the messages translate when the operator chose ``--french`` and the
exception fires after init, while preserving the English fallback when
init didn't happen.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


# ===========================================================================
# T39 — orphan service_risk.ollama_llm_server cleaned up
# ===========================================================================

class TestT39OllamaOrphanRemoved:

    _LOCALES_DIR = Path(__file__).resolve().parent.parent / "bob" / "locales"

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_ollama_llm_server_orphan_absent(self, lang):
        data = json.loads((self._LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        sr = data.get("service_risk", {})
        assert "ollama_llm_server" not in sr, (
            f"{lang}: service_risk.ollama_llm_server is still present — it was "
            f"superseded by ollama_local_llm in v0.8.0 T2; remove the orphan."
        )

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_canonical_ollama_local_llm_still_present(self, lang):
        """The replacement block ``ollama_local_llm`` (label transform of
        "Ollama (local LLM)") MUST remain — this is what services.py looks
        up for the live Ollama detection."""
        data = json.loads((self._LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        sr = data.get("service_risk", {})
        assert "ollama_local_llm" in sr
        for field in ("level", "exposure", "threat"):
            assert field in sr["ollama_local_llm"]


# ===========================================================================
# T57 — --unignore CLI path
# ===========================================================================

class TestT57RemoveIgnoreKey:

    def test_remove_existing_key_returns_true(self, tmp_path):
        from bob.ignore import add_ignore_key, remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        assert add_ignore_key("ssh.password_auth", path=path)
        assert "ssh.password_auth" in load_ignore_keys(path)
        assert remove_ignore_key("ssh.password_auth", path=path) is True
        assert "ssh.password_auth" not in load_ignore_keys(path)

    def test_remove_nonexistent_key_returns_false(self, tmp_path):
        from bob.ignore import remove_ignore_key, add_ignore_key
        path = tmp_path / "ignore.yml"
        add_ignore_key("ssh.password_auth", path=path)
        assert remove_ignore_key("kernel_hardening.aslr_disabled", path=path) is False

    def test_remove_invalid_key_pattern_returns_false(self, tmp_path):
        from bob.ignore import remove_ignore_key
        path = tmp_path / "ignore.yml"
        assert remove_ignore_key("not-an-ignore-key", path=path) is False

    def test_remove_from_missing_file_returns_false(self, tmp_path):
        from bob.ignore import remove_ignore_key
        path = tmp_path / "does_not_exist.yml"
        assert remove_ignore_key("ssh.password_auth", path=path) is False

    def test_remove_middle_key_preserves_others(self, tmp_path):
        from bob.ignore import add_ignore_key, remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        for k in ("ssh.password_auth", "ufw.policy_unknown", "rootkit.db_outdated"):
            add_ignore_key(k, path=path)
        assert remove_ignore_key("ufw.policy_unknown", path=path) is True
        assert load_ignore_keys(path) == frozenset({
            "ssh.password_auth", "rootkit.db_outdated",
        })

    def test_remove_all_keys_leaves_empty_scaffold(self, tmp_path):
        """When the last key is removed, the file is preserved with a
        minimal ``ignore:`` scaffold (rather than deleted) so the next
        ``--ignore=KEY`` doesn't have to recreate it."""
        from bob.ignore import add_ignore_key, remove_ignore_key
        path = tmp_path / "ignore.yml"
        add_ignore_key("ssh.password_auth", path=path)
        remove_ignore_key("ssh.password_auth", path=path)
        assert path.exists()
        assert "ignore:" in path.read_text()

    def test_remove_round_trips_with_add(self, tmp_path):
        """Add → remove → add: the file ends with the key present."""
        from bob.ignore import add_ignore_key, remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        add_ignore_key("ssh.password_auth", path=path)
        remove_ignore_key("ssh.password_auth", path=path)
        add_ignore_key("ssh.password_auth", path=path)
        assert "ssh.password_auth" in load_ignore_keys(path)


class TestT57CLIParsing:

    def _parse(self, *args):
        from bob.cli import parse_args
        return parse_args(list(args))

    def test_unignore_equals_form(self):
        cfg = self._parse("--unignore=ssh.password_auth")
        assert cfg.unignore_key == "ssh.password_auth"

    def test_unignore_space_form(self):
        cfg = self._parse("--unignore", "ssh.password_auth")
        assert cfg.unignore_key == "ssh.password_auth"

    def test_unignore_empty_value_raises(self):
        from bob.cli import CLIError
        with pytest.raises(CLIError, match="requires a finding key"):
            self._parse("--unignore=")

    def test_unignore_value_starting_with_dash_raises(self):
        """``bob --unignore --quiet`` must NOT silently set unignore_key="--quiet"
        (matches v0.7.3 M-4 + v0.7.4 M-2 patterns). ``--unignore`` is in the
        ``_VALUE_TAKING_OPTS`` frozenset, so a missing-value scenario raises
        a clear "requires a value" error instead of letting ``--quiet`` set
        the unignore key."""
        from bob.cli import CLIError
        with pytest.raises(CLIError, match="requires a value"):
            self._parse("--unignore", "--quiet")


class TestT57LocaleParity:

    @pytest.mark.parametrize("key", ["removed", "not_present"])
    def test_new_ignore_keys_present_in_en(self, key):
        data = json.loads(
            (Path(__file__).resolve().parent.parent / "bob" / "locales" / "en.json").read_text(encoding="utf-8")
        )
        assert key in data["cli"]["ignore"]

    @pytest.mark.parametrize("key", ["removed", "not_present"])
    def test_new_ignore_keys_present_in_fr(self, key):
        data = json.loads(
            (Path(__file__).resolve().parent.parent / "bob" / "locales" / "fr.json").read_text(encoding="utf-8")
        )
        assert key in data["cli"]["ignore"]


# ===========================================================================
# T60 — main() catch-all + parse_args error path use locale when available
# ===========================================================================

class TestT60TOrHardcodedHelper:

    def setup_method(self):
        """Reset i18n state so we test a clean pre-init path first."""
        from bob import i18n
        i18n._initialized = False
        i18n._translations = {}
        i18n._default_translations = {}

    def teardown_method(self):
        """Re-init EN so subsequent tests don't see a broken i18n state."""
        from bob import i18n
        i18n.init(lang="en")

    def test_returns_fallback_when_i18n_not_initialised(self):
        from bob.__main__ import _t_or_hardcoded
        assert _t_or_hardcoded("cli.error.fatal_prefix", "FALLBACK") == "FALLBACK"

    def test_returns_localised_value_when_i18n_initialised_en(self):
        from bob import i18n
        from bob.__main__ import _t_or_hardcoded
        i18n.init(lang="en")
        # I-2 pass 7 (v0.8.1 audit): colon-space embedded in the locale
        # value so French typography ships correctly (``"Erreur fatale : "``)
        # and ``cli.error.webhook_failed_prefix`` doesn't double-colon.
        assert _t_or_hardcoded("cli.error.fatal_prefix", "X") == "Fatal error: "

    def test_returns_localised_value_when_i18n_initialised_fr(self):
        from bob import i18n
        from bob.__main__ import _t_or_hardcoded
        i18n.init(lang="fr")
        assert _t_or_hardcoded("cli.error.fatal_prefix", "X") == "Erreur fatale : "

    def test_bob_debug_hint_translates_fr(self):
        from bob import i18n
        from bob.__main__ import _t_or_hardcoded
        i18n.init(lang="fr")
        hint = _t_or_hardcoded("cli.error.bob_debug_hint", "X")
        assert "BOB_DEBUG" in hint
        assert "trace complète" in hint or "trace complete" in hint

    def test_cli_error_prefix_translates_fr(self):
        from bob import i18n
        from bob.__main__ import _t_or_hardcoded
        i18n.init(lang="fr")
        # I-2 pass 7: trailing colon-space embedded in the locale value.
        assert _t_or_hardcoded("cli.error.prefix", "Error") == "Erreur : "


class TestT60ParseArgsErrorPath:

    def test_parse_args_error_message_translates_fr(self, capsys, monkeypatch):
        """When the user picks ``--french`` and parse_args raises ``CLIError``,
        the prefix translates. BUT — parse_args runs BEFORE i18n.init, so the
        prefix is hardcoded EN. The translated path only fires when i18n is
        already initialised (e.g. via a non-parse_args runtime error). Pin
        the EN fallback here so a future refactor doesn't accidentally
        translate the pre-init path with stale state."""
        from bob import i18n
        from bob.__main__ import _run
        i18n._initialized = False
        rc = _run(["--unknown-flag"])
        captured = capsys.readouterr()
        assert "Error" in captured.err
        i18n.init(lang="en")  # restore for subsequent tests


class TestT60DeadLocaleKeysAreNowWired:

    def test_cli_error_fatal_prefix_actually_referenced_in_source(self):
        """The locale key added by T10 must be referenced in the source
        (not just the locale files) — otherwise it's dead code and the
        cleanup-detection in T70 would flag it."""
        src = (Path(__file__).resolve().parent.parent / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "cli.error.fatal_prefix" in src

    def test_cli_error_bob_debug_hint_actually_referenced_in_source(self):
        src = (Path(__file__).resolve().parent.parent / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "cli.error.bob_debug_hint" in src

    def test_cli_error_prefix_actually_referenced_in_source(self):
        src = (Path(__file__).resolve().parent.parent / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "cli.error.prefix" in src
