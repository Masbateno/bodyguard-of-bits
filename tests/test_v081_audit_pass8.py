"""
v0.8.1 deep-hardening audit pass #8 regression pins.

The 8th sub-agent audit pass surfaced 5 findings — including a meta-regression
in the I-1 pass 7 fix (the inline-comment relaxation was dead code masked by
the defensive ``load_ignore_keys`` guard). All shipped together.

  - I-1 pass 8 — ``_KEY_LINE_RE`` relaxed to drop ``\\s*$`` anchor so the
    loader sees inline-commented entries (``- key: ssh.x  # comment``).
    The pass 7 sibling regex ``_KEY_LINE_MATCH_RE`` was unreachable.
    Loader + remover now share a single relaxed grammar.
  - I-2 pass 8 — ``runner.py:143,157,161`` had 3 hardcoded ``"Warning:"``
    prefixes that T10 left behind. i18n'd via new ``cli.error.warning_prefix``
    + ``cli.runner.*`` keys.
  - M-1 pass 8 — ``--webhook-secret`` phantom in ``_VALUE_TAKING_OPTS``
    produced inconsistent error messages for the same input. Removed.
  - M-2 pass 8 — ``_recognised_override_keys`` over-accepted
    ``services.exposure.<exp>_ufw_inactive`` for all 7 exposure values.
    The runtime emits ``_ufw_inactive`` ONLY for ``(no_rule, loopback_no_rule)``.
    Narrowed.
  - M-3 pass 8 — test pin that ``i18n.t()`` preserves trailing whitespace,
    defending the I-2 pass 7 contract (locale values embed colon-space).
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path

import pytest


# ===========================================================================
# I-1 pass 8 — loader + remover share relaxed grammar (inline comments work)
# ===========================================================================

class TestI1Pass8InlineCommentParity:

    def test_inline_commented_entry_is_loaded(self, tmp_path):
        """Pre-pass-8 the strict loader regex rejected lines with trailing
        ``# comment`` annotations. Now they load cleanly."""
        from bob.ignore import load_ignore_keys
        path = tmp_path / "ignore.yml"
        path.write_text(
            "ignore:\n"
            "  - key: ssh.password_auth  # legacy automation\n"
            "  - key: ssh.permit_root_login\n",
            encoding="utf-8",
        )
        keys = load_ignore_keys(path)
        assert "ssh.password_auth" in keys, (
            "I-1 pass 8 regression: loader misses inline-commented entries"
        )
        assert "ssh.permit_root_login" in keys

    def test_inline_commented_entry_is_removable(self, tmp_path):
        """End-to-end: add an inline-comment entry, then unignore via the
        public API. Pre-pass-8 this failed because the defensive
        ``if key not in load_ignore_keys`` guard short-circuited (loader
        didn't see the key)."""
        from bob.ignore import remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        path.write_text(
            "ignore:\n"
            "  - key: ssh.x11_forwarding  # documented exception\n",
            encoding="utf-8",
        )
        assert remove_ignore_key("ssh.x11_forwarding", path=path) is True
        assert load_ignore_keys(path) == frozenset()

    def test_inline_comment_above_block_preserved(self, tmp_path):
        """The file-header comment + the ``# Ticket SECOPS-1234`` style
        comments stay even after the inline-commented key is removed."""
        from bob.ignore import remove_ignore_key
        path = tmp_path / "ignore.yml"
        path.write_text(
            "# Per ticket SECOPS-1234\n"
            "ignore:\n"
            "  - key: ssh.password_auth  # legacy automation\n",
            encoding="utf-8",
        )
        remove_ignore_key("ssh.password_auth", path=path)
        content = path.read_text(encoding="utf-8")
        assert "# Per ticket SECOPS-1234" in content


# ===========================================================================
# I-2 pass 8 — runner.py 3 warning sites i18n'd
# ===========================================================================

class TestI2Pass8RunnerWarningsI18n:

    @pytest.fixture(autouse=True)
    def _restore_en(self):
        """Reset locale to EN after each test so we don't poison the
        global i18n state for sibling tests."""
        from bob import i18n
        yield
        i18n.init(lang="en")

    def test_runner_no_remaining_hardcoded_warning_prefix(self):
        """Pin that the 3 ``Warning:`` literals are gone from runner.py."""
        src = (Path(__file__).resolve().parent.parent / "bob" / "runner.py").read_text(encoding="utf-8")
        hardcoded = re.findall(r"f['\"]Warning: --check|f['\"]Warning: --skip", src)
        assert not hardcoded, (
            f"I-2 pass 8 regression: runner.py still has {len(hardcoded)} "
            f"hardcoded ``Warning:`` print site(s)"
        )

    def test_runner_uses_locale_warning_prefix(self):
        src = (Path(__file__).resolve().parent.parent / "bob" / "runner.py").read_text(encoding="utf-8")
        assert "cli.error.warning_prefix" in src

    @pytest.mark.parametrize("key,expected_en", [
        ("cli.error.warning_prefix",            "Warning: "),
        ("cli.runner.check_no_match_fatal",     "--check matched no known sections. Run 'bob --check=list' to see available checks."),
        ("cli.runner.suggest_did_you_mean",     "Did you mean: {matches}"),
        ("cli.runner.suggest_run_list",         "Run 'bob --check=list' to see all check names."),
    ])
    def test_en_locale_values(self, key, expected_en):
        en = json.loads(
            (Path(__file__).resolve().parent.parent / "bob" / "locales" / "en.json").read_text(encoding="utf-8")
        )
        node = en
        for p in key.split("."):
            node = node[p]
        assert node == expected_en

    @pytest.mark.parametrize("key,expected_fr", [
        ("cli.error.warning_prefix",            "Avertissement : "),
        ("cli.runner.suggest_did_you_mean",     "Vouliez-vous dire : {matches}"),
    ])
    def test_fr_locale_typography(self, key, expected_fr):
        fr = json.loads(
            (Path(__file__).resolve().parent.parent / "bob" / "locales" / "fr.json").read_text(encoding="utf-8")
        )
        node = fr
        for p in key.split("."):
            node = node[p]
        assert node == expected_fr, (
            f"I-2 pass 8 regression: FR locale {key!r} doesn't follow "
            f"French typography. Got {node!r}, expected {expected_fr!r}"
        )

    def test_runner_warning_translates_fr(self, capsys):
        from bob import i18n
        i18n.init(lang="fr")
        from bob.runner import validate_check_filters

        class _Config:
            check_only = frozenset({"completely_invalid_section_xyz"})
            skip_checks = frozenset()

        validate_check_filters(_Config)
        out = capsys.readouterr()
        # The translated prefix
        assert "Avertissement : " in out.err
        # The translated body
        assert "ne correspond à aucune section connue" in out.err


# ===========================================================================
# M-1 pass 8 — --webhook-secret phantom removed
# ===========================================================================

class TestM1Pass8WebhookSecretPhantomRemoved:

    def test_webhook_secret_space_form_now_unknown_option(self):
        """Pre-fix this raised "--webhook-secret requires a value"
        (misleading). Post-fix it should raise "Unknown option"
        consistent with the ``=`` form."""
        from bob.cli import parse_args, CLIError
        with pytest.raises(CLIError, match="Unknown option"):
            parse_args(["--webhook-secret", "foo"])

    def test_webhook_secret_equals_form_still_unknown_option(self):
        """The ``=`` form was already correct pre-fix; pin it doesn't
        regress."""
        from bob.cli import parse_args, CLIError
        with pytest.raises(CLIError, match="Unknown option"):
            parse_args(["--webhook-secret=foo"])

    def test_webhook_secret_not_in_value_taking_set(self):
        """Direct guard: the phantom entry must be gone from
        ``_VALUE_TAKING_OPTS``."""
        from bob.cli import _VALUE_TAKING_OPTS
        assert "--webhook-secret" not in _VALUE_TAKING_OPTS


# ===========================================================================
# M-2 pass 8 — _ufw_inactive variants narrowed
# ===========================================================================

class TestM2Pass8UfwInactiveNarrowed:

    def setup_method(self):
        from bob.profiles import _recognised_override_keys
        _recognised_override_keys.cache_clear()

    def _load_with_override(self, *override_lines):
        from bob.profiles import _load_from_path
        content = (
            "[profile]\nname = m2p8_test\nextends = server\n"
            "description = M-2 pass 8 test\n\n[overrides]\n"
            + "".join(f"{k} = {v}\n" for k, v in override_lines)
        )
        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "m2p8_test.conf"
        path.write_text(content, encoding="utf-8")
        records: list[str] = []
        logger = logging.getLogger("bob.profiles")
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r.getMessage())
        logger.addHandler(handler)
        try:
            return _load_from_path(path, depth=0), records
        finally:
            logger.removeHandler(handler)

    @pytest.mark.parametrize("legit", [
        "services.exposure.no_rule_ufw_inactive",
        "services.exposure.loopback_no_rule_ufw_inactive",
    ])
    def test_emitted_ufw_inactive_variants_do_not_warn(self, legit):
        _, records = self._load_with_override((legit, "info"))
        flagged = [r for r in records if legit in r and "not recognised" in r]
        assert not flagged, (
            f"M-2 pass 8 regression: legitimately-emitted _ufw_inactive "
            f"variant {legit!r} triggered a typo warning: {flagged}"
        )

    @pytest.mark.parametrize("bogus", [
        "services.exposure.open_world_ufw_inactive",
        "services.exposure.open_local_ufw_inactive",
        "services.exposure.deny_ufw_inactive",
        "services.exposure.loopback_ufw_inactive",
        "services.exposure.not_listening_ufw_inactive",
    ])
    def test_non_emitted_ufw_inactive_variants_warn(self, bogus):
        _, records = self._load_with_override((bogus, "info"))
        flagged = [r for r in records if bogus in r and "not recognised" in r]
        assert flagged, (
            f"M-2 pass 8 regression: bogus _ufw_inactive variant {bogus!r} "
            f"was silently accepted as valid (should warn — it's never "
            f"emitted by the runtime)"
        )


# ===========================================================================
# M-3 pass 8 — t() preserves trailing whitespace contract
# ===========================================================================

class TestM3Pass8TrailingWhitespacePreserved:
    """The I-2 pass 7 fix moved colon-space into the locale value
    (``"Error: "``, ``"Erreur : "``). Sites use the value verbatim
    without appending ``": "``. So the trailing space is contract-
    critical: a future JSON normaliser that calls ``.strip()`` on
    values, or an ``i18n.t()`` change that strips whitespace, would
    silently break the FR typography fix."""

    @pytest.fixture(autouse=True)
    def _restore_en(self):
        from bob import i18n
        yield
        i18n.init(lang="en")

    @pytest.mark.parametrize("key", [
        "cli.error.prefix",
        "cli.error.fatal_prefix",
        "cli.error.webhook_failed_prefix",
        "cli.error.warning_prefix",
    ])
    def test_en_t_preserves_trailing_space(self, key):
        from bob import i18n
        i18n.init(lang="en")
        v = i18n.t(key)
        assert v.endswith(" "), (
            f"M-3 pass 8 regression: EN ``t({key!r})`` returned {v!r} "
            f"without trailing space — the I-2 pass 7 fix depends on it."
        )

    @pytest.mark.parametrize("key", [
        "cli.error.prefix",
        "cli.error.fatal_prefix",
        "cli.error.webhook_failed_prefix",
        "cli.error.warning_prefix",
    ])
    def test_fr_t_preserves_trailing_space(self, key):
        from bob import i18n
        i18n.init(lang="fr")
        v = i18n.t(key)
        assert v.endswith(" "), (
            f"M-3 pass 8 regression: FR ``t({key!r})`` returned {v!r} "
            f"without trailing space — French typography requires "
            f"space-colon-space."
        )
