"""
v0.8.2 regression pins for the conservative-bundle items:

  - bob/_i18n_safe.py — make_fallback_t + t_or_hardcoded consolidation
  - --test-webhook smoke command (CLI parsing + handler resolution)
  - --check=list section descriptions (sections.descriptions.* coverage)
  - D-3 deprecation warning on EXPLAIN_KEY_ALIASES use
  - scripts/lint_locales.py — meta tool, smoke-runnable

Plus a couple of cross-module assertions that ensure the 5 modules
migrated to ``bob._i18n_safe.make_fallback_t`` still pass their
behavioural contracts (kwargs interpolation, missing-key fallback, etc.).
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent


# ===========================================================================
# bob/_i18n_safe.py — consolidated fallback patterns
# ===========================================================================

class TestI18nSafeMakeFallbackT:

    def test_returns_template_value_for_known_key(self):
        from bob._i18n_safe import make_fallback_t
        t = make_fallback_t({"foo.bar": "value"})
        assert t("foo.bar") == "value"

    def test_returns_key_itself_for_unknown(self):
        from bob._i18n_safe import make_fallback_t
        t = make_fallback_t({})
        assert t("unknown.key") == "unknown.key"

    def test_formats_kwargs_into_placeholders(self):
        from bob._i18n_safe import make_fallback_t
        t = make_fallback_t({"x": "Hello {name}!"})
        assert t("x", name="world") == "Hello world!"

    def test_format_error_returns_raw_template(self):
        """Missing placeholder → return template unchanged (defensive)."""
        from bob._i18n_safe import make_fallback_t
        t = make_fallback_t({"x": "Hello {name}!"})
        assert t("x") == "Hello {name}!"

    def test_static_template_passes_through_format(self):
        """Templates without placeholders ride through format() unchanged."""
        from bob._i18n_safe import make_fallback_t
        t = make_fallback_t({"x": "Just static text"})
        assert t("x", whatever=42) == "Just static text"


class TestI18nSafeTOrHardcoded:

    def setup_method(self):
        from bob import i18n
        i18n._initialized = False

    def teardown_method(self):
        from bob import i18n
        i18n.init(lang="en")

    def test_returns_fallback_when_not_initialised(self):
        from bob._i18n_safe import t_or_hardcoded
        assert t_or_hardcoded("cli.error.prefix", "X") == "X"

    def test_returns_translated_when_initialised(self):
        from bob import i18n
        from bob._i18n_safe import t_or_hardcoded
        i18n.init(lang="en")
        # I-2 pass 7: cli.error.prefix embeds trailing colon-space
        assert t_or_hardcoded("cli.error.prefix", "X") == "Error: "


class TestI18nConsolidationModulesUseFactory:
    """Pin that the 4 modules migrated to make_fallback_t actually import + use
    the factory (regression guard: a future refactor that reverts to a local
    hand-rolled ``_fallback_t`` would resurrect the inconsistent behaviour
    that v0.8.2 closed)."""

    @pytest.mark.parametrize("module", [
        "bob/config.py",
        "bob/webhook.py",
        "bob/markdown_output.py",
        "bob/html_output.py",
    ])
    def test_module_imports_make_fallback_t(self, module):
        src = (_REPO_ROOT / module).read_text(encoding="utf-8")
        assert "from bob._i18n_safe import make_fallback_t" in src, (
            f"{module} should import make_fallback_t from bob._i18n_safe"
        )
        assert "_fallback_t = make_fallback_t(" in src, (
            f"{module} should call the factory: ``_fallback_t = make_fallback_t(_FALLBACK_LABELS)``"
        )

    def test_main_uses_shared_t_or_hardcoded(self):
        src = (_REPO_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert "from bob._i18n_safe import t_or_hardcoded" in src
        # Local def should be gone
        assert "def _t_or_hardcoded(" not in src


# ===========================================================================
# --test-webhook CLI command
# ===========================================================================

class TestTestWebhookCli:

    def test_parse_test_webhook_flag(self):
        from bob.cli import parse_args
        cfg = parse_args(["--test-webhook"])
        assert cfg.test_webhook is True

    def test_test_webhook_default_false(self):
        from bob.cli import parse_args
        cfg = parse_args([])
        assert cfg.test_webhook is False


class TestTestWebhookSmokeFunction:

    def test_invalid_scheme_raises(self):
        from bob.webhook import test_webhook, WebhookError
        with pytest.raises(WebhookError, match="must start with"):
            test_webhook("ftp://example.com/hook")

    def test_payload_uses_smoke_tag(self, monkeypatch):
        """Pin that the payload carries the ``bob_smoke_test`` tag — receivers
        can filter on this to distinguish smoke tests from real audits."""
        from bob import webhook
        sent_payload = {}

        class _FakeResponse:
            status = 200
            def __enter__(self):  return self
            def __exit__(self, *a):  return False

        def _fake_urlopen(req, timeout=None):
            nonlocal sent_payload
            sent_payload.update(json.loads(req.data.decode("utf-8")))
            return _FakeResponse()

        monkeypatch.setattr(webhook.urllib.request, "urlopen", _fake_urlopen)
        # Use https to bypass the plain-http guard
        status = webhook.test_webhook("https://example.com/hook")
        assert status == 200
        # generic payload uses ``tag`` field
        assert sent_payload.get("tag") == "bob_smoke_test"
        assert sent_payload.get("test") is True


# ===========================================================================
# --check=list section descriptions
# ===========================================================================

class TestCheckListDescriptionsCoverage:
    """Each section in _ALL_SECTIONS + _ALWAYS_ON_SECTIONS must have a
    ``sections.descriptions.<name>`` entry in both EN and FR locales."""

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_every_section_has_a_description(self, lang):
        from bob.runner import _ALL_SECTIONS, _ALWAYS_ON_SECTIONS
        locale = json.loads((_REPO_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        descs = locale.get("sections", {}).get("descriptions", {})
        all_sections = set(_ALL_SECTIONS) | set(_ALWAYS_ON_SECTIONS)
        missing = all_sections - set(descs)
        assert not missing, (
            f"{lang}: sections without ``sections.descriptions.X`` entry: "
            f"{sorted(missing)}"
        )

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_no_orphan_descriptions(self, lang):
        from bob.runner import _ALL_SECTIONS, _ALWAYS_ON_SECTIONS
        locale = json.loads((_REPO_ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
        descs = locale.get("sections", {}).get("descriptions", {})
        all_sections = set(_ALL_SECTIONS) | set(_ALWAYS_ON_SECTIONS)
        extra = set(descs) - all_sections
        assert not extra, (
            f"{lang}: stale ``sections.descriptions.X`` entries for "
            f"unknown sections: {sorted(extra)}"
        )


# ===========================================================================
# D-3 — EXPLAIN_KEY_ALIASES (v0.8.2 warning machinery retired in v0.9.0)
# ===========================================================================
#
# The v0.8.2 ``TestExplainKeyAliasDeprecation`` class exercised the one-shot
# ``_warn_alias_deprecation`` / ``_WARNED_ALIASES`` machinery that lived in
# ``bob/explain.py`` to herald the v0.9.0 retrait of the sole live alias
# (``services_state.service_inactive`` → ``enabled_inactive``, then
# ``services_health.service_inactive`` → ``enabled_inactive`` after the
# v0.9.0 D-1 section rename). v0.9.0 D-3 resolved the underlying drift at
# the source (renamed the EXPLAIN_KEYS entry to ``service_inactive`` so it
# matches what ``services_state.py`` emits) and removed both the alias
# and the warning machinery. The remaining ``normalize_key`` lookup over
# the empty ``EXPLAIN_KEY_ALIASES`` dict is exercised by
# ``test_explain_naming_convention::test_normalize_resolves_aliases`` and
# ``test_aliases_do_not_collide_with_canonical`` — both pass trivially on
# the empty dict and immediately gain coverage when a new alias lands.


# ===========================================================================
# scripts/lint_locales.py smoke
# ===========================================================================

class TestLocaleLinterSmoke:

    def test_linter_runs_cleanly_on_shipped_locales(self):
        """The shipped EN / FR locales must pass the linter — drift in
        either causes the script to exit non-zero, blocking the ship.
        """
        result = subprocess.run(
            [sys.executable, str(_REPO_ROOT / "scripts" / "lint_locales.py")],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, (
            f"locale lint failed:\nSTDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        assert "clean" in result.stdout
