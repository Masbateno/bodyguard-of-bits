"""v0.11.1 — post-v0.11.0 deep-audit minors M-1 + M-2.

M-1 — i18n.t() must not crash on a malformed locale template.
  bob/i18n.py previously caught only KeyError from str.format(). A malformed
  template (unbalanced brace → ValueError, positional ``{0}`` field →
  IndexError) would propagate uncaught and crash the audit for that locale.
  The fix broadens t() to (KeyError, IndexError, ValueError) → degrade to the
  raw template, and adds the IndexError/ValueError guard to try_t() while
  preserving its intentional KeyError propagation. The locale linter
  (tests/test_locale_coverage.py::TestTemplateWellFormed) rejects such strings
  at CI time; these tests pin the runtime safety net.

M-2 — --test-webhook must honor --offline.
  --offline is a global no-egress guard. The audit-time webhook path already
  checks ``not config.offline``; the explicit --test-webhook command did not,
  so ``bob --test-webhook --offline`` made a POST. The fix skips the POST
  cleanly (clear message, EXIT_OK) — the more restrictive flag wins.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.__main__ import EXIT_OK, main


# ---------------------------------------------------------------------------
# M-1 — i18n runtime degrade on malformed template
# ---------------------------------------------------------------------------


class TestI18nMalformedTemplateDegrades:
    @pytest.fixture(autouse=True)
    def _init_en(self):
        i18n.init("en")
        yield

    def _inject(self, monkeypatch, template: str) -> None:
        """Inject a single malformed template under key ``_test.malformed``."""
        injected = dict(i18n._translations)
        injected["_test"] = {"malformed": template}
        monkeypatch.setattr(i18n, "_translations", injected)

    def test_unbalanced_brace_degrades_to_raw(self, monkeypatch):
        self._inject(monkeypatch, "50% off {price")
        # Must not raise ValueError — degrade to the raw template.
        assert i18n.t("_test.malformed", price=10) == "50% off {price"

    def test_positional_field_degrades_to_raw(self, monkeypatch):
        self._inject(monkeypatch, "item {0}")
        # Must not raise IndexError — degrade to the raw template.
        assert i18n.t("_test.malformed", count=3) == "item {0}"

    def test_missing_kwarg_still_degrades(self, monkeypatch):
        """The pre-existing KeyError degrade path is preserved."""
        self._inject(monkeypatch, "hello {name}")
        assert i18n.t("_test.malformed") == "hello {name}"

    def test_well_formed_named_template_still_formats(self, monkeypatch):
        self._inject(monkeypatch, "hello {name}")
        assert i18n.t("_test.malformed", name="world") == "hello world"


class TestTOptionalMalformedTemplate:
    @pytest.fixture(autouse=True)
    def _init_en(self):
        i18n.init("en")
        yield

    def _inject(self, monkeypatch, template: str) -> None:
        injected = dict(i18n._translations)
        injected["_test"] = {"malformed": template}
        monkeypatch.setattr(i18n, "_translations", injected)

    def test_try_t_unbalanced_brace_degrades(self, monkeypatch):
        self._inject(monkeypatch, "broken {x")
        # ValueError must be swallowed → raw template.
        assert i18n.try_t("_test.malformed", x=1) == "broken {x"

    def test_try_t_positional_field_degrades(self, monkeypatch):
        self._inject(monkeypatch, "pos {0}")
        assert i18n.try_t("_test.malformed", y=1) == "pos {0}"

    def test_try_t_still_propagates_keyerror(self, monkeypatch):
        """try_t's KeyError contract is intentional and preserved: a
        forgotten kwarg is a caller error, distinct from a corrupt template."""
        self._inject(monkeypatch, "needs {name}")
        with pytest.raises(KeyError):
            i18n.try_t("_test.malformed", wrong_kwarg=1)


# ---------------------------------------------------------------------------
# M-2 — --test-webhook honors --offline
# ---------------------------------------------------------------------------


class TestTestWebhookOfflineGuard:
    def test_offline_skips_webhook_post(self, monkeypatch, capsys):
        """``bob --test-webhook --offline`` must NOT make a network call and
        must exit cleanly (EXIT_OK)."""
        # Hard guard: if the POST path is ever reached, fail loudly.
        import bob.webhook as webhook_mod

        def _boom(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("test_webhook() called despite --offline")

        monkeypatch.setattr(webhook_mod, "test_webhook", _boom)

        rc = main(["--test-webhook", "--offline", "--no-color"])
        assert rc == EXIT_OK
        err = capsys.readouterr().err
        # A clear skip notice on stderr (locale key resolved, no bracket).
        assert "offline" in err.lower()
        assert "[cli.test_webhook.offline_skipped]" not in err

    def test_offline_skip_short_circuits_before_url_resolution(self, monkeypatch, capsys):
        """The offline guard returns before resolving a webhook URL, so the
        skip works even with no configured webhook (no 'no_url' error)."""
        rc = main(["--test-webhook", "--offline", "--no-color"])
        out = capsys.readouterr()
        assert rc == EXIT_OK
        # Must not have emitted the 'no URL configured' error.
        assert "requires a configured webhook" not in (out.out + out.err)
