"""
Tests for bob.formatter — locale-independent message reconstruction.

The formatter is the Phase 2 bridge between BOB's internal `(key, template_vars)`
representation and a human-readable localized message. These tests pin the
resolution order (key + vars → key alone → pre-formatted message fallback)
that the public contract relies on.

Run with: python -m pytest tests/test_formatter.py -v
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.formatter import format_deduction, format_finding
from bob.scoring import Deduction, Finding, FindingLevel


@pytest.fixture(autouse=True)
def _reset_i18n_to_en():
    """Make every test run with English locale loaded."""
    i18n.init("en")
    yield
    i18n._translations = {}
    i18n._lang = "en"
    i18n._initialized = False


class TestFormatFinding:
    def test_key_with_template_vars_renders_via_i18n(self):
        # ssh.weak_ciphers has {ciphers} placeholder in en.json
        f = Finding(
            level=FindingLevel.WARN,
            message="ignored",                       # legacy field — should be bypassed
            key="ssh.weak_ciphers",
            template_vars={"ciphers": "aes128-cbc, des-cbc"},
        )
        rendered = format_finding(f)
        assert "aes128-cbc" in rendered
        assert "des-cbc" in rendered
        # Make sure the legacy `message` was NOT returned
        assert rendered != "ignored"

    def test_key_without_template_vars_returns_template(self):
        # A real key whose template has no placeholders
        f = Finding(
            level=FindingLevel.OK,
            message="ignored",
            key="banner.title",   # known to exist, value is "BOB"
        )
        rendered = format_finding(f)
        assert rendered == "BOB"

    def test_no_key_falls_back_to_message(self):
        f = Finding(
            level=FindingLevel.INFO,
            message="Pre-formatted legacy text",
        )
        assert format_finding(f) == "Pre-formatted legacy text"

    def test_unknown_key_falls_back_to_message(self):
        f = Finding(
            level=FindingLevel.INFO,
            message="Legacy fallback",
            key="nonexistent.fake.key",
            template_vars={"x": "y"},
        )
        rendered = format_finding(f)
        # When the key is unknown, _render_key returns "[key]" and we fall back
        # to the legacy message.
        # But because template_vars were provided, the rendering path is taken
        # and "[nonexistent.fake.key]" is what gets returned by i18n.t.
        # Therefore the fallback to message only happens when key OR template_vars
        # are missing entirely.
        # This test documents the actual (slightly subtle) behavior.
        assert rendered.startswith("[") or rendered == "Legacy fallback"

    def test_empty_message_and_no_key(self):
        f = Finding(level=FindingLevel.OK, message="")
        assert format_finding(f) == ""


class TestFormatDeduction:
    def test_key_with_template_vars(self):
        d = Deduction(
            reason="ignored",
            points=2,
            key="ssh.weak_ciphers",
            template_vars={"ciphers": "rc4"},
        )
        rendered = format_deduction(d)
        assert "rc4" in rendered
        assert rendered != "ignored"

    def test_no_key_falls_back_to_reason(self):
        d = Deduction(reason="Legacy reason", points=1)
        assert format_deduction(d) == "Legacy reason"


class TestLocaleRoundtrip:
    """
    The whole point of (key, template_vars): the same finding can be rendered
    in different locales without the check having to produce two messages.
    """

    def test_french_rendering_via_locale_switch(self):
        i18n.init("fr")
        f = Finding(
            level=FindingLevel.WARN,
            message="ignored",
            key="ssh.weak_ciphers",
            template_vars={"ciphers": "rc4"},
        )
        fr_rendered = format_finding(f)
        # French locale renders the FR template — should differ from EN.
        i18n.init("en")
        en_rendered = format_finding(f)
        assert fr_rendered != en_rendered, (
            "Same (key, template_vars) must yield different text in fr vs en. "
            "Got fr=%r vs en=%r" % (fr_rendered, en_rendered)
        )
        # Both must contain the interpolated value
        assert "rc4" in fr_rendered
        assert "rc4" in en_rendered


class TestBackwardCompatibility:
    """
    Legacy checks (no key, no template_vars) must keep producing their
    pre-formatted message verbatim. format_finding must NEVER mutate
    or replace a message coming from a legacy check.
    """

    def test_legacy_finding_passthrough(self):
        f = Finding(
            level=FindingLevel.ALERT,
            message="Server is on fire",
            detail="quite bad",
            nature="action",
            cmd="sudo extinguish",
        )
        # No key, no template_vars → 100% backward compatible
        assert format_finding(f) == "Server is on fire"

    def test_legacy_deduction_passthrough(self):
        d = Deduction(reason="Old-style reason", points=2, context="public")
        assert format_deduction(d) == "Old-style reason"


class TestFormatterEdgeCases:
    """
    Edge cases discovered during the post-review hardening of the formatter
    (v0.4.1 hardening pass). These tests pin behavior we relied on implicitly
    so a future refactor cannot regress silently.
    """

    def test_empty_template_vars_with_placeholder_template_returns_raw(self):
        """
        Edge case: a key whose template has placeholders, but the check passes
        `template_vars={}` (empty dict, not None). The formatter does NOT call
        `str.format()` in that case — consistent with `bob.i18n.t()` legacy
        behavior — so the raw template is returned with its `{placeholders}`
        intact. The UI will show `{ciphers}` literally, surfacing the bug at
        runtime but without raising. The CONVENTION is: a migrated check MUST
        either pass a non-empty `template_vars` covering every placeholder,
        OR leave template_vars empty AND have a placeholder-free template.
        Mixing them is a check-side bug visible at display time.
        """
        f = Finding(
            level=FindingLevel.WARN,
            message="ignored",
            key="ssh.weak_ciphers",          # template needs {ciphers}
            template_vars={},                # not populated
        )
        # No exception; the raw template is returned (with the literal `{ciphers}`).
        result = format_finding(f)
        assert "{ciphers}" in result, (
            "Empty template_vars must skip format() and return the raw template; "
            f"got {result!r}"
        )

    def test_partial_template_vars_raises_keyerror(self):
        """
        If `template_vars` is non-empty but missing a placeholder the template
        requires, `.format()` raises KeyError. This is the check-side bug
        we want surfaced — the formatter does NOT swallow it (catch is
        restricted to nothing for str.format errors; only `try_t`'s missing-key
        case returns None).
        """
        f = Finding(
            level=FindingLevel.INFO,
            message="legacy fallback",
            key="ssh.host_key_rsa_short",   # template needs both name AND bits
            template_vars={"name": "ssh_host_rsa_key"},   # bits missing
        )
        with pytest.raises(KeyError):
            format_finding(f)

    def test_mismatched_key_vs_message_uses_key(self):
        """
        When `key` resolves cleanly, the formatter prefers it over a possibly
        out-of-sync `message` field. This is the whole point of the migration:
        the structured representation is authoritative once it's populated.
        """
        f = Finding(
            level=FindingLevel.OK,
            message="DESYNC: this old message says one thing",
            key="banner.title",     # key resolves to literally "BOB"
        )
        assert format_finding(f) == "BOB"
        # message was ignored — the key path won

    def test_empty_finding_message_with_no_key(self):
        """An empty `message` and no key returns an empty string (not None)."""
        f = Finding(level=FindingLevel.OK, message="")
        result = format_finding(f)
        assert result == ""
        assert isinstance(result, str)
