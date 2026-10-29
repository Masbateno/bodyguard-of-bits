"""
Shared pytest fixtures for the BOB test suite.

Auto-applied fixtures here run for every test in tests/.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _force_posix_locale_for_tests(monkeypatch):
    """
    Force LC_ALL/LC_MESSAGES/LANG to "C" via env vars so locale-dependent
    CLI defaults (`bob.i18n.detect_system_lang`) resolve to English regardless
    of the developer's or CI runner's host locale.

    Scope:
      - This fixture only sets process environment variables. It does NOT
        call `setlocale()` and therefore does not affect libraries that read
        the locale via libc/ICU directly. BOB itself reads `os.environ`, so
        this is sufficient for our test surface.
      - All three vars are set even though POSIX precedence makes
        `LC_MESSAGES`/`LANG` redundant when `LC_ALL` is set. The explicit
        triple makes the intent obvious to readers and is robust against
        downstream code that probes any single var directly.

    Tests that need a different locale should override with monkeypatch.
    """
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LC_MESSAGES", "C")
    monkeypatch.setenv("LANG", "C")


@pytest.fixture(autouse=True)
def _ensure_i18n_initialised_for_tests(request):
    """I-2 pass 8 (v0.8.1 audit) — make sure ``bob.i18n`` is initialised
    before each test so direct calls into runtime modules that now use
    ``i18n.t()`` (post-T10, post-I-2 pass 8) don't see the ``[key]``
    fallback. Pre-fix tests for ``validate_check_filters`` and similar
    call sites worked because the strings were hardcoded; the v0.8.1
    i18n migration made them locale-driven.

    Production callers (``bob/__main__.py``) always call ``i18n.init``
    before reaching the runner — this fixture mirrors that production
    invariant in the test environment without each test having to know
    about it.

    **Opt-out**: tests in ``test_i18n.py`` deliberately exercise the
    pre-init ``[key]`` bracketed-fallback contract and have their own
    ``reset_i18n`` teardown that flips ``_initialized = False``. Skip
    the auto-init for that module so those tests keep their freedom.
    """
    from bob import i18n
    # The module name surfaces via ``request.module.__name__``; the
    # explicit test_i18n exemption documents the conflict instead of
    # silently shadowing it.
    if request.module.__name__.endswith("test_i18n"):
        yield
        return
    # v0.28.0 — and in English: a test that switched to French and did not
    # switch back (test_v0111's French cases) made a later test that reads
    # the English text fail when run after it, as `-k sudo` ordered them.
    if not i18n._initialized or i18n._lang != "en":
        i18n.init(lang="en")
    yield


@pytest.fixture(autouse=True)
def _no_live_ssh_session_for_fail2ban(monkeypatch):
    """v0.26.0 — ``Fail2banSnapshot.from_system`` reads the host's live SSH
    sessions and ``/var/log`` when there is no journal entry to compare a
    jail's file against. A developer's or a CI runner's own sessions must not
    decide a test: no session by default, a test that needs one sets it."""
    monkeypatch.setattr("bob.checks.fail2ban._newest_session_since_syslog", lambda: None)
