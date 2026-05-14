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
