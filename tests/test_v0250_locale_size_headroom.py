"""v0.25.0 — the shipped locales stay well under the loader's size cap.

The loader refuses a locale file longer than ``_MAX_LOCALE_SIZE`` characters.
It was 512 Ki; the Kubernetes section's French text took fr.json to 524 454
characters and French stopped loading — caught by a rendered-message test,
not by anything watching the margin. The cap is now 1 Mi; this keeps a quarter
of it spare, so the margin shrinking shows long before a language breaks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob import i18n

_SHIPPED = Path(i18n.__file__).parent / "locales"


@pytest.mark.parametrize("lang", i18n.SUPPORTED_LANGS)
def test_each_locale_keeps_a_quarter_of_the_cap_spare(lang):
    path = _SHIPPED / f"{lang}.json"
    size = len(path.read_text(encoding="utf-8"))
    assert size <= 0.75 * i18n._MAX_LOCALE_SIZE, (
        f"{lang}.json holds {size} characters, past 75 % of the "
        f"{i18n._MAX_LOCALE_SIZE}-character cap"
    )


@pytest.mark.parametrize("lang", i18n.SUPPORTED_LANGS)
def test_each_locale_loads(lang):
    assert i18n._load_locale(_SHIPPED / f"{lang}.json")
