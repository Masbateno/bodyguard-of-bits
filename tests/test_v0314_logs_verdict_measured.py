"""v0.31.4 — the UFW log verdict says what was measured, not "normal".

The verdict printed when no public source is charged and no scan is recognised
opened with "Normal activity". A critique of a real audit (the Mint desktop,
9 November 2026: 10 160 blocks in 7 days, 4 243 of them from one host of the
LAN) pointed out that an absence of recognised attack patterns does not
establish that the activity is normal. The verdict now states its own
condition: no public source charged, no recognised pattern in the events
analysed. Its count keeps saying what it counts (v0.26.1).
"""

from __future__ import annotations

import pytest

from bob import i18n


@pytest.mark.parametrize("lang, words, gone", [
    ("en", "No public source triggered a finding and no recognised attack pattern was found in the analysed events", "Normal activity"),
    ("fr", "Aucune source publique n'a déclenché de constat et aucun motif d'attaque reconnu n'a été trouvé dans les événements analysés", "Activité normale")],
    ids=["en", "fr"])
def test_the_verdict_says_what_was_measured(lang, words, gone):
    i18n.init(lang)
    try:
        text = i18n.t("logs.verdict_ok", total=10160, days=7)
    finally:
        i18n.init(lang="en")
    assert words in text and gone not in text and "10160" in text


@pytest.mark.parametrize("key", ["logs.verdict_ok", "logs.verdict_ok_local_scan"])
def test_no_verdict_says_charged(key):
    """Seventh review of the 0.31.4 changelog: "charged" reads as an accusation
    or a bill in English; both verdicts say a source "triggered a finding"."""
    i18n.init("en")
    try:
        text = i18n.t(key, total=3, days=7)
    finally:
        i18n.init(lang="en")
    assert "charged" not in text and "triggered a finding" in text
