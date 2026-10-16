"""v0.25.0 — a domain with only notices says it was not scored, not that it is fine.

Measured on an Alpine 3.22 VM: auditd, fail2ban, ClamAV, AIDE/Tripwire and
rkhunter/chkrootkit all "not installed" (INFO), and the domain panel read
"Threat Detection — no action needed". The notices were reported and are not
scored by design; "no action needed" was a verdict nothing had measured.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.domain_scores import REASON_INFO_ONLY, _reason_text


@pytest.mark.parametrize("lang, label", [("en", "reported, not scored"), ("fr", "signalé, non noté")])
def test_the_label(lang, label):
    i18n.init(lang)
    try:
        assert _reason_text(REASON_INFO_ONLY, i18n.t, "server") == label
    finally:
        i18n.init(lang="en")


def test_the_fallback_says_the_same():
    assert _reason_text(REASON_INFO_ONLY, None, "server") == "reported, not scored"


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_it_claims_nothing(lang):
    i18n.init(lang)
    try:
        text = _reason_text(REASON_INFO_ONLY, i18n.t, "server").lower()
    finally:
        i18n.init(lang="en")
    for claim in ("no action", "aucune action", "ok", "clean", "propre"):
        assert claim not in text
