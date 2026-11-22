"""v0.42.0 — the labels speak of posture, not threats (B-044).

Raised by the external review of the developer's workstation audit (21
November 2026) against the doctrine, principle 12: BOB audits a hardening
posture; it does not model adversaries. Decided with the user: the labels
change, the fields do not — ``risk`` stays in the JSON and CSV outputs.
"""

from __future__ import annotations

import pytest

from bob import i18n

LABELS = ("groups.detection", "domain_scores.detection", "risk_context.title",
          "risk_context.threat", "scoring.risk_label", "markdown_output.field_risk_level",
          # second review — the detailed report kept both (found in its -d output)
          "report.field_risk", "sections.risk_context", "service_risk.local_exposure_note")

GONE = {"en": ("threat", "risk"), "fr": ("menace", "risque")}


@pytest.mark.parametrize("key", LABELS)
@pytest.mark.parametrize("lang", ["en", "fr"])
def test_no_threat_or_risk_word_in_the_label(key, lang):
    before = i18n.current_lang()
    i18n.init(lang)
    try:
        text = i18n.t(key).lower()
    finally:
        i18n.init(before)
    assert not any(word in text for word in GONE[lang]), text


def test_the_english_domain_label_follows():
    from bob.domain_scores import LABELS as DOMAIN_LABELS
    assert DOMAIN_LABELS["detection"] == "Detection Tools"


def test_the_risk_field_stays_in_json_and_csv():
    from bob import csv_output, json_output
    import inspect
    assert '"risk":' in inspect.getsource(json_output)
    assert '"risk"' in inspect.getsource(csv_output)
