"""v0.42.0, second review — the detailed report's service cards.

Read in the ``-d`` report of the developer's workstation audit with the 0.42.0
code (21 November 2026): the screen showed "Serveur SSH" and the Telnet card
said "ne tourne pas", but the report's "CONTEXTE DE RISQUE" section printed the
catalogue labels ("SSH Server", "Samba (Windows file sharing)") and gave the
Telnet card CRITICAL with no word that nothing runs. The panorama cut the
French labels at 32 characters ("Samba (partage de fichiers Windo").
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bob import i18n

ROOT = Path(__file__).resolve().parent.parent


def _snap(label, active):
    service = SimpleNamespace(label=label, is_high_or_critical=True)
    return SimpleNamespace(service=service, is_active=active, installed=True)


@pytest.fixture
def french():
    before = i18n.current_lang()
    i18n.init("fr")
    yield i18n.t
    i18n.init(before)


def test_the_report_card_shows_the_displayed_label(french):
    from bob.display import build_risk_context_entries
    entries = build_risk_context_entries([_snap("SSH Server", True)], "fr", french, network_context="local")
    assert entries[0]["label"] == "Serveur SSH"


def test_the_report_card_says_the_service_does_not_run(french):
    from bob.display import build_risk_context_entries
    entries = build_risk_context_entries([_snap("Telnet Server", False)], "fr", french, network_context="local")
    assert french("risk_context.not_running") in entries[0]["level"]


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_every_displayed_label_fits_the_panorama_column(lang):
    """``print_services_panorama`` caps the SERVICE column at 32 characters."""
    labels = json.loads((ROOT / f"bob/locales/{lang}.json").read_text(encoding="utf-8"))["services"]["labels"]
    assert [v for v in labels.values() if len(v) > 32] == []


def test_the_threat_line_uses_the_exposure_colon(capsys):
    from bob import output
    output.print_risk_context("Sensibilité du service", "CRITIQUE", "Exposition", "e",
                              "Si le service est atteint", "t")
    out = capsys.readouterr().out
    assert "Si le service est atteint : " in out and "atteint   :" not in out
