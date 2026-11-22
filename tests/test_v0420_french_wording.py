"""v0.42.0 — the French output in French (B-039).

The French output of the developer's workstation audit under 0.40.0 (21
November 2026) carried English words where French ones exist — "blocklist
votre IP", "bindent", "credentials", "service backing", "bruteforce", "Top IP"
— and the service catalogue's English descriptions: "Samba (Windows file
sharing)", "Ollama (local LLM)". Decided with the user: translate the
descriptions, keep the product names.

The catalogue label is also an identifier (``service_risk.*`` subkey,
``--explain services.exposed.<id>``, JSON, run comparison), so it stays; the
screen shows ``services.labels.<subkey>``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bob import i18n
from bob.registry import service_label_to_subkey, shown_label

ROOT = Path(__file__).resolve().parent.parent

#: English words a French sentence of BOB's had; none may come back.
REFUSED = re.compile(r"\b(bruteforce|credentials?|bindent|bindé\w*|bindez|binder|binding|backing|blocklist\w*|"
                     r"whitelist\w*|licence-restricted|panels?|downstream|matchés?|Top IPs?|Top ports)\b", re.I)
#: What may keep one: a command, and the quotation of an old English message.
ALLOWED = ("git credential-store", "« Bruteforce attempts »")


def _values(node, path=""):
    for k, v in node.items():
        if isinstance(v, dict):
            yield from _values(v, path + k + ".")
        elif isinstance(v, str):
            yield path + k, v


def test_no_refused_english_word_in_the_french_locale():
    fr = json.loads((ROOT / "bob/locales/fr.json").read_text(encoding="utf-8"))
    found = []
    for key, text in _values(fr):
        for allowed in ALLOWED:
            text = text.replace(allowed, "")
        found += [f"{key}: {m.group(0)}" for m in REFUSED.finditer(text)]
    assert found == []


@pytest.mark.parametrize("label, fr_label", [
    ("Samba (Windows file sharing)", "Samba (partage Windows)"),          # ≤ 32 for the panorama
    ("Ollama (local LLM)", "Ollama (modèle de langage local)"),
    ("SSH Server", "Serveur SSH"),
    ("PostgreSQL", "PostgreSQL"),                       # a product name stays
])
def test_the_catalogue_label_shown_in_french(label, fr_label):
    before = i18n.current_lang()
    try:
        i18n.init("fr")
        assert shown_label(label, i18n.t) == fr_label
        i18n.init("en")
        assert shown_label(label, i18n.t) == label
    finally:
        i18n.init(before)


def test_every_catalogue_service_has_its_display_label():
    labels = [s["label"] for s in json.loads((ROOT / "bob/data/services.json").read_text(encoding="utf-8"))]
    for lang in ("en", "fr"):
        loc = json.loads((ROOT / f"bob/locales/{lang}.json").read_text(encoding="utf-8"))
        shown = loc["services"]["labels"]
        assert sorted(shown) == sorted(service_label_to_subkey(lbl) for lbl in labels), lang


def test_the_identifier_is_untouched():
    """The subkey still comes from the catalogue label, whatever the screen shows."""
    assert service_label_to_subkey("Samba (Windows file sharing)") == "samba_windows_file_sharing"


def test_without_a_translation_the_catalogue_label_stays():
    assert shown_label("Some New Service", lambda key, **kw: key) == "Some New Service"
