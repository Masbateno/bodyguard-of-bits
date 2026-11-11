"""v0.32.0 — the SMTP risk text no longer calls port 25 a submission port.

TCP/25 carries mail transfer between MTAs; client submission uses 587, or 465
over implicit TLS (RFC 6409, RFC 8314). Found by a review of a real 0.31.3
audit (the Mint desktop, its Postfix bound to 127.0.0.1:25)."""

from __future__ import annotations

import json

import pytest


@pytest.mark.parametrize("lang, words, gone", [
    ("en", "client submission uses 587", "accepts mail submissions"),
    ("fr", "la soumission par les clients passe par 587", "acceptant les soumissions")], ids=["en", "fr"])
def test_the_exposure_names_the_right_ports(lang, words, gone):
    d = json.load(open(f"bob/locales/{lang}.json", encoding="utf-8"))
    text = d["service_risk"]["smtp_server_postfix_exim"]["exposure"]
    assert words in text and gone not in text and "465" in text
