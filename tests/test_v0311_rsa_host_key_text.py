"""v0.31.1 — the RSA host-key notice says what NIST says, and what regenerating costs.

0.31.0 told a Mint desktop audit that a 3072-bit RSA host key was "no longer
considered optimal" and that "modern clients and authorities recommend 4096
bits", then offered to regenerate it. NIST rates 3072-bit RSA at 128-bit
security, acceptable beyond 2030 (SP 800-57 Part 1); and regenerating a host
key changes the fingerprint every client has recorded. The notice stays INFO,
without a deduction; its text now says both.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.ssh import check_ssh
from tests.test_ssh import _make_host_key, base_snapshot


@pytest.mark.parametrize("lang, nist, fingerprint", [
    ("en", "SP 800-57", "changes the fingerprint every client has recorded"),
    ("fr", "SP 800-57", "change l'empreinte que chaque client a enregistrée"),
], ids=["en", "fr"])
def test_the_notice(lang, nist, fingerprint):
    i18n.init(lang)
    try:
        result = check_ssh(base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=3072)]), t=i18n.t)
    finally:
        i18n.init("en")
    f = next(f for f in result.findings if f.key == "ssh.host_key_rsa_short")
    assert nist in f.detail and fingerprint in f.detail
    assert "recommend" not in f.detail and "recommandent" not in f.detail


@pytest.mark.parametrize("lang, margin, alternative", [
    ("en", "higher security margin", "modern alternative"),
    ("fr", "marge de sécurité plus élevée", "alternative moderne"),
], ids=["en", "fr"])
def test_ed25519_is_not_called_stronger_than_3072_bit_rsa(lang, margin, alternative):
    """Review of the 0.31.1 changelog: ed25519 and 3072-bit RSA are both about
    128-bit security."""
    i18n.init(lang)
    try:
        result = check_ssh(base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=3072)]), t=i18n.t)
    finally:
        i18n.init("en")
    f = next(f for f in result.findings if f.key == "ssh.host_key_rsa_short")
    assert margin in f.message and alternative in f.message and "stronger" not in f.message

