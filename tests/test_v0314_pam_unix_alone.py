"""v0.31.4 — what pam_unix alone accepts, as measured.

`password_policy.no_quality_module` said, with no pam_pwquality or
pam_cracklib, that "any string is accepted regardless of length or complexity".
Measured on Ubuntu Server 26.04 (libpam-modules 1.7.0), passwd run by an
unprivileged user through a terminal, 9 November 2026
(~/.cache/bob-fieldtest/netnsbench/pam0314/pam-survey-ubuntu.txt): with the
shipped `pam_unix.so obscure yescrypt`, ab1 and abc12 were refused ("You must
choose a longer password."), abcdef, aaaaaaaa, abcdefgh and qwerty12 accepted;
without `obscure`, ab1 and abc12 refused, abcdef and aaaaaaaa accepted (the
others not tried); with `minlen=1`, a single character was accepted.
Length is checked (6 by default), complexity is not: the detail says so.
"""

from __future__ import annotations

import pytest

from bob import i18n


@pytest.mark.parametrize("lang, words, gone", [
    ("en", "pam_unix checks only a minimum length — 6 characters unless its minlen= says otherwise",
     "Any string is accepted regardless of length"),
    ("fr", "pam_unix ne vérifie qu'une longueur minimale — 6 caractères, sauf si son minlen= dit autre chose",
     "N'importe quelle chaîne est acceptée quelle que soit sa longueur")],
    ids=["en", "fr"])
def test_the_detail_says_what_pam_unix_checks(lang, words, gone):
    i18n.init(lang)
    try:
        detail = i18n.t("password_policy.no_quality_module_detail")
    finally:
        i18n.init(lang="en")
    assert words in detail and gone not in detail
