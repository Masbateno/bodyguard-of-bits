"""v0.31.3 — fail2ban with no active jail: the text says to reload, as measured.

`fail2ban.no_jails` gives a check command (`fail2ban-client status sshd`, by design
since 0.16.4) and a detail telling the operator to enable the sshd jail in
jail.local. Measured on Ubuntu Server 26.04, fail2ban 1.1.0, 8 November 2026
(~/.cache/bob-fieldtest/netnsbench/rt0313/rt-f2b-ubuntu.txt): with no jail
configured, `[sshd] enabled = true` written to jail.local left fail2ban with 0
jails and the finding in place; `fail2ban-client reload` then started the jail
and the finding went. A configured jail stopped at runtime came back with the
reload alone. The detail now says to reload.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.fail2ban import Fail2banSnapshot, check_fail2ban


@pytest.mark.parametrize("lang, words", [
    ("en", "then reload fail2ban (sudo fail2ban-client reload): the edit alone starts no jail"),
    ("fr", "puis rechargez fail2ban (sudo fail2ban-client reload) : la modification seule ne démarre aucun jail")],
    ids=["en", "fr"])
def test_the_detail_says_to_reload(lang, words):
    i18n.init(lang)
    try:
        res = check_fail2ban(Fail2banSnapshot(installed=True, service_active=True, active_jails=[]), t=i18n.t)
    finally:
        i18n.init(lang="en")
    f = next(f for f in res.findings if f.key == "fail2ban.no_jails")
    assert words in f.detail and f.cmd == "sudo fail2ban-client status sshd" and f.cmd_type == "check"
