"""v0.31.4 — "no authorized_keys" is said of the account it was read for.

The SSH section reads ~/.ssh of the user who ran sudo (SUDO_USER), or of root.
Its text said "No authorized_keys file — public-key authentication not
configured", as if key logins were off for the whole server; a critique of a
real audit (the Mint desktop, 9 November 2026) pointed it out. The text now
names the directory read and says what is not read: other accounts, an
AuthorizedKeysFile set elsewhere in sshd's configuration, an AuthorizedKeysCommand
and SSH certificates. It no longer says key login is not set up for the account:
those two can provide keys without any file (review of the 0.31.4 changelog).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob import i18n
from bob.checks.ssh import check_ssh
from tests.test_ssh import base_snapshot


@pytest.mark.parametrize("lang, words", [
    ("en", "No authorized_keys file in /home/alice/.ssh — other accounts, an AuthorizedKeysFile set elsewhere, an AuthorizedKeysCommand and SSH certificates (TrustedUserCAKeys) are not read"),
    ("fr", "Aucun fichier authorized_keys dans /home/alice/.ssh — les autres comptes, un AuthorizedKeysFile défini ailleurs, un AuthorizedKeysCommand et les certificats SSH (TrustedUserCAKeys) ne sont pas lus")],
    ids=["en", "fr"])
def test_it_names_the_account_read(lang, words):
    snap = base_snapshot(ssh_dir_exists=True, ssh_dir_perms=0o700, authorized_keys_exists=False,
                         user_home=Path("/home/alice"))
    i18n.init(lang)
    try:
        res = check_ssh(snap, t=i18n.t)
    finally:
        i18n.init(lang="en")
    found = [f for f in res.findings if f.key == "ssh.authorized_keys_not_found"]
    assert len(found) == 1 and words in found[0].message
    assert found[0].template_vars == {"path": "/home/alice/.ssh"}
