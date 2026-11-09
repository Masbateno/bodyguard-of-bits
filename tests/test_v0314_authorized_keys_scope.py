"""v0.31.4 — "no authorized_keys" is said of the account it was read for.

The SSH section reads ~/.ssh of the user who ran sudo (SUDO_USER), or of root.
Its text said "No authorized_keys file — public-key authentication not
configured", as if key logins were off for the whole server; a critique of a
real audit (the Mint desktop, 9 November 2026) pointed it out. The text now
names the directory read and says what is not read: other accounts, and an
AuthorizedKeysFile set elsewhere in sshd's configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob import i18n
from bob.checks.ssh import check_ssh
from tests.test_ssh import base_snapshot


@pytest.mark.parametrize("lang, words", [
    ("en", "No authorized_keys file in /home/alice/.ssh — public-key login is not set up for this account; other accounts"),
    ("fr", "Aucun fichier authorized_keys dans /home/alice/.ssh — la connexion par clé publique n'est pas configurée pour ce compte")],
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
