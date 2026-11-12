"""v0.34.0 — DisableForwarding yes turns both forwarding findings off.

sshd's ``DisableForwarding yes`` disables X11 and TCP forwarding whatever
X11Forwarding and AllowTcpForwarding say — and ``sshd -T`` still prints
``x11forwarding yes`` and ``allowtcpforwarding yes`` under it. BOB read the two
directives alone. Measured on Fedora 44 (OpenSSH 10.2p1, whose 50-redhat.conf
sets X11Forwarding yes), the oracle being a real forwarding attempt (`ssh -W`
for TCP, `ssh -X` for X11) — netnsbench/a10340:

| configuration                              | oracle          | 0.33.0          | 0.34.0 |
|--------------------------------------------|-----------------|-----------------|--------|
| Fedora defaults                            | both allowed    | both findings   | both   |
| DisableForwarding yes                      | both refused    | both findings   | none   |
| X11Forwarding no + AllowTcpForwarding no   | both refused    | none            | none   |
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import check_ssh
from tests.test_ssh import base_snapshot

_KEYS = {"ssh.x11.forwarding.server", "ssh.allow_tcp_forwarding"}


def _found(cfg):
    snap = base_snapshot()
    snap.sshd_config = dict(cfg)
    return {f.key for f in check_ssh(snap).findings} & _KEYS


@pytest.mark.parametrize("cfg, want", [
    ({"x11forwarding": "yes"}, _KEYS),
    ({"x11forwarding": "yes", "disableforwarding": "yes"}, set()),
    ({"x11forwarding": "yes", "disableforwarding": "YES"}, set()),
    ({"x11forwarding": "yes", "disableforwarding": "no"}, _KEYS),
    ({"x11forwarding": "no", "allowtcpforwarding": "no"}, set()),
], ids=["fedora-defaults", "disable-forwarding", "case", "explicit-no", "both-off"])
def test_as_measured(cfg, want):
    assert _found(cfg) == want
