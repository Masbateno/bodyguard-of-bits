"""v0.37.0 — the ufw enable BOB runs itself is the one that takes effect unattended.

Measured on Linux Mint 22.3, ufw 0.36.2, over SSH (a10370, 14 November 2026).
ufw walks its parent processes looking for sshd and, when it finds one, asks
"Command may disrupt existing ssh connections. Proceed with operation (y|n)?".
`--fix --apply` runs every command with stdin closed (`bob.fixes._run_fix_command`):

| command, through BOB's own runner        | returned      | ufw afterwards |
|------------------------------------------|---------------|----------------|
| ['sudo', 'ufw', 'enable']                | ('ok', 0, b'')| inactive       |
| ['sudo', 'ufw', '--force', 'enable']     | ('ok', 0, b'')| active         |

So the bare form, the one BOB applies on its own when sshd answers on no
external address, printed "✔ Applied" over a firewall still off. The question
guards the SSH session; the allows `enable_cmd` puts first already keep it.
"""

from __future__ import annotations

import pytest

from bob import fixes
from bob.checks import _ufw


@pytest.mark.parametrize("ports, ipv6_off", [([], False), ([22], False), ([22, 2222], True)])
def test_every_enable_bob_writes_is_forced(ports, ipv6_off):
    cmd = _ufw.enable_cmd(ports, ipv6_off=ipv6_off)
    assert cmd.endswith("sudo ufw --force enable")
    assert cmd.count("ufw") == cmd.count("ufw --force enable") + cmd.count("ufw allow") + cmd.count("/etc/default/ufw")


def test_the_bare_case_is_still_one_bob_applies_itself():
    cmd = _ufw.enable_cmd([])
    assert cmd == "sudo ufw --force enable"
    assert fixes._can_apply_unattended(cmd)


def test_the_forced_enable_still_runs_after_the_allows():
    assert fixes._WITHDRAWS_ACCESS.search("sudo ufw --force enable")
    assert not fixes._GRANTS_ACCESS.search("sudo ufw --force enable")
