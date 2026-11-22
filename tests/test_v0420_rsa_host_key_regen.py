"""v0.42.0 — regenerating an RSA host key: the old pair kept, sshd tested (B-041).

Measured on the test Mint (OpenSSH 9.6p1, 21 November 2026), in a throw-away
directory:

- ``ssh-keygen -t rsa -b 4096 -f <existing key> -N ''`` asks "Overwrite
  (y/n)?". Answered y, it overwrites the key and no copy is left; the restart
  then ran without ``sshd -t``. Run from a script (stdin closed) it exits 1 and
  nothing changes. (``--fix --apply`` does not run this chained command; it
  shows it to the operator.)
- The new chain on a closed stdin: exit 0, the old pair in ``.bob-old`` with
  its fingerprint, the new key 4096 bits, both files mode 600, ``sshd -t``
  accepting a configuration that names the new key.

The 3072-bit notice also pointed at ``/etc/ssh/ssh_host_rsa_key`` whatever
file sshd serves; it now names the key it is about, like the weak-key fix.
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import check_ssh
from tests.test_ssh import _make_host_key, base_snapshot

_PATH = "/etc/ssh/ssh_host_rsa_key"


def _cmd(bits, name="ssh_host_rsa_key", key="ssh.host_key_rsa_short"):
    snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=bits, name=name)])
    snap.sshd_config = {"_hostkeys": [f"/etc/ssh/{name}"]}
    snap.sshd_config_readable = True
    return next(f.cmd for f in check_ssh(snap).findings if f.key == key)


@pytest.mark.parametrize("bits, key", [(3072, "ssh.host_key_rsa_short"), (1024, "ssh.host_key_rsa_weak")])
def test_the_old_pair_is_moved_aside_before_generating(bits, key):
    cmd = _cmd(bits, key=key)
    move = f"sudo mv {_PATH} {_PATH}.bob-old && sudo mv {_PATH}.pub {_PATH}.pub.bob-old && "
    assert cmd.startswith(move + f"sudo ssh-keygen -t rsa -b 4096 -f {_PATH} -N ''")


@pytest.mark.parametrize("bits, key", [(3072, "ssh.host_key_rsa_short"), (1024, "ssh.host_key_rsa_weak")])
def test_sshd_is_tested_before_the_restart(bits, key):
    cmd = _cmd(bits, key=key)
    assert "&& sudo sshd -t && " in cmd
    assert cmd.index("sshd -t") < cmd.index("restart")


def test_the_notice_names_the_key_sshd_serves():
    cmd = _cmd(3072, name="custom_rsa_key")
    assert "-f /etc/ssh/custom_rsa_key " in cmd and _PATH not in cmd
