"""v0.32.0 — an RSA server host key below 2048 bits is scored, not noted.

A 1024-bit host key received the same INFO as a 3072-bit one ("4096-bit RSA
gives a higher security margin"). NIST SP 800-131A — the source BOB's own
detail cites — disallows generating RSA signatures with keys below 2048 bits,
and a host key signs at every connection. Now `ssh.host_key_rsa_weak`,
WARN −1, the level the user identity keys below 2048 have had since 0.4.x
(ssh.rsa_weak). From 2048 up, unchanged (INFO below 4096, OK from 4096).
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import check_ssh
from bob.scoring import FindingLevel
from tests.test_ssh import _make_host_key, base_snapshot


def _result(bits):
    return check_ssh(base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=bits)]))


@pytest.mark.parametrize("bits", [1024, 2047])
def test_below_2048_is_warn_minus_one(bits):
    result = _result(bits)
    f = next(f for f in result.findings if f.key == "ssh.host_key_rsa_weak")
    assert f.level == FindingLevel.WARN and f.detail and f.cmd_type == "fix"
    assert f.template_vars == {"name": "ssh_host_rsa_key", "bits": bits}
    assert [d.points for d in result.deductions if d.key == "ssh.host_key_rsa_weak"] == [1]
    assert "ssh.host_key_rsa_short" not in {x.key for x in result.findings}


def test_2048_stays_info_without_a_point():
    result = _result(2048)
    assert "ssh.host_key_rsa_weak" not in {f.key for f in result.findings}
    f = next(f for f in result.findings if f.key == "ssh.host_key_rsa_short")
    assert f.level == FindingLevel.INFO
    assert not [d for d in result.deductions if d.key.startswith("ssh.host_key_rsa")]
