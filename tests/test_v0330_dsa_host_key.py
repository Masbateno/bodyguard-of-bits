"""v0.33.0 — a DSA host key costs a point only when sshd serves it.

0.32.0 and before: −1 for any /etc/ssh/ssh_host_*_key.pub of type DSA, "in
use", "cryptographically broken". Measured on 11 November 2026, oracle
`ssh-keyscan -t dsa` against the live sshd (netnsbench/dsa0330):

| configuration                                  | OpenSSH 9.6 (Mint) | 10.2 (Ubuntu)          |
|------------------------------------------------|--------------------|------------------------|
| DSA key at the default path, no line           | not offered        | not offered            |
| HostKeyAlgorithms +ssh-dss only                | not offered        | refused: Bad key types |
| HostKey names it, default algorithms           | not offered        | not offered            |
| HostKey names it + HostKeyAlgorithms +ssh-dss  | offered (1024)     | refused: Bad key types |

So: served only when a HostKey line names the file and HostKeyAlgorithms
offers ssh-dss. Otherwise `ssh.host_key_dsa_unused`, INFO; sshd_config
unreadable, `ssh.host_key_dsa_unknown`, INFO, a ceiling. The fix no longer
generates an ed25519 host key over an existing one (ssh-keygen would stop at
"Overwrite (y/n)?"). Sources cited in the texts: FIPS 186-5 §4 (DSA no longer
approved for signature generation), OpenSSH release notes 7.0 and 10.0.
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import check_ssh
from tests.test_ssh import _make_host_key, base_snapshot

_HK = ["/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_dsa_key"]


def _run(cfg=None, readable=True, others=()):
    snap = base_snapshot(host_keys=[_make_host_key("dsa"), *others])
    snap.sshd_config = dict(cfg or {})
    snap.sshd_config_readable = readable
    result = check_ssh(snap)
    keys = {f.key for f in result.findings if f.key.startswith("ssh.host_key_dsa")}
    points = sum(d.points for d in result.deductions if d.key.startswith("ssh.host_key_dsa"))
    return keys, points, result


_NOT_SERVED = [
    ({}, "default-path"),
    ({"hostkeyalgorithms": "+ssh-dss"}, "algorithms-only"),
    ({"_hostkeys": _HK}, "hostkey-only"),
    ({"_hostkeys": _HK, "hostkeyalgorithms": "-ssh-dss"}, "removal-never-adds"),
    ({"_hostkeys": _HK, "hostkeyalgorithms": "ssh-ed25519,rsa-sha2-512"}, "list-without-dss"),
]
_SERVED = [
    ({"_hostkeys": _HK, "hostkeyalgorithms": "+ssh-dss"}, "measured-served"),
    ({"_hostkeys": _HK, "hostkeyalgorithms": "^ssh-dss"}, "in-front"),
    ({"_hostkeys": _HK, "hostkeyalgorithms": "ssh-ed25519,ssh-dss"}, "listed"),
    ({"_hostkeys": _HK, "hostkeyalgorithms": "+ssh-d*"}, "pattern"),
]


@pytest.mark.parametrize("cfg", [c for c, _ in _NOT_SERVED], ids=[i for _, i in _NOT_SERVED])
def test_not_served_is_shown_not_counted(cfg):
    keys, points, _ = _run(cfg)
    assert (keys, points) == ({"ssh.host_key_dsa_unused"}, 0)


@pytest.mark.parametrize("cfg", [c for c, _ in _SERVED], ids=[i for _, i in _SERVED])
def test_served_is_counted(cfg):
    keys, points, _ = _run(cfg)
    assert (keys, points) == ({"ssh.host_key_dsa"}, 1)


def test_unreadable_config_is_unknown_and_a_ceiling():
    from bob.visibility import VISIBILITY_KEYS
    keys, points, _ = _run(readable=False)
    assert (keys, points) == ({"ssh.host_key_dsa_unknown"}, 0)
    assert "ssh.host_key_dsa_unknown" in VISIBILITY_KEYS


def test_the_fix_keeps_an_existing_ed25519_host_key():
    _, _, result = _run({"_hostkeys": _HK, "hostkeyalgorithms": "+ssh-dss"},
                        others=(_make_host_key("ed25519"),))
    cmd = next(f.cmd for f in result.findings if f.key == "ssh.host_key_dsa")
    assert "ssh-keygen" not in cmd and "rm /etc/ssh/ssh_host_dsa_key" in cmd


def test_the_fix_generates_ed25519_only_without_one():
    _, _, result = _run({"_hostkeys": _HK, "hostkeyalgorithms": "+ssh-dss"})
    cmd = next(f.cmd for f in result.findings if f.key == "ssh.host_key_dsa")
    assert "ssh-keygen -t ed25519" in cmd
