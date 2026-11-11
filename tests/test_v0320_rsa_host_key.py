"""v0.32.0 — an RSA server host key below 2048 bits is scored, not noted.

A 1024-bit host key received the same INFO as a 3072-bit one ("4096-bit RSA
gives a higher security margin"). NIST SP 800-131A — the source BOB's own
detail cites — disallows generating RSA signatures with keys below 2048 bits,
and a host key signs every connection that negotiates its algorithm. Now
`ssh.host_key_rsa_weak`, WARN −1, the level the user identity keys below 2048
have had since 0.4.x (ssh.rsa_weak). From 2048 up, unchanged (INFO below 4096,
OK from 4096).

Narrowed before release (decided with the user, 11 November 2026, doctrine:
a key on disk is not a key sshd serves): the point is counted only when
sshd_config loads the file (a HostKey line names it, or none is written and it
is one of sshd's default files) and HostKeyAlgorithms leaves RSA offered.
Otherwise INFO, shown and not counted (`ssh.host_key_rsa_weak_unused`); with
sshd_config unreadable, unknown (`ssh.host_key_rsa_weak_unknown`, score "≤").
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


# --- narrowed: what sshd serves --------------------------------------------

def _keys_and_points(cfg=None, readable=True, name=None, bits=1024):
    snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=bits, name=name)])
    snap.sshd_config = dict(cfg or {})
    snap.sshd_config_readable = readable
    result = check_ssh(snap)
    keys = {f.key for f in result.findings if f.key.startswith("ssh.host_key_rsa")}
    points = sum(d.points for d in result.deductions if d.key.startswith("ssh.host_key_rsa"))
    return keys, points


_SERVED = [
    ({}, "default-file"),
    ({"_hostkeys": ["/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key"]}, "named"),
    ({"_hostkeys": ["/etc/ssh//ssh_host_rsa_key"]}, "named-unnormalised"),
    ({"hostkeyalgorithms": "+ssh-rsa"}, "appended"),
    ({"hostkeyalgorithms": "^rsa-sha2-512"}, "in-front"),
    ({"hostkeyalgorithms": "ssh-ed25519,rsa-sha2-256"}, "listed"),
    ({"hostkeyalgorithms": "ssh-ed25519,rsa-sha2-*"}, "listed-by-pattern"),
    ({"hostkeyalgorithms": "-rsa-sha2-256"}, "one-rsa-left"),
]
_NOT_SERVED = [
    ({"_hostkeys": ["/etc/ssh/ssh_host_ed25519_key"]}, "other-file"),
    ({"hostkeyalgorithms": "ssh-ed25519,ecdsa-sha2-nistp256"}, "rsa-not-listed"),
    ({"hostkeyalgorithms": "-rsa-sha2-*"}, "rsa-removed-by-pattern"),
    ({"hostkeyalgorithms": "-rsa-sha2-512,rsa-sha2-256"}, "both-rsa-removed"),
]


@pytest.mark.parametrize("cfg", [c for c, _ in _SERVED], ids=[i for _, i in _SERVED])
def test_served_is_counted(cfg):
    assert _keys_and_points(cfg) == ({"ssh.host_key_rsa_weak"}, 1)


@pytest.mark.parametrize("cfg", [c for c, _ in _NOT_SERVED], ids=[i for _, i in _NOT_SERVED])
def test_not_served_is_shown_not_counted(cfg):
    assert _keys_and_points(cfg) == ({"ssh.host_key_rsa_weak_unused"}, 0)


def test_a_file_outside_the_defaults_is_not_served_without_a_hostkey_line():
    assert _keys_and_points({}, name="ssh_host_rsa1024_key") == ({"ssh.host_key_rsa_weak_unused"}, 0)


def test_unreadable_config_is_unknown_and_a_ceiling():
    from bob.visibility import VISIBILITY_KEYS
    assert _keys_and_points(readable=False) == ({"ssh.host_key_rsa_weak_unknown"}, 0)
    assert "ssh.host_key_rsa_weak_unknown" in VISIBILITY_KEYS


def test_2048_is_untouched_by_the_config():
    assert _keys_and_points({"hostkeyalgorithms": "ssh-ed25519"}, bits=2048) == ({"ssh.host_key_rsa_short"}, 0)


def test_the_fix_regenerates_the_file_sshd_serves():
    snap = base_snapshot(host_keys=[_make_host_key("rsa", rsa_bits=1024, name="custom_rsa_key")])
    snap.sshd_config = {"_hostkeys": ["/etc/ssh/custom_rsa_key"]}
    f = next(f for f in check_ssh(snap).findings if f.key == "ssh.host_key_rsa_weak")
    assert "-f /etc/ssh/custom_rsa_key " in f.cmd


def test_the_parser_keeps_every_hostkey_line(tmp_path):
    from bob.checks.ssh import _parsers
    conf = tmp_path / "sshd_config"
    conf.write_text("HostKey /etc/ssh/ssh_host_ed25519_key\nHostKey /etc/ssh/ssh_host_rsa_key\n"
                    "HostKeyAlgorithms ssh-ed25519\nHostKeyAlgorithms rsa-sha2-512\n")
    cfg: dict = {}
    _parsers._parse_config_file(conf, cfg, set())
    assert cfg["_hostkeys"] == ["/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key"]
    assert cfg["hostkeyalgorithms"] == "ssh-ed25519"          # first value wins, as sshd
