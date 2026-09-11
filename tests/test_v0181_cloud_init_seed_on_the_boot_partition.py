"""The credentials Raspberry Pi OS trixie leaves on the boot partition.

Trixie provisions the first account through cloud-init: the Imager writes a
NoCloud seed — ``user-data``, ``network-config``, ``meta-data`` — to the FAT
boot partition, and /etc/cloud/cloud.cfg.d/99_raspberry-pi.cfg reads it from
there. Nothing removes it after the first boot.

Measured on a Raspberry Pi Zero W the day after flashing: ``user-data`` held
the sudo account's yescrypt hash, byte-identical to its /etc/shadow entry, and
``network-config`` the 64-hex-digit Wi-Fi PSK. Both read as mode 0755 through
the vfat ``fmask=0022`` mount — readable by every local account. BOB 0.18.0
looked for ``userconf.txt`` only, found none, and printed::

    ✔ [OK] No provisioning credentials left on the boot partition

The remediation was proven on the board before it was written down: removing
only the secret lines and rebooting kept Wi-Fi, /etc/shadow, netplan and the
hostname unchanged, because meta-data still names the same instance and
cloud-init skips every once-per-instance module.

The fixtures below follow that board's files line for line; every secret in
them is invented.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

from bob.checks.raspberry_pi import RaspberryPiSnapshot, check_raspberry_pi
from bob.fixes import _can_apply_unattended
from bob import i18n

_MODEL = "Raspberry Pi Zero W Rev 1.1"
_HASH = "$y$j9T$Q2Z1ZmFrZXNhbHQ$ZmFrZWhhc2hmYWtlaGFzaGZha2VoYXNoZmFrZWhhc2g1"
_OLD_HASH = "$y$j9T$b2xkc2FsdG9sZHNhbHQ$b2xkaGFzaG9sZGhhc2hvbGRoYXNob2xkaGFzaA1"
_PSK = "3b1c" * 16

_USER_DATA = f"""#cloud-config
manage_resolv_conf: false
hostname: pizero
manage_etc_hosts: true
packages:
- avahi-daemon
apt:
  preserve_sources_list: true
  conf: |
    Acquire {{
      Check-Date "false";
    }};
timezone: Europe/Paris
keyboard:
  model: pc105
  layout: "fr"
user:
  name: so6
  shell: /bin/bash
  lock_passwd: false
  passwd: {_HASH}
  sudo: true
ssh_pwauth: true
runcmd:
- [ sh, -c, "true" ]
"""

_NETWORK = f"""network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: true
      optional: true
  wifis:
    wlan0:
      dhcp4: true
      regulatory-domain: "FR"
      access-points:
        "HomeNetwork":
          password: "{_PSK}"
      optional: true
"""


@pytest.fixture
def board(tmp_path):
    boot = tmp_path / "firmware"
    boot.mkdir()
    (boot / "config.txt").write_text("arm_64bit=0\n", encoding="utf-8")
    (boot / "meta-data").write_text("instance-id: rpi-imager-1789045005454\n", encoding="utf-8")
    (boot / "user-data").write_text(_USER_DATA, encoding="utf-8")
    (boot / "network-config").write_text(_NETWORK, encoding="utf-8")
    passwd = tmp_path / "passwd"
    passwd.write_text("so6:x:1000:1000::/home/so6:/bin/bash\n", encoding="utf-8")
    shadow = tmp_path / "shadow"
    shadow.write_text(f"so6:{_HASH}:20341:0:99999:7:::\n", encoding="utf-8")
    return boot, passwd, shadow


def _audit(boot, passwd, shadow):
    snap = RaspberryPiSnapshot.from_system(
        _boot_dir=boot, _passwd=passwd, _shadow=shadow, _model=_MODEL)
    i18n.init("en")
    return snap, check_raspberry_pi(snap, t=i18n.t)


def _by_key(result):
    return {f.key: f for f in result.findings}


# ---------------------------------------------------------------------------
# What the board showed
# ---------------------------------------------------------------------------

def test_the_password_in_the_seed_is_reported_not_passed_as_ok(board):
    _, result = _audit(*board)
    found = _by_key(result)
    assert "raspberry_pi.userconf_absent" not in found, (
        "BOB 0.18.0's all-clear, printed over the sudo account's hash"
    )
    f = found["raspberry_pi.seed_password"]
    assert f.level.name == "WARN"
    assert "so6" in f.message
    assert any(d.key == "raspberry_pi.seed_password" for d in result.deductions)


def test_the_wifi_key_in_the_seed_is_reported(board):
    _, result = _audit(*board)
    f = _by_key(result)["raspberry_pi.seed_wifi_key"]
    assert "1" in f.message
    assert any(d.key == "raspberry_pi.seed_wifi_key" for d in result.deductions)


def test_the_hash_is_said_to_be_the_current_one_when_it_is(board):
    snap, result = _audit(*board)
    assert snap.seed_password_current is True
    assert "uses now" in _by_key(result)["raspberry_pi.seed_password"].detail


def test_no_secret_reaches_the_report(board):
    """The finding names the file and the account — never the value."""
    _, result = _audit(*board)
    text = " ".join(f"{f.message} {f.detail} {f.cmd}" for f in result.findings)
    assert _HASH not in text and _HASH[:12] not in text
    assert _PSK not in text


# ---------------------------------------------------------------------------
# The other states, each asserting only what it established
# ---------------------------------------------------------------------------

def test_a_stale_hash_is_called_stale(board):
    boot, passwd, shadow = board
    shadow.write_text(f"so6:{_OLD_HASH}:20341:0:99999:7:::\n", encoding="utf-8")
    snap, result = _audit(boot, passwd, shadow)
    assert snap.seed_password_current is False
    assert "no longer" in _by_key(result)["raspberry_pi.seed_password"].detail


def test_an_unreadable_shadow_leaves_currency_unestablished(board, tmp_path):
    boot, passwd, _ = board
    snap, result = _audit(boot, passwd, tmp_path / "no-such-shadow")
    assert snap.seed_password_current is None
    assert "not established" in _by_key(result)["raspberry_pi.seed_password"].detail


def test_a_clear_text_password_is_named_as_one(board):
    boot, passwd, shadow = board
    (boot / "user-data").write_text(
        _USER_DATA.replace(f"  passwd: {_HASH}", "  plain_text_passwd: hunter2"),
        encoding="utf-8")
    _, result = _audit(boot, passwd, shadow)
    f = _by_key(result)["raspberry_pi.seed_password"]
    assert "clear text" in f.message
    assert "hunter2" not in f"{f.message} {f.detail} {f.cmd}"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_a_seed_bob_could_not_read_blocks_the_all_clear(board):
    boot, passwd, shadow = board
    (boot / "user-data").chmod(0o000)
    try:
        _, result = _audit(boot, passwd, shadow)
    finally:
        (boot / "user-data").chmod(0o644)
    found = _by_key(result)
    assert "raspberry_pi.seed_unreadable" in found
    assert "raspberry_pi.userconf_absent" not in found, (
        "an all-clear about a file BOB never read"
    )


# ---------------------------------------------------------------------------
# The remediation, run — the round trip the board went through
# ---------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("sed") is None, reason="needs sed")
def test_applying_both_commands_clears_the_findings_and_nothing_else(board):
    boot, passwd, shadow = board
    _, before = _audit(boot, passwd, shadow)
    for key in ("raspberry_pi.seed_password", "raspberry_pi.seed_wifi_key"):
        cmd = _by_key(before)[key].cmd
        assert _can_apply_unattended(cmd), f"--fix --apply would refuse: {cmd}"
        subprocess.run(re.sub(r"^sudo ", "", cmd), shell=True, check=True)

    user_data = (boot / "user-data").read_text(encoding="utf-8")
    network = (boot / "network-config").read_text(encoding="utf-8")
    assert _HASH not in user_data and _PSK not in network
    # Only the secret lines went: the rest of the seed is the same file.
    assert user_data == _USER_DATA.replace(f"  passwd: {_HASH}\n", "")
    assert network == _NETWORK.replace(f'          password: "{_PSK}"\n', "")
    assert (boot / "meta-data").read_text(encoding="utf-8").startswith("instance-id: rpi-imager")

    _, after = _audit(boot, passwd, shadow)
    found = _by_key(after)
    assert "raspberry_pi.seed_password" not in found
    assert "raspberry_pi.seed_wifi_key" not in found
    assert "raspberry_pi.userconf_absent" in found


def test_a_seed_without_secrets_is_clean():
    """The mirror, from the collector: nothing there, all-clear allowed."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        boot = Path(d)
        (boot / "user-data").write_text("#cloud-config\nhostname: pizero\n", encoding="utf-8")
        (boot / "network-config").write_text("network:\n  version: 2\n", encoding="utf-8")
        _, result = _audit(boot, boot / "passwd-missing", boot / "shadow-missing")
    assert "raspberry_pi.userconf_absent" in _by_key(result)
