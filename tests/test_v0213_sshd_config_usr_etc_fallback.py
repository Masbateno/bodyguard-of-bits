"""SSH config discovery must honour the /usr/etc vendor layout (openSUSE Leap 16+).

openSUSE ships the real `sshd_config` under `/usr/etc/ssh/sshd_config`, with
`/etc/ssh/sshd_config` as the *optional* override. sshd reads the `/usr/etc` file
(which carries the `Include /etc/ssh/sshd_config.d/*.conf` that pulls in the
drop-ins). BOB parsed `/etc/ssh/sshd_config` only, so on openSUSE it found nothing
and reported OpenSSH's compiled-in defaults for every config-derived finding — a
real `PermitRootLogin yes` was masked as "✔ root login restricted" (the
MEDIUM-HIGH gap from the v0.21.2 field campaign).

The fix: `/etc` wins when present (behaviour unchanged on every distro that keeps
sshd_config in `/etc`); when `/etc` is absent, BOB parses the `/usr/etc` vendor
file; only when *both* are absent does it fall back to defaults. FIFO safety
(v0.21.2) is preserved on whichever path is used — the non-regular guard runs
after the path is resolved.
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import _snapshot


def _patch_paths(monkeypatch, etc, vendor):
    monkeypatch.setattr(_snapshot, "_SSHD_CONFIG_PATH", etc)
    monkeypatch.setattr(_snapshot, "_SSHD_CONFIG_VENDOR_PATH", vendor)


def test_reads_vendor_config_when_etc_absent(tmp_path, monkeypatch):
    """The whole point: /etc absent, the /usr/etc file is read and its directives
    reach the snapshot — so a `PermitRootLogin yes` there is no longer invisible."""
    etc = tmp_path / "etc_sshd_config"  # deliberately not created
    vendor = tmp_path / "usr_etc_sshd_config"
    vendor.write_text("PermitRootLogin yes\nPasswordAuthentication no\n",
                      encoding="utf-8")
    _patch_paths(monkeypatch, etc, vendor)

    snap = _snapshot.SSHSnapshot.from_system()

    assert snap.sshd_config_readable is True
    assert snap.sshd_config.get("permitrootlogin") == "yes"
    assert snap.sshd_config.get("passwordauthentication") == "no"


def test_etc_wins_when_both_present(tmp_path, monkeypatch):
    """/etc is the override: when it exists it is used, /usr/etc ignored — sshd's
    own precedence, and unchanged behaviour on a normal distro."""
    etc = tmp_path / "etc_sshd_config"
    etc.write_text("PermitRootLogin no\n", encoding="utf-8")
    vendor = tmp_path / "usr_etc_sshd_config"
    vendor.write_text("PermitRootLogin yes\n", encoding="utf-8")
    _patch_paths(monkeypatch, etc, vendor)

    snap = _snapshot.SSHSnapshot.from_system()

    assert snap.sshd_config.get("permitrootlogin") == "no"


def test_absent_everywhere_runs_on_defaults(tmp_path, monkeypatch):
    """Neither path exists: sshd genuinely runs on its defaults, so the snapshot
    stays readable-with-empty-config (not 'unreadable', which would fail closed on
    a host that has no problem)."""
    etc = tmp_path / "nope_etc"
    vendor = tmp_path / "nope_vendor"
    _patch_paths(monkeypatch, etc, vendor)

    snap = _snapshot.SSHSnapshot.from_system()

    assert snap.sshd_config_readable is True
    assert snap.sshd_config == {}


def test_fifo_at_vendor_path_does_not_hang(tmp_path, monkeypatch):
    """FIFO safety must extend to the vendor path: a FIFO at /usr/etc (with /etc
    absent) must read as unreadable, never block on open()."""
    import os
    import signal

    etc = tmp_path / "nope_etc"
    vendor = tmp_path / "usr_etc_sshd_config"
    os.mkfifo(vendor)
    _patch_paths(monkeypatch, etc, vendor)

    class _Hang(BaseException):
        pass

    def _boom(signum, frame):
        raise _Hang

    old = signal.signal(signal.SIGALRM, _boom)
    signal.alarm(5)
    try:
        snap = _snapshot.SSHSnapshot.from_system()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

    assert snap.sshd_config_readable is False
