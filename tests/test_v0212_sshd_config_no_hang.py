"""A FIFO (or any non-regular file) at /etc/ssh/sshd_config must not hang BOB.

Found by the v0.21.1 Debian stress test: the ssh snapshot probed the config
with a raw ``open("rb")`` to tell absent / unreadable / readable apart, and
``open`` on a FIFO blocks forever waiting for a writer — so ``mkfifo
/etc/ssh/sshd_config`` hung the whole audit. This is the samba FIFO class
(v0.20.1) at a read the ``read_text_capped`` guard never reached, because this
one is a purpose-built open-probe, not a capped read. The probe now ``stat``s
first (metadata only, never blocks) and fails closed on a non-regular file.
"""

from __future__ import annotations

import os
import pathlib
import signal

from bob.checks.ssh import _snapshot


class _Hang(BaseException):
    """Not an ``Exception`` — so the code under test cannot swallow it via a
    bare ``except OSError`` (``TimeoutError`` is an ``OSError`` subclass, which
    the sshd_config probe's ``except OSError`` would silently absorb, making the
    guard pass even while the open blocked)."""


def test_a_fifo_sshd_config_does_not_hang_and_reads_as_unreadable(monkeypatch, tmp_path):
    fifo = tmp_path / "sshd_config"
    os.mkfifo(fifo)
    monkeypatch.setattr(_snapshot, "_SSHD_CONFIG_PATH", pathlib.Path(fifo))

    def _hung(signum, frame):
        raise _Hang("from_system() blocked on a FIFO sshd_config")

    old = signal.signal(signal.SIGALRM, _hung)
    signal.alarm(5)
    try:
        snap = _snapshot.SSHSnapshot.from_system()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

    # Fail closed: a FIFO is not a legitimate config. It must never read as
    # present-and-parsed, so the subchecks cannot fall back to sshd's compiled-in
    # defaults and hand a host a false "root login is restricted".
    assert snap.sshd_config_readable is False
