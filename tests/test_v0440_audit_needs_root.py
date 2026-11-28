"""v0.44.0 — B-055: the audit stays root's (decided with the user, 27 November 2026).

Measured without root on three distributions (Linux Mint 22.3, Fedora 44,
Alpine 3.24): the audit was honest but incomplete, and on Fedora misleading —
two whole domains unread, the score up from 8 to 9, the exit code down from 2
to 1. A hardening audit's verdict must not depend on what the account could
read, so ``bob`` without root refuses, as in 0.43.0.

What B-055 needed was BOB not staying root for everything: plugins already run
as the calling account (tests/test_v0440_plugins_drop_root.py).

The account is simulated (``os.geteuid``), HOME is the test's own, and what
would run past the gate is stopped: were the gate ever lost, nothing real runs.
"""

from __future__ import annotations

import pytest

from bob import __main__ as M


class _Stopped(Exception):
    pass


def _stop(*_a, **_k):
    raise _Stopped("stopped by the test")


@pytest.fixture
def ordinary_account(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("DOAS_USER", raising=False)
    monkeypatch.setattr("bob.__main__.os.geteuid", lambda: 1000)
    import bob.cron
    import bob.manage_logs
    reached: list = []

    def audit(*_a, **_k):
        reached.append(True)
        raise _Stopped("stopped by the test")

    monkeypatch.setattr(M, "run_checks", audit)
    monkeypatch.setattr(bob.cron, "run_install_cron", _stop)
    monkeypatch.setattr(bob.cron, "run_manage_cron", _stop)
    monkeypatch.setattr(bob.manage_logs, "run_manage_logs", _stop)
    return reached


@pytest.mark.parametrize("args", [[], ["--fix"], ["--install-cron"], ["--manage-cron"],
                                  ["--manage-logs"], ["--fix", "--apply"]])
def test_without_root_the_audit_and_what_writes_are_refused(ordinary_account, capsys, args):
    rc = M.main(args + ["--offline", "--lang=en"])
    assert rc == M.EXIT_ERROR
    assert "must be run as root" in capsys.readouterr().err
    assert not ordinary_account, "the audit started without root"
