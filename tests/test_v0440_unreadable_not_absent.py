"""v0.44.0 — B-055 step 1: unreadable is not absent, and it is said.

Measured on a test host (26 November 2026): the same audit run as root and as
an ordinary account. Three places said "absent", or nothing at all, where the
file existed and could not be read — the UFW log (/var/log/ufw.log, 0640
syslog:adm), root's ~/.ssh (0700) and GRUB's password (grub.cfg, 0600).

The denial is simulated here, never left to file modes: the tests must mean the
same run as root, as an ordinary account or on a CI runner.
"""

from __future__ import annotations

import types

import pytest

from bob import i18n
from bob.checks import grub as G
from bob.checks import logs as L
from bob.checks.ssh import _parsers as P
from bob.checks.ssh import _snapshot as S
from bob.checks.ssh import check_ssh
from bob.visibility import NOT_A_VISIBILITY_LIMIT, VISIBILITY_KEYS


@pytest.fixture(autouse=True)
def _english():
    before = i18n.current_lang()
    i18n.init("en")
    yield
    i18n.init(before)


def keys(result) -> list[str]:
    return [f.key for f in result.findings]


def message(result, key: str) -> str:
    return next(f.message for f in result.findings if f.key == key)


# --- GRUB --------------------------------------------------------------------

def test_an_unread_grub_cfg_says_the_password_is_not_checked():
    snap = G.GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o600, readable=False)
    result = G.check_grub(snap, i18n.t)
    assert "grub.password_unknown" in keys(result)
    assert "grub.cfg_perms_ok" in keys(result)
    assert not {"grub.no_password", "grub.password_set"} & set(keys(result))
    assert "/boot/grub/grub.cfg" in message(result, "grub.password_unknown")


def test_a_read_grub_cfg_without_password_still_says_none():
    snap = G.GrubSnapshot(cfg_path="/boot/grub/grub.cfg", cfg_mode=0o600,
                          readable=True, password_set=False)
    result = G.check_grub(snap, i18n.t)
    assert "grub.no_password" in keys(result)
    assert "grub.password_unknown" not in keys(result)


def test_a_denied_read_of_grub_cfg_is_recorded(tmp_path, monkeypatch):
    cfg = tmp_path / "grub.cfg"
    cfg.write_text("set superusers=\"admin\"\n")
    monkeypatch.setattr(G, "_GRUB_CFG_CANDIDATES", (str(cfg),))

    def denied(*_a, **_k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(G, "read_text_capped", denied)
    snap = G.GrubSnapshot.from_system()
    assert snap.cfg_path == str(cfg) and snap.readable is False
    assert "grub.password_unknown" in keys(G.check_grub(snap, i18n.t))


def test_the_unknown_password_carries_no_point_and_is_not_a_ceiling():
    assert "grub.password_unknown" in NOT_A_VISIBILITY_LIMIT
    assert "grub.password_unknown" not in VISIBILITY_KEYS


# --- the UFW log ---------------------------------------------------------------

def _no_journald(monkeypatch):
    monkeypatch.setattr(L, "_read_from_journald", lambda days: ("", False))


def test_a_present_but_unreadable_ufw_log_is_not_called_absent(tmp_path, monkeypatch):
    log = tmp_path / "ufw.log"
    log.write_text("")

    def denied(_path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(L, "_read_log_tail_flagged", denied)
    _no_journald(monkeypatch)
    snap = L.LogsSnapshot.from_system(log_days=7, log_path=log)
    assert snap.log_found is False and snap.logfile_readable is False
    assert snap.files_unread == (str(log),)
    result, _report = L.check_logs(snap, t=i18n.t)
    assert "logs.logfile_unreadable" in keys(result)
    assert "logs.no_logfile" not in keys(result)
    assert str(log) in message(result, "logs.logfile_unreadable")


def test_an_absent_ufw_log_is_still_absent(tmp_path, monkeypatch):
    _no_journald(monkeypatch)
    snap = L.LogsSnapshot.from_system(log_days=7, log_path=tmp_path / "absent.log")
    assert snap.log_found is False and snap.logfile_readable is True
    result, _report = L.check_logs(snap, t=i18n.t)
    assert "logs.no_logfile" in keys(result)
    assert "logs.logfile_unreadable" not in keys(result)


def test_an_unreadable_ufw_log_counts_as_not_read():
    assert "logs.logfile_unreadable" in VISIBILITY_KEYS


# --- ~/.ssh ----------------------------------------------------------------------

def _probe(monkeypatch, tmp_path, home, user="alice", sudo=""):
    """SSHSnapshot.from_system with nothing of the host's sshd, as *user*."""
    monkeypatch.setattr(S, "_SSHD_CONFIG_PATH", tmp_path / "no-sshd_config")
    monkeypatch.setattr(S, "_command_exists", lambda name: False)
    monkeypatch.setattr("bob.sysinfo.invoking_user_name", lambda: sudo)
    monkeypatch.setattr(S.pwd, "getpwuid",
                        lambda uid: types.SimpleNamespace(pw_dir=str(home), pw_name=user))
    return S.SSHSnapshot.from_system()


def test_without_sudo_the_account_running_bob_is_read(tmp_path, monkeypatch):
    """Measured: without root, BOB looked at /root/.ssh. It reads its own."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    snap = _probe(monkeypatch, tmp_path, home)
    assert snap.user_home == home and snap.ssh_user == "alice"
    assert snap.ssh_dir_exists is True and snap.ssh_dir_readable is True


def test_a_denied_ssh_dir_is_unreadable_not_absent(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)

    def denied(_path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(S, "strict_is_dir", denied)
    snap = _probe(monkeypatch, tmp_path, home)
    assert snap.ssh_dir_readable is False and snap.ssh_dir_exists is False
    result = check_ssh(snap, i18n.t)
    assert "ssh.dir_unreadable" in keys(result)
    assert "ssh.dir_not_found" not in keys(result)
    assert "alice" in message(result, "ssh.dir_unreadable")


def test_a_denial_half_way_drops_what_was_read(tmp_path, monkeypatch):
    """A part of ~/.ssh is not a verdict on it: nothing of it is kept."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)

    def denied(_dir):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(P, "_collect_private_keys", denied)
    snap = _probe(monkeypatch, tmp_path, home)
    assert snap.ssh_dir_readable is False
    assert snap.ssh_dir_exists is False and snap.ssh_dir_perms is None
    assert "ssh.no_private_keys" not in keys(check_ssh(snap, i18n.t))


def test_an_absent_ssh_dir_is_still_absent(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    snap = _probe(monkeypatch, tmp_path, home)
    assert snap.ssh_dir_readable is True and snap.ssh_dir_exists is False
    result = check_ssh(snap, i18n.t)
    assert "ssh.dir_not_found" in keys(result)
    assert "ssh.dir_unreadable" not in keys(result)


def test_an_unreadable_ssh_dir_counts_as_not_read():
    assert "ssh.dir_unreadable" in VISIBILITY_KEYS


# --- the authentication journal (measured on Fedora 44) ------------------------------

from bob.checks import auth_log as A  # noqa: E402

_HINT = ("Hint: You are currently not seeing messages from other users and the system.\n"
         "      Users in groups 'adm', 'systemd-journal', 'wheel' can see all messages.\n")


def _journal(monkeypatch, stdout, stderr):
    monkeypatch.setattr(A.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr))


def test_journalctl_saying_the_account_sees_only_its_own_is_recorded(monkeypatch):
    """Measured: exit 0, '-- No entries --', and the hint on stderr."""
    _journal(monkeypatch, "-- No entries --\n", _HINT)
    text = A._read_auth_from_journald()
    assert text == "-- No entries --\n" and text.partial is True


def test_a_whole_journal_is_not_called_partial(monkeypatch):
    _journal(monkeypatch, "-- No entries --\n", "")
    assert getattr(A._read_auth_from_journald(), "partial", False) is False


def test_a_partial_journal_is_not_no_login(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "_LOG_PATHS", [tmp_path / "no-auth.log"])
    _journal(monkeypatch, "-- No entries --\n", _HINT)
    snap = A.AuthLogSnapshot.from_system()
    assert snap.journal_readable is False
    result = A.check_auth_log(snap, i18n.t)
    assert "auth_log.journal_partial" in keys(result)
    assert "auth_log.no_logins" not in keys(result)


def test_a_whole_journal_without_logins_still_says_none(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "_LOG_PATHS", [tmp_path / "no-auth.log"])
    _journal(monkeypatch, "-- No entries --\n", "")
    snap = A.AuthLogSnapshot.from_system()
    assert snap.journal_readable is True
    assert "auth_log.no_logins" in keys(A.check_auth_log(snap, i18n.t))


def test_the_partial_journal_carries_no_point_and_is_not_a_ceiling():
    assert "auth_log.journal_partial" in NOT_A_VISIBILITY_LIMIT
    assert "auth_log.journal_partial" not in VISIBILITY_KEYS
