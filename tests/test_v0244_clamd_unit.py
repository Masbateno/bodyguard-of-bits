"""v0.24.4 — start the ClamAV daemon this host actually ships.

The fix for ``clamav.clamd_inactive`` was ``sudo systemctl enable --now
clamav-daemon`` everywhere. Measured by installing each family's daemon
package: Debian 13, Ubuntu 24.04 and Arch ship ``clamav-daemon.service``;
Fedora ``clamd@.service`` (a template, run as ``clamd@scan``); openSUSE
Tumbleweed ``clamd.service``; Alpine an OpenRC script ``clamd``. On Fedora 44
``clamd@scan`` then failed — "Please define server type (local and/or TCP)":
its scan.conf ships every socket commented out, and the signature database is
empty until freshclam runs. Socket, freshclam, enable: the service came up.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.checks import _run, clamav
from bob.checks.clamav import ClamAVSnapshot, check_clamav
from tests.helpers import _t


def _snap(**kw):
    base = dict(installed=True, freshclam_installed=True, clamd_active=False, db_age_days=1)
    base.update(kw)
    return ClamAVSnapshot(**base)


def _cmd(snap):
    return next(f for f in check_clamav(snap, t=_t).findings if f.key == "clamav.clamd_inactive").cmd


@pytest.fixture
def systemd(monkeypatch):
    monkeypatch.setattr(_run, "openrc_available", lambda: False)
    monkeypatch.setattr(_run, "_command_exists", lambda c: True)


class TestWhichUnit:
    @pytest.mark.parametrize("shipped, unit", [
        ("/usr/lib/systemd/system/clamav-daemon.service", "clamav-daemon"),
        ("/usr/lib/systemd/system/clamd@.service", "clamd@scan"),
        ("/usr/lib/systemd/system/clamd.service", "clamd"),
        (None, ""),
    ])
    def test_the_unit_the_package_ships(self, monkeypatch, shipped, unit):
        monkeypatch.setattr(clamav, "openrc_available", lambda: False)
        monkeypatch.setattr(clamav, "path_exists", lambda p: str(p) == shipped)
        assert clamav._clamd_unit() == unit

    def test_openrc_ships_clamd(self, monkeypatch):
        monkeypatch.setattr(clamav, "openrc_available", lambda: True)
        monkeypatch.setattr(clamav, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(clamav, "path_exists", lambda p: str(p) == "/etc/init.d/clamd")
        assert clamav._clamd_unit() == "clamd"


class TestTheFix:
    def test_debian(self, systemd):
        assert _cmd(_snap(clamd_unit="clamav-daemon")) == "sudo systemctl enable --now clamav-daemon"

    def test_fedora_gets_its_socket_and_database_first(self, systemd):
        cmd = _cmd(_snap(clamd_unit="clamd@scan", clamd_needs_socket=True, db_age_days=None))
        assert cmd == ("sudo sed -i '0,/^#LocalSocket \\/run\\/clamd.scan\\/clamd.sock$/"
                       "s//LocalSocket \\/run\\/clamd.scan\\/clamd.sock/' /etc/clamd.d/scan.conf"
                       " && sudo freshclam && sudo systemctl enable --now clamd@scan")

    def test_a_configured_fedora_just_starts(self, systemd):
        assert _cmd(_snap(clamd_unit="clamd@scan")) == "sudo systemctl enable --now clamd@scan"

    def test_no_daemon_shipped_no_command(self, systemd):
        assert not _cmd(_snap(clamd_unit=""))

    def test_openrc(self, monkeypatch):
        monkeypatch.setattr(_run, "openrc_available", lambda: True)
        monkeypatch.setattr(_run, "_command_exists", lambda c: c != "systemctl")
        assert _cmd(_snap(clamd_unit="clamd")) == "sudo rc-update add clamd default && sudo rc-service clamd start"


class TestScanConf:
    @pytest.mark.parametrize("text, lacks", [
        ("#Example\n#LocalSocket /run/clamd.scan/clamd.sock\n", True),
        ("LocalSocket /run/clamd.scan/clamd.sock\n", False),
        ("TCPSocket 3310\n", False),
    ])
    def test_the_socket_lines(self, tmp_path, monkeypatch, text, lacks):
        conf = tmp_path / "scan.conf"; conf.write_text(text)
        monkeypatch.setattr(clamav, "_SCAN_CONF", conf)
        assert clamav._scan_conf_lacks_socket() is lacks

    def test_an_unreadable_conf_is_no_evidence(self, monkeypatch):
        monkeypatch.setattr(clamav, "_SCAN_CONF", Path("/nonexistent/scan.conf"))
        assert clamav._scan_conf_lacks_socket() is False


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_message_names_the_unit_this_host_ships(systemd, lang):
    """It said "(clamav-daemon)" on a Fedora whose daemon is clamd@scan."""
    from bob import i18n
    i18n.init(lang)
    try:
        msg = next(f for f in check_clamav(_snap(clamd_unit="clamd@scan"), t=i18n.t).findings
                   if f.key == "clamav.clamd_inactive").message
    finally:
        i18n.init(lang="en")
    assert "clamd@scan" in msg and "clamav-daemon" not in msg


class TestASocketEveryLocalUserCanReach:
    """Measured in containers with each package's own clamd.conf: on Alpine
    (``LocalSocketMode`` commented, ``srw-rw-rw-`` under a 0755 /run/clamav)
    and on Debian (``LocalSocketMode 666``) an unprivileged user sent SHUTDOWN
    and clamd stopped. With ``LocalSocketGroup`` and ``LocalSocketMode 660``
    that user was refused and a group member still got PONG. Fedora's 0666
    socket sits in a 0710 directory: refused."""

    @pytest.fixture
    def sock_dir(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp(dir="/tmp")          # every ancestor searchable by others
        yield Path(d)
        shutil.rmtree(d)

    def _socket(self, sock_dir, dir_mode, sock_mode):
        import socket
        path = sock_dir / "clamd.sock"
        s = socket.socket(socket.AF_UNIX)
        s.bind(str(path))
        s.close()
        path.chmod(sock_mode)
        sock_dir.chmod(dir_mode)
        return str(path)

    @pytest.mark.parametrize("dir_mode, sock_mode, expected", [
        (0o755, 0o666, True),     # Alpine, Arch, openSUSE, Debian as packaged
        (0o755, 0o660, False),    # LocalSocketGroup + LocalSocketMode 660
        (0o710, 0o666, False),    # Fedora's /run/clamd.scan
    ])
    def test_who_can_connect(self, sock_dir, dir_mode, sock_mode, expected):
        assert clamav._open_to_others(self._socket(sock_dir, dir_mode, sock_mode)) is expected

    def test_not_a_socket_is_not_judged(self, sock_dir):
        (sock_dir / "f").write_text("")
        assert clamav._open_to_others(str(sock_dir / "f")) is None

    def test_the_configured_socket_is_read(self, sock_dir, monkeypatch):
        path = self._socket(sock_dir, 0o755, 0o666)
        conf = sock_dir / "clamd.conf"
        conf.write_text(f"#LocalSocket /tmp/clamd.sock\nLocalSocket {path}\nUser clamav\n")
        monkeypatch.setattr(clamav, "_CLAMD_CONFS", (Path("/nonexistent/clamd.conf"), conf))
        assert clamav._socket_open_to_all() == path

    def test_a_commented_socket_is_not_the_daemon_s(self, sock_dir, monkeypatch):
        path = self._socket(sock_dir, 0o755, 0o666)
        conf = sock_dir / "clamd.conf"
        conf.write_text(f"#LocalSocket {path}\nTCPSocket 3310\n")
        monkeypatch.setattr(clamav, "_CLAMD_CONFS", (conf,))
        assert clamav._socket_open_to_all() == ""

    def test_it_is_said_without_a_command(self):
        result = check_clamav(_snap(clamd_active=True, clamd_socket_open="/run/clamav/clamd.sock"), t=_t)
        finding = next(f for f in result.findings if f.key == "clamav.socket_open_to_all")
        assert not finding.cmd
        assert not [d for d in result.deductions if d.key == "clamav.socket_open_to_all"]

    def test_a_restricted_socket_says_nothing(self):
        result = check_clamav(_snap(clamd_active=True), t=_t)
        assert "clamav.socket_open_to_all" not in {f.key for f in result.findings}

    def test_the_snapshot_looks_when_the_daemon_runs(self):
        import inspect
        src = inspect.getsource(ClamAVSnapshot.from_system)
        assert "if snap.clamd_active:\n            snap.clamd_socket_open = _socket_open_to_all()" in src

    @pytest.mark.parametrize("lang, needle", [("en", "SHUTDOWN included"), ("fr", "SHUTDOWN compris")])
    def test_the_rendered_message(self, lang, needle):
        from bob import i18n
        i18n.init(lang)
        try:
            msg = next(f for f in check_clamav(_snap(clamd_active=True, clamd_socket_open="/run/clamav/clamd.sock"),
                                               t=i18n.t).findings if f.key == "clamav.socket_open_to_all").message
        finally:
            i18n.init(lang="en")
        assert needle in msg and "/run/clamav/clamd.sock" in msg


class TestARunningDaemonWithoutSystemd:
    """Measured in an Alpine container: clamd running, its socket
    ``/run/clamav/clamd.sock`` present — BOB said "ClamAV daemon (clamd) is not
    running": without systemctl it looked only for ``clamd.ctl``."""

    @pytest.fixture
    def alpine(self, monkeypatch):
        monkeypatch.setattr(clamav, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(clamav, "_clamd_unit", lambda: "clamd")
        monkeypatch.setattr(clamav, "_DB_CANDIDATES", [])
        monkeypatch.setattr(clamav, "_SCAN_LOG_CANDIDATES", [])
        monkeypatch.setattr(clamav, "_CLAMD_SOCKETS", [])
        monkeypatch.setattr(clamav, "_CLAMD_CONFS", ())

    def test_openrc_answers(self, alpine, monkeypatch):
        monkeypatch.setattr(clamav, "unit_active_state", lambda name: "active" if name == "clamd" else None)
        assert ClamAVSnapshot.from_system().clamd_active

    def test_the_configured_socket_shows_it_running(self, alpine, monkeypatch, tmp_path):
        monkeypatch.setattr(clamav, "unit_active_state", lambda name: None)
        sock = tmp_path / "clamd.sock"
        sock.write_text("")
        conf = tmp_path / "clamd.conf"
        conf.write_text(f"LocalSocket {sock}\n")
        monkeypatch.setattr(clamav, "_CLAMD_CONFS", (conf,))
        assert ClamAVSnapshot.from_system().clamd_active

    def test_nothing_running(self, alpine, monkeypatch):
        monkeypatch.setattr(clamav, "unit_active_state", lambda name: "inactive")
        assert not ClamAVSnapshot.from_system().clamd_active
