"""v0.24.4 — an SSH jail that reads a file nothing writes is active and blind.

Measured on a Raspberry Pi (Raspbian 13 trixie, no rsyslog — sshd logs to the
systemd journal only). With the sshd jail on ``backend = polling`` and
``logpath = /var/log/auth.log``, ``fail2ban-client status`` listed the jail;
two failed SSH logins later its ``Total failed`` was still 0 — and BOB said
"SSH brute-force protection active". With the stock jail (``Journal matches:``)
the same two failures counted 2.

BOB now reads what the SSH jail watches. A jail on files, with no syslog
daemon running to write them, is a WARN −1 instead of an OK. Not knowing
whether a syslog daemon runs (an OpenRC host that names none) keeps the OK:
unknown is not blamed.
"""

from __future__ import annotations

import pytest

from bob.checks import fail2ban as f2b
from bob.checks.fail2ban import Fail2banSnapshot, check_fail2ban
from bob.scoring import FindingLevel
from tests.helpers import _keys, _t

# Verbatim from the Pi (tabs as fail2ban prints them).
_FILE_JAIL = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n"
              "|  |- Total failed:\t0\n|  `- File list:\t/var/log/auth.log\n`- Actions\n")
_JOURNAL_JAIL = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n"
                 "|  |- Total failed:\t0\n|  `- Journal matches:\t_SYSTEMD_UNIT=ssh.service + _COMM=sshd\n"
                 "`- Actions\n")


def _snap(**kw):
    base = dict(installed=True, service_active=True, active_jails=["sshd"], ssh_jail="sshd",
                ssh_jail_files=("/var/log/auth.log",), ssh_jail_journal=False,
                syslog_active=False, journal_available=True)
    base.update(kw)
    return Fail2banSnapshot(**base)


class TestWhatTheJailReads:
    def test_a_file_backed_jail(self):
        assert f2b._parse_jail_sources(_FILE_JAIL) == (("/var/log/auth.log",), False)

    def test_a_journal_backed_jail(self):
        assert f2b._parse_jail_sources(_JOURNAL_JAIL) == ((), True)


class TestTheVerdict:
    def test_files_with_no_syslog_daemon_are_blind(self):
        result = check_fail2ban(_snap(), t=_t)
        finding = next(f for f in result.findings if f.key == "fail2ban.ssh_jail_blind")
        assert finding.level == FindingLevel.WARN
        assert [d.points for d in result.deductions] == [1]
        assert "fail2ban.ssh_jail_active" not in _keys(result)

    def test_a_running_syslog_daemon_writing_sshd_lines_keeps_the_ok(self):
        assert "fail2ban.ssh_jail_active" in _keys(check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=True), t=_t))

    def test_a_running_syslog_daemon_is_not_proof_on_its_own(self):
        """Mint 22.3, rsyslog running, jail on a file rsyslog does not write:
        two failed logins, ``Total failed: 0`` — and BOB had said OK."""
        result = check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=False), t=_t)
        assert "fail2ban.ssh_jail_file_silent" in _keys(result)
        assert "fail2ban.ssh_jail_active" not in _keys(result)
        assert not result.deductions

    def test_an_unread_file_is_not_credited(self):
        result = check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=None), t=_t)
        assert "fail2ban.ssh_jail_source_unverified" in _keys(result)
        assert "fail2ban.ssh_jail_active" not in _keys(result)

    def test_sshd_lines_are_proof_even_when_the_init_cannot_say(self):
        assert "fail2ban.ssh_jail_active" in _keys(check_fail2ban(_snap(syslog_active=None, ssh_jail_fed=True), t=_t))

    def test_an_unknown_syslog_state_is_not_blamed(self):
        result = check_fail2ban(_snap(syslog_active=None), t=_t)
        assert not result.deductions

    def test_an_unknown_syslog_state_is_not_credited_either(self):
        """Not knowing the file is written is no proof the jail sees anything."""
        result = check_fail2ban(_snap(syslog_active=None), t=_t)
        assert "fail2ban.ssh_jail_source_unverified" in _keys(result)
        assert "fail2ban.ssh_jail_active" not in _keys(result)

    def test_a_journal_jail_is_not_blind(self):
        snap = _snap(ssh_jail_files=(), ssh_jail_journal=True, syslog_active=None)
        assert "fail2ban.ssh_jail_active" in _keys(check_fail2ban(snap, t=_t))


class TestTheFix:
    def test_the_jail_is_pointed_at_the_journal(self, monkeypatch):
        monkeypatch.setattr(f2b, "service_restart_cmd", lambda unit: f"sudo systemctl restart {unit}")
        finding = next(f for f in check_fail2ban(_snap(), t=_t).findings
                       if f.key == "fail2ban.ssh_jail_blind")
        assert finding.cmd == ("printf '[%s]\\nbackend = systemd\\n' sshd | "
                               "sudo tee /etc/fail2ban/jail.d/zz-bob-sshd-journal.local && "
                               "sudo systemctl restart fail2ban")

    def test_the_override_is_read_after_every_existing_local(self, monkeypatch):
        """Measured on the Pi: a ``zz-bobtest.local`` (backend = polling) sorted
        after BOB's ``zz-bob-sshd-journal.local`` and the jail stayed blind."""
        monkeypatch.setattr(f2b, "service_restart_cmd", lambda unit: f"sudo systemctl restart {unit}")
        finding = next(f for f in check_fail2ban(_snap(jail_d_locals=("sshd.local", "zz-bobtest.local")),
                                                 t=_t).findings if f.key == "fail2ban.ssh_jail_blind")
        name = finding.cmd.split("/etc/fail2ban/jail.d/")[1].split(" ")[0]
        assert name.endswith(".local") and sorted(["zz-bobtest.local", name])[-1] == name

    def test_no_journal_no_command(self):
        """Without the systemd journal, starting a syslog daemon is the operator's call."""
        finding = next(f for f in check_fail2ban(_snap(journal_available=False), t=_t).findings
                       if f.key == "fail2ban.ssh_jail_blind")
        assert not finding.cmd

    def test_a_hostile_jail_name_stays_one_word(self):
        finding = next(f for f in check_fail2ban(_snap(ssh_jail="ssh; rm -rf /"), t=_t).findings
                       if f.key == "fail2ban.ssh_jail_blind")
        assert "'ssh; rm -rf /'" in finding.cmd
        assert "zz-bob-ssh__rm_-rf__-journal.local" in finding.cmd

    @pytest.mark.parametrize("lang, needle", [("en", "no syslog daemon writes it"),
                                              ("fr", "aucun démon syslog ne l'écrit")])
    def test_the_rendered_message(self, lang, needle):
        from bob import i18n
        i18n.init(lang)
        try:
            finding = next(f for f in check_fail2ban(_snap(), t=i18n.t).findings
                           if f.key == "fail2ban.ssh_jail_blind")
        finally:
            i18n.init(lang="en")
        assert needle in finding.message
        assert "'sshd'" in finding.message and "/var/log/auth.log" in finding.message


class TestIsASyslogDaemonRunning:
    @pytest.mark.parametrize("states, expected", [
        ({"rsyslog": "active"}, True),
        ({}, False),
        ({"syslog": None}, None),
    ])
    def test_the_answer(self, monkeypatch, states, expected):
        monkeypatch.setattr(f2b, "unit_active_state", lambda name: states.get(name, "inactive"))
        assert f2b._syslog_active() is expected

    def test_the_jail_sources_are_collected(self, monkeypatch):
        outputs = {("fail2ban-client", "ping"): "pong",
                   ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
                   ("fail2ban-client", "status", "sshd"): _FILE_JAIL}
        monkeypatch.setattr(f2b, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "inactive")
        monkeypatch.setattr(f2b, "_run", lambda *a, **k: outputs.get(a, ""))
        snap = Fail2banSnapshot.from_system()
        assert (snap.ssh_jail_files, snap.ssh_jail_journal, snap.syslog_active) == \
            (("/var/log/auth.log",), False, False)


class TestDoesTheFileHoldSshdMessages:
    def test_a_file_rsyslog_writes(self, tmp_path):
        f = tmp_path / "auth.log"     # Mint 22.3, verbatim but for the address
        f.write_text("2026-10-11T20:51:02.118437+02:00 so6minttest sshd[9120]: "
                     "Invalid user nosuchuser1 from 192.0.2.10 port 51122\n")
        assert f2b._jail_files_fed((str(f),)) is True

    def test_openssh_9_8_session_process(self, tmp_path):
        f = tmp_path / "secure"
        f.write_text("Oct 11 20:51:02 fedora sshd-session[1201]: Invalid user x from 192.0.2.10 port 4\n")
        assert f2b._jail_files_fed((str(f),)) is True

    def test_a_file_nothing_sends_sshd_to(self, tmp_path):
        f = tmp_path / "bobtest-ssh.log"
        f.write_text("Oct 11 20:51:02 host CRON[77]: pam_unix(cron:session): session opened\n")
        assert f2b._jail_files_fed((str(f),)) is False

    def test_no_file_could_be_read(self, tmp_path):
        assert f2b._jail_files_fed((str(tmp_path / "missing.log"),)) is None

    def test_a_fifo_is_not_opened(self, tmp_path):
        import os
        fifo = tmp_path / "auth.log"
        os.mkfifo(fifo)
        assert f2b._jail_files_fed((str(fifo),)) is None

    def test_the_snapshot_reads_them(self):
        import inspect
        src = inspect.getsource(Fail2banSnapshot.from_system)
        assert "snap.ssh_jail_fed = _jail_files_fed(snap.ssh_jail_files, latest)" in src
        assert "entries = _sshd_entries() if snap.journal_available else []" in src
        assert "if snap.ssh_jail_fed is True and (latest is None or _syslog_started_after(entry)):" in src

    @pytest.mark.parametrize("lang, needle", [("en", "no sshd message was found"),
                                              ("fr", "aucun message de sshd")])
    def test_the_rendered_message(self, lang, needle):
        from bob import i18n
        i18n.init(lang)
        try:
            msg = next(f for f in check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=False), t=i18n.t).findings
                       if f.key == "fail2ban.ssh_jail_file_silent").message
        finally:
            i18n.init(lang="en")
        assert needle in msg and "/var/log/auth.log" in msg


@pytest.mark.parametrize("fed, key", [(False, "fail2ban.ssh_jail_file_silent"),
                                      (None, "fail2ban.ssh_jail_source_unverified")])
def test_an_unproven_jail_bounds_the_score(fed, key):
    """A jail BOB cannot prove fed may be blind — a −1 it cannot see. The
    score is then a ceiling, not a measurement."""
    result = check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=fed), t=_t)
    assert key in _keys(result)
    from bob.visibility import is_visibility_key
    assert is_visibility_key(key)


class TestAnOldMessageIsNotAFeed:
    """An sshd message proves the file was fed once. Routing changed after it,
    the old lines stay — so where the journal holds sshd's latest message, the
    file must hold that one. Measured on Mint 22.3 (rsyslog): see the replay
    in the 0.24.4 changelog."""

    _OLD = (b"2026-10-11T20:51:02.118437+02:00 so6minttest sshd[9120]: "
            b"Invalid user nosuchuser1 from 192.0.2.10 port 51122\n")
    _LATEST = b"[2536]: Server listening on :: port 22."

    def test_the_latest_journal_message_is_read(self, monkeypatch):
        # `journalctl -o json -n 1 … _COMM=sshd _COMM=sshd-session`, trimmed
        out = '{"MESSAGE":"Server listening on :: port 22.","_PID":"2536","SYSLOG_PID":"2536","SYSLOG_IDENTIFIER":"sshd"}\n'
        monkeypatch.setattr(f2b, "_run", lambda *a, **k: out)
        assert f2b._latest_sshd_message() == self._LATEST

    @pytest.mark.parametrize("out", ["", "not json\n", '{"MESSAGE":[83,101],"_PID":"1"}\n'])
    def test_no_usable_journal_answer(self, monkeypatch, out):
        monkeypatch.setattr(f2b, "_run", lambda *a, **k: out)
        assert f2b._latest_sshd_message() is None

    def test_an_old_message_without_the_latest_is_not_proof(self, tmp_path):
        f = tmp_path / "auth.log"
        f.write_bytes(self._OLD)
        assert f2b._jail_files_fed((str(f),)) is True              # fed once
        assert f2b._jail_files_fed((str(f),), self._LATEST) is False

    def test_the_latest_message_is_proof(self, tmp_path):
        f = tmp_path / "auth.log"
        f.write_bytes(self._OLD + b"2026-10-11T21:30:00+02:00 so6minttest sshd" + self._LATEST + b"\n")
        assert f2b._jail_files_fed((str(f),), self._LATEST) is True

    def test_the_verdict(self):
        result = check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=False, ssh_jail_stale=True), t=_t)
        assert "fail2ban.ssh_jail_file_stale" in _keys(result)
        assert "fail2ban.ssh_jail_active" not in _keys(result)
        assert not result.deductions
        from bob.visibility import is_visibility_key
        assert is_visibility_key("fail2ban.ssh_jail_file_stale")

    def test_the_snapshot_says_stale(self, monkeypatch, tmp_path):
        f = tmp_path / "auth.log"
        f.write_bytes(self._OLD)
        jail = f"Status for the jail: sshd\n|- Filter\n|  `- File list:\t{f}\n`- Actions\n"
        outputs = {("fail2ban-client", "ping"): "pong",
                   ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
                   ("fail2ban-client", "status", "sshd"): jail}
        journal = '{"MESSAGE":"Server listening on :: port 22.","_PID":"2536"}\n'
        monkeypatch.setattr(f2b, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "active")
        monkeypatch.setattr(f2b, "_run", lambda *a, **k: journal if a[0] == "journalctl" else outputs.get(a, ""))
        snap = Fail2banSnapshot.from_system()
        assert (snap.ssh_jail_fed, snap.ssh_jail_stale) == (False, True)

    @pytest.mark.parametrize("lang, needle", [("en", "not sshd's latest one"), ("fr", "pas son dernier")])
    def test_the_rendered_message(self, lang, needle):
        from bob import i18n
        i18n.init(lang)
        try:
            msg = next(f for f in check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=False, ssh_jail_stale=True),
                                                 t=i18n.t).findings if f.key == "fail2ban.ssh_jail_file_stale").message
        finally:
            i18n.init(lang="en")
        assert needle in msg and "/var/log/auth.log" in msg


_BOOT = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"


class TestRoutedByTheRoutingInForceNow:
    """The file holding sshd's latest message proves today's routing only when
    that message came after the running syslog daemon started: a daemon reads
    its routing when it starts. Measured on Mint: rsyslog re-routed and
    restarted after sshd's last message, nothing from sshd since — the file
    still held the journal's latest message and BOB said OK."""

    @pytest.fixture
    def host(self, monkeypatch):
        def build(rsyslog_since, boot=_BOOT, other_state="inactive"):
            monkeypatch.setattr(f2b, "_boot_id", lambda: boot)
            block = (f"Id=rsyslog.service\nActiveState=active\nActiveEnterTimestampMonotonic={rsyslog_since}\n"
                     if rsyslog_since is not None
                     else "Id=rsyslog.service\nActiveState=inactive\nActiveEnterTimestampMonotonic=0\n")
            other = f"Id=syslog-ng.service\nActiveState={other_state}\nActiveEnterTimestampMonotonic=1\n"
            monkeypatch.setattr(f2b, "_run", lambda *a, **k: block + "\n" + other)
        return build

    def _entry(self, at, boot=_BOOT):
        return {"__MONOTONIC_TIMESTAMP": str(at), "_BOOT_ID": boot, "_PID": "1", "MESSAGE": "x"}

    def test_logged_after_the_daemon_started(self, host):
        host(rsyslog_since=1_000_000)
        assert f2b._syslog_started_after(self._entry(5_000_000)) is False

    def test_the_daemon_restarted_since(self, host):
        host(rsyslog_since=9_000_000)
        assert f2b._syslog_started_after(self._entry(5_000_000)) is True

    def test_logged_in_an_earlier_boot(self, host):
        host(rsyslog_since=1_000_000)
        assert f2b._syslog_started_after(self._entry(5_000_000, boot="ff" * 16)) is True

    def test_no_running_daemon_to_date(self, host):
        host(rsyslog_since=None)
        assert f2b._syslog_started_after(self._entry(5_000_000)) is True

    def test_a_daemon_that_reroutes_on_reload_cannot_be_dated(self, host):
        """Measured in a Debian 13 container: syslog-ng 4.8.1 re-routed on
        ``syslog-ng-ctl reload``, no restart — its start time says nothing."""
        host(rsyslog_since=1_000_000, other_state="active")
        assert f2b._syslog_started_after(self._entry(5_000_000)) is True

    def test_no_timestamp(self, host):
        host(rsyslog_since=1_000_000)
        assert f2b._syslog_started_after({"_BOOT_ID": _BOOT}) is True

    def test_the_verdict_is_unverified(self, monkeypatch, tmp_path):
        f = tmp_path / "auth.log"
        f.write_bytes(b"Oct 11 22:05:20 so6minttest sshd[2536]: Server listening on :: port 22.\n")
        jail = f"Status for the jail: sshd\n|- Filter\n|  `- File list:\t{f}\n`- Actions\n"
        outputs = {("fail2ban-client", "ping"): "pong",
                   ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
                   ("fail2ban-client", "status", "sshd"): jail}
        entry = '{"MESSAGE":"Server listening on :: port 22.","_PID":"2536","__MONOTONIC_TIMESTAMP":"5000000","_BOOT_ID":"%s"}\n' % _BOOT
        monkeypatch.setattr(f2b, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "active")
        monkeypatch.setattr(f2b, "_boot_id", lambda: _BOOT)
        def run(*a, **k):
            if a[0] == "journalctl":
                return entry
            if a[:2] == ("systemctl", "show"):
                return "Id=rsyslog.service\nActiveState=active\nActiveEnterTimestampMonotonic=9000000\n"
            return outputs.get(a, "")
        monkeypatch.setattr(f2b, "_run", run)
        snap = Fail2banSnapshot.from_system()
        assert snap.ssh_jail_fed is None
        assert "fail2ban.ssh_jail_source_unverified" in _keys(check_fail2ban(snap, t=_t))


def test_without_a_journal_an_old_line_is_not_proof(monkeypatch, tmp_path):
    """OpenRC (no journal): an sshd line shows the file was fed once, nothing
    about the routing in force now — not verified, not OK."""
    f = tmp_path / "messages"
    f.write_bytes(b"Oct 11 12:00:00 alpine sshd[812]: Server listening on 0.0.0.0 port 22.\n")
    jail = f"Status for the jail: sshd\n|- Filter\n|  `- File list:\t{f}\n`- Actions\n"
    outputs = {("fail2ban-client", "ping"): "pong",
               ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
               ("fail2ban-client", "status", "sshd"): jail}
    monkeypatch.setattr(f2b, "_command_exists", lambda c: c not in ("systemctl", "journalctl"))
    monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "active")
    monkeypatch.setattr(f2b, "_run", lambda *a, **k: outputs.get(a, ""))
    snap = Fail2banSnapshot.from_system()
    assert snap.ssh_jail_fed is None
    assert "fail2ban.ssh_jail_active" not in _keys(check_fail2ban(snap, t=_t))


class TestTheFailuresAreWhatCounts:
    """Measured on Mint 22.3: rsyslog sent "invalid user" lines to another file
    and the rest of sshd's to auth.log. After a failed login and a good one,
    the jail on auth.log counted 0 failures; auth.log held sshd's latest
    message (a session closing) and BOB said OK."""

    _FAIL = {"MESSAGE": "Invalid user nosuchsplit1 from 192.0.2.10 port 40000", "_PID": "35990",
             "__MONOTONIC_TIMESTAMP": "8000000", "_BOOT_ID": _BOOT}
    _CLOSE = {"MESSAGE": "pam_unix(sshd:session): session closed for user root", "_PID": "35997",
              "__MONOTONIC_TIMESTAMP": "9000000", "_BOOT_ID": _BOOT}

    @pytest.mark.parametrize("message, failure", [
        ("Failed password for root from 192.0.2.10 port 4 ssh2", True),
        ("Invalid user nosuchsplit1 from 192.0.2.10 port 40000", True),
        ("Connection closed by invalid user x 192.0.2.10 port 5 [preauth]", True),
        ("Accepted publickey for root from 192.0.2.10 port 6 ssh2", False),
        ("pam_unix(sshd:session): session closed for user root", False),
    ])
    def test_what_is_a_failure(self, message, failure):
        assert (f2b._failure_kind(message) is not None) is failure

    def test_one_failure_of_each_kind(self):
        entries = [{"MESSAGE": "Invalid user a from 192.0.2.10 port 1"},
                   {"MESSAGE": "Connection closed by authenticating user root 192.0.2.10 port 2 [preauth]"},
                   {"MESSAGE": "Invalid user b from 192.0.2.10 port 3"}]
        kinds = f2b._latest_sshd_failures(entries)
        assert set(kinds) == {"invalid user", "user"}
        assert kinds["invalid user"]["MESSAGE"].startswith("Invalid user b")

    def _snap(self, monkeypatch, tmp_path, lines):
        import json as _json
        f = tmp_path / "auth.log"
        f.write_bytes(lines)
        jail = f"Status for the jail: sshd\n|- Filter\n|  `- File list:\t{f}\n`- Actions\n"
        outputs = {("fail2ban-client", "ping"): "pong",
                   ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
                   ("fail2ban-client", "status", "sshd"): jail}
        journal = "".join(_json.dumps(e) + "\n" for e in (self._FAIL, self._CLOSE))
        monkeypatch.setattr(f2b, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "active")
        monkeypatch.setattr(f2b, "_boot_id", lambda: _BOOT)

        def run(*a, **k):
            if a[0] == "journalctl":
                return journal
            if a[:2] == ("systemctl", "show"):
                return "Id=rsyslog.service\nActiveState=active\nActiveEnterTimestampMonotonic=1000000\n"
            return outputs.get(a, "")
        monkeypatch.setattr(f2b, "_run", run)
        return Fail2banSnapshot.from_system()

    def test_failures_routed_elsewhere(self, monkeypatch, tmp_path):
        snap = self._snap(monkeypatch, tmp_path,
                          b"Oct 11 23:20:01 so6minttest sshd[35997]: pam_unix(sshd:session): session closed for user root\n")
        assert (snap.ssh_jail_fed, snap.ssh_jail_misses_failures) == (False, True)
        result = check_fail2ban(snap, t=_t)
        assert "fail2ban.ssh_jail_misses_failures" in _keys(result)
        assert "fail2ban.ssh_jail_active" not in _keys(result)
        from bob.visibility import is_visibility_key
        assert is_visibility_key("fail2ban.ssh_jail_misses_failures")

    def test_failures_in_the_file(self, monkeypatch, tmp_path):
        snap = self._snap(monkeypatch, tmp_path,
                          b"Oct 11 23:20:00 so6minttest sshd[35990]: Invalid user nosuchsplit1 from 192.0.2.10 port 40000\n")
        assert snap.ssh_jail_fed is True
        assert "fail2ban.ssh_jail_active" in _keys(check_fail2ban(snap, t=_t))

    def test_one_kind_held_another_routed_away(self, monkeypatch, tmp_path):
        """Measured on Mint, "invalid user" still routed away: an invalid user,
        then root's key refused. auth.log held the latter — the latest failure
        — and BOB said OK; the jail could not count the former."""
        import json as _json
        auth = {"MESSAGE": "Connection closed by authenticating user root 192.0.2.10 port 47694 [preauth]",
                "_PID": "40797", "__MONOTONIC_TIMESTAMP": "8500000", "_BOOT_ID": _BOOT}
        journal = "".join(_json.dumps(e) + "\n" for e in (self._FAIL, auth))
        f = tmp_path / "auth.log"
        f.write_bytes(b"Oct 11 23:27:13 so6minttest sshd[40797]: Connection closed by authenticating user root "
                      b"192.0.2.10 port 47694 [preauth]\n")
        jail = f"Status for the jail: sshd\n|- Filter\n|  `- File list:\t{f}\n`- Actions\n"
        outputs = {("fail2ban-client", "ping"): "pong",
                   ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
                   ("fail2ban-client", "status", "sshd"): jail}
        monkeypatch.setattr(f2b, "_command_exists", lambda c: c != "systemctl")
        monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "active")
        monkeypatch.setattr(f2b, "_boot_id", lambda: _BOOT)

        def run(*a, **k):
            if a[0] == "journalctl":
                return journal
            if a[:2] == ("systemctl", "show"):
                return "Id=rsyslog.service\nActiveState=active\nActiveEnterTimestampMonotonic=1000000\n"
            return outputs.get(a, "")
        monkeypatch.setattr(f2b, "_run", run)
        snap = Fail2banSnapshot.from_system()
        assert (snap.ssh_jail_fed, snap.ssh_jail_misses_failures) == (False, True)

    @pytest.mark.parametrize("lang, needle", [("en", "latest failed login"), ("fr", "dernier échec")])
    def test_the_rendered_message(self, lang, needle):
        from bob import i18n
        i18n.init(lang)
        try:
            msg = next(f for f in check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=False,
                                                       ssh_jail_misses_failures=True), t=i18n.t).findings
                       if f.key == "fail2ban.ssh_jail_misses_failures").message
        finally:
            i18n.init(lang="en")
        assert needle in msg and "/var/log/auth.log" in msg


@pytest.mark.parametrize("lang, needle", [("en", "This is not a proof that every failure reaches the file"),
                                          ("fr", "Ce n'est pas une preuve que chaque échec atteint le fichier")])
def test_a_file_ok_says_what_it_rests_on(lang, needle):
    """An OK on a file proves the kinds of failure seen since rsyslog started,
    not the others: the finding says so where the operator reads it."""
    from bob import i18n
    i18n.init(lang)
    try:
        ok = next(f for f in check_fail2ban(_snap(syslog_active=True, ssh_jail_fed=True), t=i18n.t).findings
                  if f.key == "fail2ban.ssh_jail_active")
        journal_ok = next(f for f in check_fail2ban(_snap(ssh_jail_files=(), ssh_jail_journal=True), t=i18n.t).findings
                          if f.key == "fail2ban.ssh_jail_active")
    finally:
        i18n.init(lang="en")
    assert needle in ok.detail
    assert not journal_ok.detail
