"""v0.26.0 — a file-backed fail2ban jail on a host with no systemd journal.

Measured on Alpine 3.24 (OpenRC, no journal, fail2ban 1.1 from apk, whose
``jail.d/alpine-ssh.conf`` reads /var/log/messages):

* busybox syslogd writes sshd to /var/log/messages. Two refused logins:
  ``Total failed: 2``. 0.25.1 said "whether a syslog daemon writes it could
  not be established" — one was running, and BOB knew it. The jail's own count
  was never read.
* syslog-ng with Alpine's own syslog-ng.conf sends auth to /var/log/auth.log.
  A refused login: ``Total failed: 0`` — the packaged jail is blind. 0.25.1
  and the working tree before this said "not verified". The live SSH
  session's ``Accepted`` line was in auth.log and not in messages; the
  printed ``logpath`` override, run as written, made the jail count 1.
* syslog-ng 4 names itself ``syslog-ng-main`` in ``/proc/<pid>/comm``.
"""

from bob.checks import fail2ban as f2b
from bob.checks.fail2ban import Fail2banSnapshot, _newest_session_since_syslog, check_fail2ban
from tests.helpers import _keys, _t

# As `fail2ban-client status sshd` printed it on the Alpine host.
STATUS = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t1\n"
          "|  |- Total failed:\t2\n|  `- File list:\t/var/log/messages\n`- Actions\n"
          "   |- Currently banned:\t0\n   |- Total banned:\t0\n   `- Banned IP list:\t\n")
# As syslog-ng and busybox syslogd wrote the session's line there.
ACCEPTED = (b"2026-10-18 18:56:24 info sshd-session[8919]: Accepted publickey for root "
            b"from 192.168.1.10 port 57566 ssh2\n")
OLD = (b"Oct 18 20:55:05 so6alpinetest auth.info sshd-session[7972]: Connection closed "
       b"by invalid user bobnosuchuser 192.168.1.10 port 55756 [preauth]\n")


def _snap(**kw):
    base = dict(installed=True, service_active=True, active_jails=["sshd"], ssh_jail="sshd",
                ssh_jail_files=("/var/log/messages",), ssh_jail_journal=False,
                syslog_active=True, journal_available=False, ssh_jail_fed=None)
    base.update(kw)
    return Fail2banSnapshot(**base)


def test_the_jails_count_is_read():
    assert f2b._parse_total_failed(STATUS) == 2
    assert f2b._parse_total_failed("") == 0


class TestTheJailsCount:
    def test_failures_counted_credit_the_jail(self):
        res = check_fail2ban(_snap(ssh_jail_counted=2), t=_t)
        ok = next(f for f in res.findings if f.key == "fail2ban.ssh_jail_active")
        assert ok.detail == _t("fail2ban.ssh_jail_active_counted_detail", jail="sshd", count=2)
        assert "fail2ban.ssh_jail_source_unverified" not in _keys(res)

    def test_none_counted_stays_unverified_and_says_why(self):
        res = check_fail2ban(_snap(), t=_t)
        info = next(f for f in res.findings if f.key == "fail2ban.ssh_jail_source_unverified")
        assert info.message == _t("fail2ban.ssh_jail_source_unverified_no_journal",
                                  jail="sshd", files="/var/log/messages")
        assert "fail2ban.ssh_jail_active" not in _keys(res)

    def test_a_daemon_unknown_keeps_the_old_wording(self):
        res = check_fail2ban(_snap(syslog_active=None), t=_t)
        info = next(f for f in res.findings if f.key == "fail2ban.ssh_jail_source_unverified")
        assert info.message == _t("fail2ban.ssh_jail_source_unverified", jail="sshd",
                                  files="/var/log/messages")


class TestRoutedElsewhere:
    def test_said_with_the_file_sshd_goes_to_and_a_fix(self):
        res = check_fail2ban(_snap(ssh_jail_fed=False, ssh_jail_routed_to="/var/log/auth.log"), t=_t)
        info = next(f for f in res.findings if f.key == "fail2ban.ssh_jail_routed_elsewhere")
        assert info.template_vars["dest"] == "/var/log/auth.log"
        assert "logpath = %s" in info.cmd and "/var/log/auth.log" in info.cmd
        assert "zz-bob-sshd-logpath.local" in info.cmd and "fail2ban" in info.cmd.split("&&")[-1]

    def test_it_outweighs_an_old_count(self):
        res = check_fail2ban(_snap(ssh_jail_fed=False, ssh_jail_routed_to="/var/log/auth.log",
                                   ssh_jail_counted=3), t=_t)
        assert "fail2ban.ssh_jail_active" not in _keys(res)


class TestWhereTheSessionsLineIs:
    def _logs(self, tmp_path, monkeypatch, jail_bytes, other_bytes):
        jail, other = tmp_path / "messages", tmp_path / "auth.log"
        jail.write_bytes(jail_bytes)
        other.write_bytes(other_bytes)
        monkeypatch.setattr(f2b, "_AUTH_LOGS", (str(other), str(jail)))
        monkeypatch.setattr(f2b, "_newest_session_since_syslog", lambda: 8919)
        return (str(jail),), str(other)

    def test_in_another_file_only(self, tmp_path, monkeypatch):
        files, other = self._logs(tmp_path, monkeypatch, OLD, ACCEPTED)
        assert f2b._session_routed_elsewhere(files) == other

    def test_in_the_jails_file(self, tmp_path, monkeypatch):
        files, _ = self._logs(tmp_path, monkeypatch, OLD + ACCEPTED, ACCEPTED)
        assert f2b._session_routed_elsewhere(files) == ""

    def test_found_nowhere_is_not_blind(self, tmp_path, monkeypatch):
        files, _ = self._logs(tmp_path, monkeypatch, OLD, OLD)
        assert f2b._session_routed_elsewhere(files) == ""

    def test_no_session_to_go_on(self, tmp_path, monkeypatch):
        files, _ = self._logs(tmp_path, monkeypatch, OLD, ACCEPTED)
        monkeypatch.setattr(f2b, "_newest_session_since_syslog", lambda: None)
        assert f2b._session_routed_elsewhere(files) == ""


def _proc(root, pid, comm, start, argv0=b""):
    d = root / str(pid)
    d.mkdir()
    (d / "comm").write_text(comm + "\n")
    (d / "stat").write_text(f"{pid} ({comm}) S " + " ".join(["0"] * 18) + f" {start} 0 0\n")
    (d / "cmdline").write_bytes(argv0 + b"\0")


class TestTheNewestSession:
    def test_the_newest_priv_session_after_the_daemon(self, tmp_path):
        _proc(tmp_path, 8093, "syslog-ng-main", 95717)
        _proc(tmp_path, 2665, "sshd-session", 7062, b"sshd-session: so6 [priv]")
        _proc(tmp_path, 8919, "sshd-session", 101844, b"sshd-session: root [priv]")
        _proc(tmp_path, 8922, "sshd-session", 101867, b"sshd-session: root@notty")
        assert _newest_session_since_syslog(str(tmp_path)) == 8919

    def test_only_sessions_older_than_the_daemon(self, tmp_path):
        _proc(tmp_path, 10588, "syslogd", 120000)
        _proc(tmp_path, 2665, "sshd-session", 7062, b"sshd-session: so6 [priv]")
        assert _newest_session_since_syslog(str(tmp_path)) is None

    def test_no_daemon_process_found(self, tmp_path):
        _proc(tmp_path, 8919, "sshd-session", 101844, b"sshd-session: root [priv]")
        assert _newest_session_since_syslog(str(tmp_path)) is None


def test_the_collection_reads_count_and_routing(monkeypatch):
    outputs = {("fail2ban-client", "ping"): "pong",
               ("fail2ban-client", "status"): "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
               ("fail2ban-client", "status", "sshd"): STATUS}
    monkeypatch.setattr(f2b, "_command_exists", lambda c: c not in ("systemctl", "journalctl"))
    monkeypatch.setattr(f2b, "unit_active_state", lambda name: None if name == "fail2ban" else "active")
    monkeypatch.setattr(f2b, "_run", lambda *a, **k: outputs.get(a, ""))
    monkeypatch.setattr(f2b, "_session_routed_elsewhere", lambda files: "/var/log/auth.log")
    snap = Fail2banSnapshot.from_system()
    assert snap.ssh_jail_counted == 2
    assert (snap.ssh_jail_fed, snap.ssh_jail_routed_to) == (False, "/var/log/auth.log")


class TestTheCaveats:
    """v0.26.0 — an OK on partial evidence shows what it rests on. The reason
    was in the OK's detail, which the terminal never prints for an OK: the
    operator read "SSH brute-force protection active" and nothing else."""

    def _after_the_ok(self, res, caveat):
        keys = _keys(res)
        i = keys.index("fail2ban.ssh_jail_active")
        assert keys[i + 1] == caveat
        ok = res.findings[i]
        assert ok.qualified_by == (caveat,)
        return res.findings[i + 1]

    def test_the_count(self):
        res = check_fail2ban(_snap(ssh_jail_counted=2), t=_t)
        info = self._after_the_ok(res, "fail2ban.ssh_jail_counted_caveat")
        assert info.template_vars == {"count": 2} and not res.deductions

    def test_the_sample(self):
        res = check_fail2ban(_snap(journal_available=True, ssh_jail_fed=True), t=_t)
        info = self._after_the_ok(res, "fail2ban.ssh_jail_sampled_caveat")
        assert info.template_vars == {"files": "/var/log/messages"}

    def test_a_journal_jail_needs_none(self):
        res = check_fail2ban(_snap(ssh_jail_files=(), ssh_jail_journal=True), t=_t)
        assert "fail2ban.ssh_jail_active" in _keys(res)
        assert not [k for k in _keys(res) if k.endswith("_caveat")]

    def test_not_visibility_the_jail_is_seen(self):
        from bob.visibility import is_visibility_key
        assert not is_visibility_key("fail2ban.ssh_jail_counted_caveat")
        assert not is_visibility_key("fail2ban.ssh_jail_sampled_caveat")

    def test_the_terminal_shows_it(self, capsys):
        from unittest.mock import MagicMock

        from bob import i18n
        from bob.display import display_result
        from bob.output import init as output_init
        output_init(no_color=True)
        res = check_fail2ban(_snap(ssh_jail_counted=2), t=i18n.t)
        display_result(res, MagicMock(), verbose=False)
        out = capsys.readouterr().out
        # Wrapped to the terminal width: compared with whitespace collapsed.
        assert " ".join(i18n.t("fail2ban.ssh_jail_counted_caveat", count=2).split()) \
            in " ".join(out.split())
