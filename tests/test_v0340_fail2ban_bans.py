"""v0.34.0 — what fail2ban's jails did: bans now, and since it started.

BOB said "Fail2ban active — N jail(s) enabled" and nothing about what they
did. Each active jail's `fail2ban-client status <jail>` carries
"Currently banned:" and "Total banned:" (since fail2ban started); BOB shows
them per jail, never the banned addresses. A jail whose status could not be
read is left out. Measured on Ubuntu Server 26.04.1 (fail2ban, a ban of a
documentation address set by hand), netnsbench/b20340.
"""

from __future__ import annotations

from bob import i18n
from bob.checks import fail2ban as f2b

_STATUS = """Status for the jail: sshd
|- Filter
|  |- Currently failed:\t0
|  |- Total failed:\t12
|  `- Journal matches:\t_SYSTEMD_UNIT=ssh.service + _COMM=sshd
`- Actions
   |- Currently banned:\t1
   |- Total banned:\t3
   `- Banned IP list:\t192.0.2.10
"""


def test_the_counts():
    assert f2b._parse_bans(_STATUS) == (1, 3)
    assert f2b._parse_bans("Status for the jail: sshd\n") is None


def test_shown_per_jail_without_addresses():
    snap = f2b.Fail2banSnapshot(installed=True, service_active=True, active_jails=["recidive", "sshd"],
                                jail_bans={"sshd": (1, 3), "recidive": (0, 0)})
    i18n.init("en")
    f = next(x for x in f2b.check_fail2ban(snap, t=i18n.t).findings if x.key == "fail2ban.bans")
    assert f.message == "Bans: recidive 0 now, 0 in total; sshd 1 now, 3 in total (total since fail2ban started)"
    assert "192.0.2.10" not in f.message


def test_from_system_reads_each_jail(monkeypatch):
    def run(*a, **k):
        if a == ("fail2ban-client", "status"):
            return "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"
        if a == ("fail2ban-client", "status", "sshd"):
            return _STATUS
        if a == ("fail2ban-client", "ping"):
            return "Server replied: pong"
        return ""
    monkeypatch.setattr(f2b, "_run", run)
    monkeypatch.setattr(f2b, "_command_exists", lambda n: n == "fail2ban-client")
    monkeypatch.setattr(f2b, "unit_active_state", lambda *a, **k: None)
    snap = f2b.Fail2banSnapshot.from_system()
    assert snap.jail_bans == {"sshd": (1, 3)}
