"""
v0.15.0 — a refused query was reported as "nothing configured", with a
deduction.

`auditd` and `fail2ban` both ask a tool for their configuration and both read
an empty answer as an empty configuration. `_run` discards the exit code, so a
failed call and a genuinely empty result are the same string.

Measured on this host, with both services running:

    $ auditctl -l           -> exit 4,   stdout empty
    $ fail2ban-client status -> exit 255, stdout empty

Each produced a WARN and a 1-point deduction for a configuration BOB had never
read. The direction is the cautious one, which is why it survived, but it is
still a false statement with a score attached — the kind an operator disproves
in one command, which is how the other findings lose their credit.

Each tool provides its own discriminator, so no exit-code plumbing was needed:

* `auditctl` prints the literal "No rules" when the audit system is reachable
  and holds none — the string is in the binary. Empty output therefore means
  the query failed.
* `fail2ban-client status` always emits a "Jail list:" line, empty or not
  (`fail2ban/client/beautifier.py`).
"""

from __future__ import annotations

import pytest

from bob.checks.auditd import AuditdSnapshot, check_auditd
from bob.checks.fail2ban import Fail2banSnapshot, check_fail2ban


def _summary(result):
    return ({f.key for f in result.findings},
            sum(d.points for d in result.deductions))


class TestAuditd:
    def test_a_failed_query_is_not_an_empty_rule_set(self):
        keys, points = _summary(check_auditd(AuditdSnapshot(
            installed=True, service_active=True, rules_readable=False)))
        assert "auditd.rules_unreadable" in keys
        assert "auditd.no_rules" not in keys
        assert points == 0, "deducted for a rule set it never read"

    def test_it_does_not_deduct_twice_for_the_same_empty_output(self):
        """The sensitive-file coverage is derived from the same output, so it
        has to stop too — it used to add a second point."""
        keys, points = _summary(check_auditd(AuditdSnapshot(
            installed=True, service_active=True, rules_readable=False)))
        assert "auditd.missing_sensitive_rules" not in keys
        assert points == 0

    def test_a_readable_but_empty_rule_set_is_still_reported(self):
        keys, points = _summary(check_auditd(AuditdSnapshot(
            installed=True, service_active=True, rules_readable=True)))
        assert "auditd.no_rules" in keys
        assert points >= 1

    def test_a_configured_host_is_unaffected(self):
        keys, points = _summary(check_auditd(AuditdSnapshot(
            installed=True, service_active=True, rules_readable=True,
            rule_count=12,
            watched_files={"/etc/passwd", "/etc/shadow", "/etc/sudoers",
                           "/etc/group", "/etc/gshadow"})))
        assert "auditd.active" in keys
        assert points == 0

    @pytest.mark.parametrize("output,expected", [
        ("", False),
        ("   \n", False),
        ("No rules\n", True),
        ("-w /etc/passwd -p wa -k identity\n", True),
    ])
    def test_the_readability_signal(self, output, expected, monkeypatch):
        import bob.checks.auditd as m
        monkeypatch.setattr(m, "_command_exists", lambda n: True)
        monkeypatch.setattr(m, "is_unit_active", lambda n: True)
        monkeypatch.setattr(m, "_run", lambda *a, **k: output)
        assert AuditdSnapshot.from_system().rules_readable is expected


class TestFail2ban:
    def test_a_failed_query_is_not_an_absence_of_jails(self):
        keys, points = _summary(check_fail2ban(Fail2banSnapshot(
            installed=True, service_active=True, status_readable=False)))
        assert "fail2ban.status_unreadable" in keys
        assert "fail2ban.no_jails" not in keys
        assert points == 0

    def test_a_readable_empty_jail_list_is_still_reported(self):
        keys, points = _summary(check_fail2ban(Fail2banSnapshot(
            installed=True, service_active=True, status_readable=True)))
        assert "fail2ban.no_jails" in keys
        assert points >= 1

    def test_a_configured_host_is_unaffected(self):
        keys, points = _summary(check_fail2ban(Fail2banSnapshot(
            installed=True, service_active=True, status_readable=True,
            active_jails=["sshd"], ssh_jail="sshd")))
        assert "fail2ban.no_jails" not in keys
        assert points == 0

    @pytest.mark.parametrize("output,expected", [
        ("", False),
        ("Server replied: ERROR\n", False),
        ("Status\n|- Number of jail:\t0\n`- Jail list:\n", True),
        ("Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n", True),
    ])
    def test_the_readability_signal(self, output, expected, monkeypatch):
        import bob.checks.fail2ban as m
        monkeypatch.setattr(m, "_command_exists", lambda n: True)
        monkeypatch.setattr(m, "is_unit_active", lambda n: True)
        monkeypatch.setattr(m, "_run", lambda *a, **k: output)
        assert Fail2banSnapshot.from_system().status_readable is expected
