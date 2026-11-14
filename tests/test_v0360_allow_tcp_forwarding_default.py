"""v0.36.0 — AllowTcpForwarding absent from sshd_config is an INFO; written yes, a WARN.

Decided with the user on 14 November 2026 (backlog item C1, option 2). Until
0.36.0 the directive's absence cost a point on every stock OpenSSH host: its
default is yes. Measured on Linux Mint 22.3 (OpenSSH 9.6p1): only
`#AllowTcpForwarding yes` (commented) in sshd_config, `sshd -T` prints
`allowtcpforwarding yes`. The default in force is said, with the line to write;
only a value written in the file costs the point.
"""

from __future__ import annotations

from bob.checks.ssh import check_ssh
from bob.scoring import FindingLevel
from tests.test_ssh import base_snapshot


def _result(cfg):
    return check_ssh(base_snapshot(sshd_config=dict(cfg)))


def _levels(result):
    return {(f.key, f.level) for f in result.findings if "tcp_forwarding" in f.key}


def test_absent_is_an_info_without_a_point_and_with_the_line_to_write():
    r = _result({})
    assert _levels(r) == {("ssh.allow_tcp_forwarding_default", FindingLevel.INFO)}
    assert not any(d.key.startswith("ssh.allow_tcp_forwarding") for d in r.deductions)
    f = next(f for f in r.findings if f.key == "ssh.allow_tcp_forwarding_default")
    assert "AllowTcpForwarding no" in f.cmd


def test_written_yes_costs_the_point():
    r = _result({"allowtcpforwarding": "yes"})
    assert _levels(r) == {("ssh.allow_tcp_forwarding", FindingLevel.WARN)}
    assert sum(d.points for d in r.deductions if d.key == "ssh.allow_tcp_forwarding") == 1


def test_written_no_or_local_says_nothing():
    for v in ("no", "local"):
        assert _levels(_result({"allowtcpforwarding": v})) == set(), v


def test_disable_forwarding_silences_the_default_too():
    assert _levels(_result({"disableforwarding": "yes"})) == set()


def test_the_default_is_not_an_issue_for_the_section():
    from bob.checks.ssh import _directives as d
    rule = next(r for r in d._BAD_DIRECTIVES if r.name == "allowtcpforwarding")
    from bob.scoring import CheckResult
    assert d._apply_bad_directive(rule, {}, CheckResult(), lambda k, **v: k) is False
