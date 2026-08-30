"""
v0.15.0 — verdict-accuracy guards for the UFW rule analysis.

Same audit as the SSH one, same class of defect: the check's patterns were
written against the *tidy* form of a line and stopped matching as soon as the
operator added a comment. `ufw allow ... comment 'x'` appends `# x` to every
line of `ufw status numbered`, and commenting firewall rules is good
practice — so the more disciplined the operator, the likelier the miss.
"""

from __future__ import annotations

import pytest

from bob.checks.firewall import (
    _check_ipv6_coverage,
    _check_open_any,
    _strip_comment,
)
from bob.scoring import CheckResult


def _keys(fn, lines, *extra) -> set[str]:
    """Both sub-checks take (lines, t, result); _check_ipv6_coverage adds
    ipv6_enabled after result."""
    result = CheckResult()
    fn(lines, lambda k, **kw: k, result, *extra)
    return {f.key for f in result.findings if f.key}


class TestOpenAnySurvivesComments:
    """`Anywhere ALLOW IN Anywhere` allows every port from every source — the
    most dangerous rule UFW can hold. It carries an ALERT and a 2-point
    deduction, and before v0.15.0 a comment removed both."""

    @pytest.mark.parametrize("line", [
        "[ 1] Anywhere                   ALLOW IN    Anywhere",
        "[ 1] Anywhere                   ALLOW IN    Anywhere    # temporary",
        "[ 2] Anywhere/tcp               ALLOW IN    Anywhere/tcp",
        "[ 2] Anywhere/tcp               ALLOW IN    Anywhere/tcp  # debug",
        "[ 3] Anywhere (v6)              ALLOW IN    Anywhere (v6)",
        "[ 3] Anywhere (v6)              ALLOW IN    Anywhere (v6) # ipv6 test",
        "[ 4] Anywhere                   ALLOW IN    Anywhere      ",
    ])
    def test_every_wildcard_form_is_alerted(self, line):
        assert "firewall_rules.open_any_found" in _keys(_check_open_any, [line])

    @pytest.mark.parametrize("line", [
        "[ 1] 22/tcp                     ALLOW IN    Anywhere",
        "[ 2] 22/tcp                     ALLOW IN    Anywhere    # ssh",
        "[ 3] Anywhere                   ALLOW IN    192.168.1.0/24",
        "[ 4] 80                         ALLOW IN    Anywhere    # Anywhere ALLOW IN Anywhere",
    ])
    def test_a_port_restricted_rule_is_not_flagged(self, line):
        """Including the last one: a *comment* quoting the dangerous pattern
        must not itself trigger the alert."""
        assert "firewall_rules.open_any_found" not in _keys(_check_open_any, [line])


class TestIpv6CoverageIgnoresComments:
    def test_v6_inside_a_comment_is_not_an_ipv6_rule(self):
        """Counting `"(v6)" in line` let a comment suppress the warning: the
        host had no IPv6 rules at all and was told it did."""
        lines = ["[ 1] 80/tcp ALLOW IN Anywhere # todo add (v6) rules"]
        assert "firewall_rules.ipv6_missing" in _keys(_check_ipv6_coverage, lines, True)

    def test_a_real_ipv6_rule_still_counts(self):
        lines = [
            "[ 1] 80/tcp        ALLOW IN Anywhere",
            "[ 2] 80/tcp (v6)   ALLOW IN Anywhere (v6)",
        ]
        assert "firewall_rules.ipv6_missing" not in _keys(_check_ipv6_coverage, lines, True)


class TestStripComment:
    @pytest.mark.parametrize("raw,expected", [
        ("80/tcp ALLOW IN Anywhere # note", "80/tcp ALLOW IN Anywhere"),
        ("80/tcp ALLOW IN Anywhere",        "80/tcp ALLOW IN Anywhere"),
        ("# only a comment",                ""),
        ("a  #  b  # c",                    "a"),
    ])
    def test_cuts_at_the_first_hash(self, raw, expected):
        assert _strip_comment(raw) == expected
