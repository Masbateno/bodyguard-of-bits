"""v0.27.0 — firewalld rich rules that name one family.

Measured on a real Debian 13 host (firewalld 2.3.1, 24 October 2026), probing
through a veth namespace the default zone takes: zone public at target default
let 22 in over both families and refused 80 over both — firewalld filters IPv6
as IPv4 (BOB: "same zone rules as IPv4", right); at target ACCEPT 80 opened over
both (BOB: ALERT, and IPv6 "not filtered", right). With `rule family="ipv6"
port port="80" protocol="tcp" accept`, 80 opened over IPv6 only — and BOB said
"allows: … 80/tcp (rich)" and "same zone rules as IPv4", which it was not.
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import _firewalld as fw
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6

RULE6 = 'rule family="ipv6" port port="80" protocol="tcp" accept'


@pytest.mark.parametrize("rule, grant", [
    (RULE6, "80/tcp (rich, IPv6)"),
    ('rule family="ipv4" service name="https" accept', "https (rich, IPv4)"),
    ('rule port port="5432" protocol="tcp" accept', "5432/tcp (rich)"),
    ('rule family="ipv6" source address="fd00::/8" accept', "rich rule (IPv6)"),
    ('rule family="ipv6" port port="80" protocol="tcp" reject', None),
])
def test_the_grant_names_the_family(rule, grant):
    assert fw._rich_rule_grant(rule) == grant


def test_the_family_scoped_accepts_of_the_judged_zones():
    status = fw.FirewalldStatus(active=True, default_zone="public", target="default",
                                rich_rules=[RULE6, 'rule port port="5432" protocol="tcp" accept'])
    assert status.family_scoped_accepts() == ["80/tcp (rich, IPv6)"]


@pytest.mark.parametrize("lang, words", [("en", "rich rules open some ports to one family only: 80/tcp (rich, IPv6)"),
                                         ("fr", "des règles riches ouvrent certains ports à une seule famille : 80/tcp (rich, IPv6)")])
def test_the_ipv6_ok_does_not_say_same_rules(lang, words):
    i18n.init(lang)
    try:
        res = check_ipv6(IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False, ipv6_listeners=["80/tcp"]),
                         ufw_active=False, firewalld_active=True, firewalld_policy="deny",
                         firewalld_family_rules=("80/tcp (rich, IPv6)",), t=i18n.t)
    finally:
        i18n.init(lang="en")
    msg = next(f.message for f in res.findings if f.key == "ipv6.firewalld_v6")
    assert words in msg and "same zone rules as IPv4" not in msg


def test_without_such_rules_the_ok_stands():
    res = check_ipv6(IPv6Snapshot(kernel_ipv6_enabled=True, ufw_present=False), ufw_active=False,
                     firewalld_active=True, firewalld_policy="deny", t=lambda k, **kw: k)
    assert [f.message for f in res.findings if f.key == "ipv6.firewalld_v6"] == ["ipv6.firewalld_v6"]


def test_the_runner_hands_them():
    from bob import runner
    assert "firewalld_family_rules=tuple(fwd_status.family_scoped_accepts())" in inspect.getsource(runner)
