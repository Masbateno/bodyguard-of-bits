"""v0.42.0 — the delete command of an orphan ufw rule removes that rule (B-035).

Found on the developer's workstation audit under 0.40.0 (21 November 2026):
for ``57621 ALLOW IN 192.168.1.0/24`` BOB proposed ``sudo ufw delete allow
57621``. Measured on the test Mint (ufw 0.36.2): ufw answered "Could not
delete non-existent rule", exited 0, and the rule stayed — ufw deletes only
the rule whose every field matches, and that one has a source.

The command is now rebuilt from the whole ``ufw status numbered`` line. Every
row of ``CASES`` is a line the real ufw printed, and its command was run
against the real ufw, which deleted exactly that rule (and its ``(v6)`` copy):
27 forms, 27 exact deletions, in a throw-away user and network namespace
(``ufw --rootdir``), the host's firewall untouched.
"""

from __future__ import annotations

import pytest

from bob.checks import _ufw
from bob.checks._run import _identity_t
from bob.checks.firewall import _check_orphan_rules
from bob.scoring import CheckResult

APPS = {"OpenSSH": ["22/tcp"], "CUPS": ["631"], "Samba": ["137,138/udp", "139,445/tcp"]}

#: (line printed by ufw 0.36.2, command that deleted exactly it)
CASES = [
    ("57621                      ALLOW IN    Anywhere", "sudo ufw delete allow 57621"),
    ("41681/tcp                  ALLOW IN    Anywhere", "sudo ufw delete allow 41681/tcp"),
    ("57622                      ALLOW IN    192.168.1.0/24             # Spotify Connect",
     "sudo ufw delete allow from 192.168.1.0/24 to any port 57622"),
    ("41682/tcp                  ALLOW IN    192.168.1.0/24             # Spotify Connect",
     "sudo ufw delete allow from 192.168.1.0/24 to any port 41682 proto tcp"),
    ("4455/tcp                   ALLOW IN    192.168.1.11",
     "sudo ufw delete allow from 192.168.1.11 to any port 4455 proto tcp"),
    ("6000:6007/tcp              ALLOW IN    Anywhere", "sudo ufw delete allow 6000:6007/tcp"),
    ("8080,8443/tcp              ALLOW IN    Anywhere", "sudo ufw delete allow 8080,8443/tcp"),
    ("9001/tcp on eth9           ALLOW IN    Anywhere",
     "sudo ufw delete allow in on eth9 from any to any port 9001 proto tcp"),
    ("9002 on eth9               ALLOW IN    10.0.0.0/8",
     "sudo ufw delete allow in on eth9 from 10.0.0.0/8 to any port 9002"),
    ("192.168.1.5 9003/tcp       ALLOW IN    Anywhere",
     "sudo ufw delete allow from any to 192.168.1.5 port 9003 proto tcp"),
    ("OpenSSH                    ALLOW IN    Anywhere", "sudo ufw delete allow OpenSSH"),
    ("CUPS                       ALLOW IN    192.168.1.0/24",
     "sudo ufw delete allow from 192.168.1.0/24 to any app CUPS"),
    ("9004/tcp                   ALLOW IN    Anywhere                   (log)",
     "sudo ufw delete allow log 9004/tcp"),
    ("9005                       ALLOW IN    Anywhere                   (log-all)",
     "sudo ufw delete allow log-all 9005"),
    ("9006/tcp                   LIMIT IN    Anywhere", "sudo ufw delete limit 9006/tcp"),
    ("9008/udp                   ALLOW IN    192.168.1.0/24 1234/udp",
     "sudo ufw delete allow from 192.168.1.0/24 port 1234 to any port 9008 proto udp"),
    ("9009/udp                   ALLOW IN    192.168.1.0/24",
     "sudo ufw delete allow from 192.168.1.0/24 to any port 9009 proto udp"),
    ("9010/udp                   ALLOW IN    Anywhere", "sudo ufw delete allow 9010/udp"),
    ("192.168.1.10 9011          ALLOW IN    192.168.1.0/24",
     "sudo ufw delete allow from 192.168.1.0/24 to 192.168.1.10 port 9011"),
    ("192.168.1.10 9012/tcp on eth9 ALLOW IN    192.168.1.0/24             # tout",
     "sudo ufw delete allow in on eth9 from 192.168.1.0/24 to 192.168.1.10 port 9012 proto tcp"),
    ("9015,9016:9018/tcp         ALLOW IN    Anywhere", "sudo ufw delete allow 9015,9016:9018/tcp"),
    ("9019/tcp on eth9           ALLOW IN    192.168.1.0/24             (log)",
     "sudo ufw delete allow in on eth9 log from 192.168.1.0/24 to any port 9019 proto tcp"),
    ("9020/udp                   ALLOW IN    53/udp",
     "sudo ufw delete allow from any port 53 to any port 9020 proto udp"),
    ("Samba                      ALLOW IN    Anywhere", "sudo ufw delete allow Samba"),
    ("192.168.1.10 OpenSSH       ALLOW IN    192.168.1.0/24",
     "sudo ufw delete allow from 192.168.1.0/24 to 192.168.1.10 app OpenSSH"),
    ("9021                       DENY IN     192.168.1.66",
     "sudo ufw delete deny from 192.168.1.66 to any port 9021"),
    ("9007                       ALLOW IN    2001:db8::/32",
     "sudo ufw delete allow from 2001:db8::/32 to any port 9007"),
]


@pytest.mark.parametrize("line, cmd", CASES, ids=[c[0].split()[0] + "-" + str(i) for i, c in enumerate(CASES)])
def test_the_command_ufw_ran_is_rebuilt(line, cmd):
    assert _ufw.delete_command(_ufw.parse_rule(f"[ 1] {line}"), APPS) == cmd


@pytest.mark.parametrize("line", [
    "9022/tcp                   ALLOW OUT   Anywhere",          # outgoing: another grammar
    "9023/tcp                   ALLOW FWD   Anywhere",          # routed
    "Anywhere                   ALLOW IN    192.168.1.0/24",    # no port
    "9024/tcp                   ALLOW IN    192.168.1.0/24 CUPS",  # profile on the source side
    "Mystery                    ALLOW IN    Anywhere",          # unknown profile
])
def test_a_line_not_read_gets_no_command(line):
    assert _ufw.delete_command(_ufw.parse_rule(f"[ 1] {line}"), APPS) is None


def _orphans(lines, listening, apps=None):
    r = CheckResult()
    _check_orphan_rules(lines, set(listening), _identity_t, r, apps)
    return [f for f in r.findings if f.key == "firewall_rules.orphan_rule"]


class TestTheMeasuredWorkstation:
    """The two rules of the audit, as ``ufw status numbered`` printed them."""

    LINES = ["[ 1] 41681/tcp                  ALLOW IN    192.168.1.0/24             # Spotify Connect",
             "[ 2] 57621                      ALLOW IN    192.168.1.0/24             # Spotify Connect"]

    def test_each_command_names_the_source(self):
        cmds = {f.cmd for f in _orphans(self.LINES, [])}
        assert cmds == {"sudo ufw delete allow from 192.168.1.0/24 to any port 41681 proto tcp",
                        "sudo ufw delete allow from 192.168.1.0/24 to any port 57621"}

    def test_the_message_and_detail_are_unchanged(self):
        f = _orphans(self.LINES, [])[1]
        assert f.message == "firewall_rules.orphan_rule port=57621/tcp+udp"
        assert f.detail == "firewall_rules.orphan_rule_detail"


def test_a_rule_still_used_on_another_port_gets_no_command():
    """``80,443/tcp`` with 80 listening: deleting the rule would close 80 too."""
    found = _orphans(["[ 1] 80,443/tcp   ALLOW IN   Anywhere"], ["80/tcp"])
    assert [f.message for f in found] == ["firewall_rules.orphan_rule port=443/tcp"]
    assert found[0].cmd == ""
    assert "firewall_rules.orphan_rule_partly_used" in found[0].detail


def test_a_rule_not_rewritten_says_to_delete_it_by_number():
    found = _orphans(["[ 1] 9024/tcp   ALLOW IN   192.168.1.0/24 CUPS"], [], APPS)
    assert found[0].cmd == ""
    assert "firewall_rules.orphan_rule_by_number" in found[0].detail


def test_two_rules_on_one_port_get_both_commands():
    found = _orphans(["[ 1] 9030/tcp   ALLOW IN   192.168.1.0/24",
                      "[ 2] 9030/tcp   ALLOW IN   10.0.0.0/8"], [])
    assert found[0].cmd == ("sudo ufw delete allow from 192.168.1.0/24 to any port 9030 proto tcp"
                            " && sudo ufw delete allow from 10.0.0.0/8 to any port 9030 proto tcp")


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_two_new_texts_exist_and_name_the_rule(lang):
    from bob import i18n
    before = i18n.current_lang()
    i18n.init(lang)
    try:
        for key in ("firewall_rules.orphan_rule_partly_used", "firewall_rules.orphan_rule_by_number"):
            text = i18n.t(key, rule="9024/tcp ALLOW IN 192.168.1.0/24 CUPS")
            assert "9024/tcp ALLOW IN 192.168.1.0/24 CUPS" in text and key not in text
        assert "(v6)" in i18n.t("firewall_rules.orphan_rule_by_number", rule="x")
    finally:
        i18n.init(before)
