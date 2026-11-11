"""v0.32.0 — the orphan-rule `ufw delete` never enters --fix.

The backlog carried "`ufw delete` offered too eagerly" from a real Mint audit.
Measured against the code: since 0.26.1 the detail says to delete the rule
only if nothing uses it (a program may listen only while it runs), and the
finding is INFO with no nature — `--fix` takes action findings only. This
test freezes that: the command stays shown, copy-ready, but no fix path
collects it.
"""

from __future__ import annotations

from bob.checks.firewall import _check_orphan_rules
from bob.checks._run import _identity_t
from bob.scoring import CheckResult


def _orphan_finding():
    result = CheckResult()
    _check_orphan_rules(["[ 1] 41681/tcp                 ALLOW IN    192.168.1.0/24"],
                        set(), _identity_t, result)
    return next(f for f in result.findings if f.key == "firewall_rules.orphan_rule")


def test_it_is_info_without_a_nature_so_fix_skips_it():
    f = _orphan_finding()
    assert f.level.value == "info" and f.nature == ""
    assert f.cmd.startswith("sudo ufw delete allow")


def test_the_detail_says_delete_only_if_unused():
    assert _orphan_finding().detail == "firewall_rules.orphan_rule_detail"
