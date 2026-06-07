"""
Unit tests for check_rules() — open-any detection, duplicate detection,
IPv6 consistency.

Focus: trailing-space regression (ufw status numbered pads lines with spaces,
which caused the open-any pattern to silently miss the wildcard rule).

Run with: python -m pytest tests/test_check_rules.py -v
"""

import pytest
from bob.checks.firewall import check_rules as _check_rules
from bob.scoring import FindingLevel
from tests.helpers import _deduction_keys, _get_finding, _has_finding


# ---------------------------------------------------------------------------
# Minimal translation stub
# ---------------------------------------------------------------------------

def t(key, **kwargs):
    """Return the key itself so assertions stay readable."""
    return key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def total_deductions(result) -> int:
    return sum(d.points for d in result.deductions)


def has_alert(result) -> bool:
    return any(f.level == FindingLevel.ALERT for f in result.findings)


def has_warn(result) -> bool:
    return any(f.level == FindingLevel.WARN for f in result.findings)


# ---------------------------------------------------------------------------
# UFW rule fixtures
# ---------------------------------------------------------------------------

# ufw status numbered pads lines with trailing spaces — this was the root cause
# of the v0.11.3 regression where open-any was silently missed.
OPEN_ANY_TRAILING_SPACES = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere                  \n"
    "[ 2] 22/tcp                     ALLOW IN    Anywhere                  \n"
)

OPEN_ANY_NO_TRAILING = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere\n"
    "[ 2] 22/tcp                     ALLOW IN    Anywhere\n"
)

OPEN_ANY_V6 = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere                  \n"
    "[ 2] Anywhere (v6)              ALLOW IN    Anywhere (v6)             \n"
)

OPEN_ANY_TCP = (
    "[ 1] Anywhere/tcp               ALLOW IN    Anywhere/tcp              \n"
    "[ 2] 22/tcp                     ALLOW IN    Anywhere                  \n"
)

OPEN_ANY_UDP = (
    "[ 1] Anywhere/udp               ALLOW IN    Anywhere/udp              \n"
)

CLEAN_RULES = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)

DUPLICATE_EXACT = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)

DUPLICATE_COMMENT_IGNORED = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                   # test2\n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
)

# PORT/proto is redundant when PORT (no proto) exists for same action+source
DUPLICATE_SEMANTIC_TCP = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                   # test2\n"
    "[ 2] 80                         ALLOW IN    Anywhere                  \n"
)

DUPLICATE_SEMANTIC_UDP = (
    "[ 1] 5353/udp                   ALLOW IN    Anywhere                  \n"
    "[ 2] 5353                       ALLOW IN    Anywhere                  \n"
)

# PORT/tcp + PORT/udp only (no PORT) — NOT a duplicate, they are complementary
NO_DUPLICATE_TCP_UDP_ONLY = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 80/udp                     ALLOW IN    Anywhere                  \n"
)

NO_DUPLICATE_RULES = (
    "[ 1] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 443/tcp                    ALLOW IN    Anywhere                  \n"
)

IPV4_ONLY_RULES = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
)

IPV4_AND_IPV6_RULES = (
    "[ 1] 22/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)             \n"
)

# Combined: open-any (line 1) + duplicate 80/tcp (lines 2+3) + IPv4-only → ipv6_missing
ALL_ISSUES = (
    "[ 1] Anywhere                   ALLOW IN    Anywhere                  \n"
    "[ 2] 80/tcp                     ALLOW IN    Anywhere                  \n"
    "[ 3] 80/tcp                     ALLOW IN    Anywhere                  \n"
)


# ---------------------------------------------------------------------------
# open-any detection
# ---------------------------------------------------------------------------

class TestOpenAny:
    def test_trailing_spaces_detected(self):
        """Regression: trailing spaces must not prevent open-any detection."""
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        assert _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT), \
            "Wildcard ALLOW IN Anywhere with trailing spaces not detected"

    def test_no_trailing_spaces_detected(self):
        """Baseline: detection works when there are no trailing spaces."""
        result = _check_rules("", OPEN_ANY_NO_TRAILING, t)
        assert _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT)

    def test_v6_both_detected(self):
        """Both IPv4 and IPv6 wildcard rules trigger separate alerts."""
        result = _check_rules("", OPEN_ANY_V6, t)
        alerts = [f for f in result.findings if f.key == "firewall_rules.open_any_found"]
        assert len(alerts) == 2, f"Expected 2 open-any alerts (IPv4 + IPv6), got {len(alerts)}"

    def test_deduction_applied(self):
        """Wildcard rule carries a score deduction."""
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        assert total_deductions(result) >= 2

    def test_deduction_key(self):
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        assert "firewall_rules.open_any_found" in _deduction_keys(result)

    def test_tcp_variant_detected(self):
        """Anywhere/tcp ALLOW IN Anywhere/tcp — all TCP ports open — must be detected."""
        result = _check_rules("", OPEN_ANY_TCP, t)
        assert _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT)

    def test_udp_variant_detected(self):
        """Anywhere/udp ALLOW IN Anywhere/udp — all UDP ports open — must be detected."""
        result = _check_rules("", OPEN_ANY_UDP, t)
        assert _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT)

    def test_clean_rules_no_alert(self):
        """No false positive when rules are port-restricted."""
        result = _check_rules("", CLEAN_RULES, t)
        assert not _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT)

    def test_nature_is_action(self):
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        finding = _get_finding(result, "firewall_rules.open_any_found")
        assert finding is not None
        assert finding.nature == "action"

    def test_cmd_contains_delete(self):
        """The fix command must reference ufw --force delete."""
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        finding = _get_finding(result, "firewall_rules.open_any_found")
        assert finding is not None
        assert "ufw --force delete" in finding.cmd

    def test_cmd_references_rule_index(self):
        """The delete command must target the specific rule index."""
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        finding = _get_finding(result, "firewall_rules.open_any_found")
        assert finding is not None
        assert "1" in finding.cmd  # rule [ 1] → delete 1


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------

class TestDuplicates:
    def test_exact_duplicate_detected(self):
        result = _check_rules("", DUPLICATE_EXACT, t)
        assert _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_comment_stripped_for_duplicate_check(self):
        """80/tcp # test2 and 80/tcp without comment are the same rule."""
        result = _check_rules("", DUPLICATE_COMMENT_IGNORED, t)
        assert _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_semantic_duplicate_tcp_detected(self):
        """80/tcp is redundant when 80 (no proto) exists — must be flagged."""
        result = _check_rules("", DUPLICATE_SEMANTIC_TCP, t)
        assert _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_semantic_duplicate_udp_detected(self):
        """5353/udp is redundant when 5353 (no proto) exists — must be flagged."""
        result = _check_rules("", DUPLICATE_SEMANTIC_UDP, t)
        assert _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_tcp_and_udp_only_no_false_positive(self):
        """PORT/tcp + PORT/udp without PORT — complementary rules, not duplicates."""
        result = _check_rules("", NO_DUPLICATE_TCP_UDP_ONLY, t)
        assert not _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_no_false_positive_duplicates(self):
        result = _check_rules("", NO_DUPLICATE_RULES, t)
        assert not _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_deduction_applied(self):
        result = _check_rules("", DUPLICATE_EXACT, t)
        assert total_deductions(result) >= 1

    def test_deduction_key(self):
        result = _check_rules("", DUPLICATE_EXACT, t)
        assert "firewall_rules.duplicate_found" in _deduction_keys(result)

    def test_nature_is_action(self):
        result = _check_rules("", DUPLICATE_EXACT, t)
        finding = _get_finding(result, "firewall_rules.duplicate_found")
        assert finding is not None
        assert finding.nature == "action"

    def test_cmd_contains_delete(self):
        """The fix command must reference ufw --force delete."""
        result = _check_rules("", DUPLICATE_EXACT, t)
        finding = _get_finding(result, "firewall_rules.duplicate_found")
        assert finding is not None
        assert "ufw --force delete" in finding.cmd


# ---------------------------------------------------------------------------
# IPv6 consistency
# ---------------------------------------------------------------------------

class TestIPv6Coverage:
    def test_ipv6_missing_triggers_warning(self):
        result = _check_rules("", IPV4_ONLY_RULES, t)
        assert _has_finding(result, "firewall_rules.ipv6_missing", FindingLevel.WARN)

    def test_ipv4_and_ipv6_no_warning(self):
        result = _check_rules("", IPV4_AND_IPV6_RULES, t)
        assert not _has_finding(result, "firewall_rules.ipv6_missing", FindingLevel.WARN)

    def test_ipv6_disabled_suppresses_warning(self):
        """When ipv6_enabled=False, missing IPv6 rules are not flagged."""
        result = _check_rules("", IPV4_ONLY_RULES, t, ipv6_enabled=False)
        assert not _has_finding(result, "firewall_rules.ipv6_missing", FindingLevel.WARN)

    def test_deduction_key(self):
        result = _check_rules("", IPV4_ONLY_RULES, t)
        assert "firewall_rules.ipv6_missing" in _deduction_keys(result)

    def test_nature_is_improvement(self):
        result = _check_rules("", IPV4_ONLY_RULES, t)
        finding = _get_finding(result, "firewall_rules.ipv6_missing")
        assert finding is not None
        assert finding.nature == "improvement"


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

class TestCombined:
    def test_open_any_and_duplicate_both_detected(self):
        """open-any + duplicate in same ruleset → both findings present."""
        result = _check_rules("", ALL_ISSUES, t)
        assert _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT)
        assert _has_finding(result, "firewall_rules.duplicate_found", FindingLevel.ALERT)

    def test_combined_total_deduction(self):
        """open-any (−2) + duplicate (−1) = at least 3 pts deducted."""
        result = _check_rules("", ALL_ISSUES, t)
        assert total_deductions(result) >= 3

    def test_open_any_and_ipv6_missing(self):
        """IPv4-only open-any ruleset → both open-any alert and ipv6_missing warn."""
        result = _check_rules("", OPEN_ANY_TRAILING_SPACES, t)
        assert _has_finding(result, "firewall_rules.open_any_found", FindingLevel.ALERT)
        assert _has_finding(result, "firewall_rules.ipv6_missing", FindingLevel.WARN)
