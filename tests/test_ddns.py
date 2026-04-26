"""
Unit tests for bob.checks.ddns module.

All tests use DdnsSnapshot instances built directly — no subprocess calls.

Run with: python -m pytest tests/test_ddns.py -v
"""

import pytest
from bob.checks.ddns import (
    DdnsSnapshot,
    _extract_ddclient_domain,
    _extract_duckdns_domain,
    _extract_inadyn_domain,
    _extract_noip_domain,
    _find_open_ports,
    check_ddns,
    ddns_effective_context,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def has_level(result, level):
    return level in _levels(result)


def total_deductions(result):
    return sum(d.points for d in result.deductions)


UFW_OPEN = """\
[ 1] 8096/tcp                   ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere
"""

UFW_LOCAL_ONLY = """\
[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24
"""

UFW_EMPTY = ""


# ---------------------------------------------------------------------------
# DdnsSnapshot factories
# ---------------------------------------------------------------------------

class TestDdnsSnapshotFactories:
    def test_none_factory(self):
        s = DdnsSnapshot.none()
        assert not s.installed
        assert not s.active
        assert s.client_name is None

    def test_detected_factory(self):
        s = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        assert s.installed
        assert s.active
        assert s.client_name == "ddclient"
        assert s.domain == "test.duckdns.org"

    def test_detected_inactive(self):
        s = DdnsSnapshot.detected("ddclient", active=False)
        assert not s.active
        assert s.installed


# ---------------------------------------------------------------------------
# _find_open_ports
# ---------------------------------------------------------------------------

class TestFindOpenPorts:
    def test_finds_unrestricted_ports(self):
        ports = _find_open_ports(UFW_OPEN)
        assert "8096/tcp" in ports
        assert "80/tcp" in ports

    def test_skips_local_restricted(self):
        ports = _find_open_ports(UFW_LOCAL_ONLY)
        assert ports == []

    def test_empty_rules(self):
        assert _find_open_ports(UFW_EMPTY) == []

    def test_no_duplicates(self):
        rules = "[ 1] 80/tcp  ALLOW IN  Anywhere\n[ 2] 80/tcp  ALLOW IN  Anywhere\n"
        ports = _find_open_ports(rules)
        assert ports.count("80/tcp") == 1

    def test_skips_deny_rules(self):
        rules = "[ 1] 22/tcp  DENY IN  Anywhere\n"
        assert _find_open_ports(rules) == []

    def test_private_10_skipped(self):
        rules = "[ 1] 22/tcp  ALLOW IN  10.0.0.0/8\n"
        assert _find_open_ports(rules) == []

    def test_private_172_skipped(self):
        rules = "[ 1] 22/tcp  ALLOW IN  172.16.0.0/12\n"
        assert _find_open_ports(rules) == []

    def test_udp_port_detected(self):
        rules = "[ 1] 51820/udp  ALLOW IN  Anywhere\n"
        ports = _find_open_ports(rules)
        assert "51820/udp" in ports

    def test_malformed_rule_no_port_proto_does_not_crash(self):
        """A rule line with no port/proto token must be skipped without raising."""
        rules = "[ 1] ALLOW IN  Anywhere\n"
        assert _find_open_ports(rules) == []


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

class TestExtractDdclientDomain:
    def test_standard_hostname_key(self):
        content = "protocol=duckdns\nhostname=myhost.duckdns.org\n"
        assert _extract_ddclient_domain(content) == "myhost.duckdns.org"

    def test_host_key(self):
        content = "protocol=dyndns\nhost=myhost.example.com\n"
        assert _extract_ddclient_domain(content) == "myhost.example.com"

    def test_duckdns_format_last_line(self):
        content = (
            "protocol=duckdns \\\n"
            "use=web \\\n"
            "login=myhost \\\n"
            "password=token \\\n"
            "http://myhost.duckdns.org \n"
        )
        result = _extract_ddclient_domain(content)
        assert result == "myhost.duckdns.org"

    def test_empty_content(self):
        assert _extract_ddclient_domain("") is None

    def test_hostname_with_empty_value(self):
        """hostname = (trailing spaces only) must not return a non-empty domain."""
        result = _extract_ddclient_domain("hostname = \n")
        assert not result  # empty string or None — neither is a valid domain

    def test_quoted_hostname(self):
        """hostname = "myhost.duckdns.org" — quotes must be stripped."""
        result = _extract_ddclient_domain('hostname="myhost.duckdns.org"\n')
        assert result == "myhost.duckdns.org"


class TestExtractInadynDomain:
    def test_hostname_key(self):
        content = "provider dyndns {\n  hostname = myhost.ddns.net\n}\n"
        assert _extract_inadyn_domain(content) == "myhost.ddns.net"

    def test_empty(self):
        assert _extract_inadyn_domain("") is None

    def test_invalid_domain_format_returns_none(self):
        """A value that fails the domain regex (no dot, no TLD) must return None."""
        content = "hostname = not-a-valid\n"
        assert _extract_inadyn_domain(content) is None


class TestExtractNoipDomain:
    def test_hostname_key(self):
        content = "hostname myhost.ddns.net\n"
        assert _extract_noip_domain(content) == "myhost.ddns.net"

    def test_empty(self):
        assert _extract_noip_domain("") is None


class TestExtractDuckdnsDomain:
    def test_finds_duckdns_org(self):
        content = "curl https://www.duckdns.org/update?domains=myhost&token=abc\n"
        assert _extract_duckdns_domain(content) == "myhost.duckdns.org"

    def test_empty(self):
        assert _extract_duckdns_domain("") is None

    def test_full_domain_in_content(self):
        """Full domain present without ?domains= param uses the fallback regex."""
        content = "echo url=myhost.duckdns.org | curl -K -\n"
        result = _extract_duckdns_domain(content)
        assert result == "myhost.duckdns.org"


# ---------------------------------------------------------------------------
# check_ddns
# ---------------------------------------------------------------------------

class TestCheckDdnsNoClient:
    def test_ok_when_no_ddns(self):
        result = check_ddns(DdnsSnapshot.none())
        assert has_level(result, "ok")

    def test_no_deduction_when_no_ddns(self):
        result = check_ddns(DdnsSnapshot.none())
        assert total_deductions(result) == 0


class TestCheckDdnsInactive:
    def test_info_when_inactive(self):
        snap = DdnsSnapshot.detected("ddclient", active=False)
        result = check_ddns(snap)
        assert has_level(result, "info")

    def test_no_deduction_when_inactive(self):
        snap = DdnsSnapshot.detected("ddclient", active=False)
        result = check_ddns(snap)
        assert total_deductions(result) == 0


class TestCheckDdnsActiveFoundKey:
    def test_found_finding_has_key(self):
        result = check_ddns(DdnsSnapshot.detected("ddclient"), ufw_rules=UFW_EMPTY)
        keys = [f.key for f in result.findings]
        assert "ddns.found" in keys


class TestCheckDdnsActiveNoPorts:
    def test_warn_for_active_ddns(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert has_level(result, "warn")

    def test_ok_when_no_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert has_level(result, "ok")

    def test_no_deduction_when_no_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert total_deductions(result) == 0

    def test_domain_in_findings(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        messages = [f.message for f in result.findings]
        assert any("test.duckdns.org" in m for m in messages)

    def test_no_domain_info(self):
        snap = DdnsSnapshot.detected("ddclient", domain=None)
        result = check_ddns(snap, ufw_rules=UFW_EMPTY)
        assert has_level(result, "info")


class TestCheckDdnsActiveWithPorts:
    def test_warn_with_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        warns = [f for f in result.findings if f.level == FindingLevel.WARN]
        assert len(warns) >= 1

    def test_deduction_1_with_open_ports(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        assert total_deductions(result) == 1

    def test_open_ports_stored(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        assert "8096/tcp" in result.open_ports

    def test_advice_info_present(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_OPEN)
        assert has_level(result, "info")

    def test_local_only_ports_no_deduction(self):
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=UFW_LOCAL_ONLY)
        assert total_deductions(result) == 0

    def test_single_global_deduction_regardless_of_port_count(self):
        """One deduction total, not per open port."""
        rules = (
            "[ 1] 80/tcp    ALLOW IN  Anywhere\n"
            "[ 2] 443/tcp   ALLOW IN  Anywhere\n"
            "[ 3] 8096/tcp  ALLOW IN  Anywhere\n"
        )
        snap = DdnsSnapshot.detected("ddclient", domain="test.duckdns.org")
        result = check_ddns(snap, ufw_rules=rules)
        assert total_deductions(result) == 1


class TestCheckDdnsTranslation:
    def test_translation_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        result = check_ddns(DdnsSnapshot.none(), t=my_t)
        assert any("T:" in f.message for f in result.findings)


# ---------------------------------------------------------------------------
# ddns_effective_context
# ---------------------------------------------------------------------------

class TestDdnsEffectiveContext:
    def test_inactive_ddns_returns_local(self):
        snap = DdnsSnapshot.detected("ddclient", active=False)
        assert ddns_effective_context(snap, UFW_OPEN) == "local"

    def test_no_client_returns_local(self):
        assert ddns_effective_context(DdnsSnapshot.none(), UFW_OPEN) == "local"

    def test_active_with_open_ports_returns_ddns(self):
        snap = DdnsSnapshot.detected("ddclient")
        assert ddns_effective_context(snap, UFW_OPEN) == "ddns"

    def test_active_no_open_ports_returns_local(self):
        snap = DdnsSnapshot.detected("ddclient")
        assert ddns_effective_context(snap, UFW_LOCAL_ONLY) == "local"

    def test_active_empty_rules_returns_local(self):
        snap = DdnsSnapshot.detected("ddclient")
        assert ddns_effective_context(snap, UFW_EMPTY) == "local"

    def test_returns_ddns_not_public(self):
        """Context must be "ddns" (not "public") so display is accurate."""
        snap = DdnsSnapshot.detected("ddclient")
        ctx = ddns_effective_context(snap, UFW_OPEN)
        assert ctx == "ddns"
        assert ctx != "public"
