"""v0.26.0 — a host without an active UFW is not audited as a UFW host.

Measured on real hosts (0.25.x audits): openSUSE Leap 16 and Fedora 44
(firewalld, no ufw) and Ubuntu Server 26.04 (ufw installed, off) all received
"No duplicate UFW rules detected", "No 'allow from any' rule…", "UFW log source:
systemd-journald" and "No UFW BLOCK events found" — OK lines about rules and logs
UFW never wrote — under the UFW RULES ANALYSIS and UFW LOG ANALYSIS headers;
Ubuntu also got "Port 22/tcp listening on IPv6 without a matching UFW (v6) rule"
with UFW off, and the firewalld hosts "no UFW rule needed" / "no UFW v6 rule
required" in their port and IPv6 lines.
"""

import inspect

import pytest

import bob.runner as runner
from bob import i18n
from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
from bob.checks.logs import LogsSnapshot, check_logs
from tests.helpers import _keys, _t


def _src():
    return inspect.getsource(runner)


def _line_before(marker):
    lines = _src().splitlines()
    i = next(n for n, ln in enumerate(lines) if marker in ln)
    return lines[i - 1].strip()


def test_ufw_rules_are_analysed_only_while_ufw_is_active():
    assert _line_before('emit_section("firewall_rules")') == "if fw_status.active:"


def test_the_ufw_log_section_needs_ufw_installed():
    lines = _src().splitlines()
    i = next(n for n, ln in enumerate(lines) if 'print_section(t("sections.logs"))' in ln)
    assert lines[i - 1].strip() == "if not config.quiet:" and lines[i - 2].strip() == "if fw_status.installed:"
    assert "ufw_active=fw_status.active" in "\n".join(lines[i:i + 10])


def _empty_logs():
    return LogsSnapshot(entries=[], days_available=1, log_days=7, log_found=True, log_source="journald")


def test_an_empty_log_with_ufw_off_is_not_credited():
    result, _ = check_logs(_empty_logs(), t=_t, ufw_active=False)
    empty = [f for f in result.findings if f.key == "logs.empty"]
    assert empty and empty[0].message == "logs.empty_ufw_inactive"
    assert str(getattr(empty[0].level, "value", empty[0].level)).lower() == "info"


def test_an_empty_log_with_ufw_on_stays_ok():
    result, _ = check_logs(_empty_logs(), t=_t, ufw_active=True)
    empty = [f for f in result.findings if f.key == "logs.empty"]
    assert str(getattr(empty[0].level, "value", empty[0].level)).lower() == "ok"


def test_nftables_beside_an_inactive_ufw_is_not_parallel():
    snap = FirewallStackSnapshot(nftables_active=True)
    assert "firewall_drivers.nftables_parallel" not in _keys(check_firewall_stack(snap, t=_t, ufw_active=False))
    assert "firewall_drivers.nftables_parallel" in _keys(check_firewall_stack(snap, t=_t, ufw_active=True))


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_port_and_ipv6_lines_do_not_name_ufw(lang):
    i18n.init(lang)
    try:
        system = i18n.t("ports.system_port", port="53/udp", service="DNS")
        v6 = i18n.t("ipv6.firewalld_v6")
    finally:
        i18n.init(lang="en")
    assert "UFW" not in system and "UFW" not in v6
