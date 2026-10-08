"""v0.24.2 — a firewalld zone that accepts everything is not an OK.

A zone's target decides what happens to a packet no rule matches; ``ACCEPT``
(the ``trusted`` zone, or any zone set that way) lets everything in. Measured
on Fedora 44 in 0.24.1: with the default zone's target set to ACCEPT the
attack surface rightly said "default policy is ALLOW — no filtering", while the
firewall section said "firewalld is the active firewall" as an OK and nothing
was deducted. UFW's ALLOW default has cost 3 points since the beginning
(``firewall.policy_open``); firewalld now pays the same, under its own key —
the UFW key carries a UFW-specific CIS reference.

The other polarity matters as much: ``default``, ``%%REJECT%%`` and ``DROP``
filter, and a target BOB could not read is not evidence of ACCEPT.
"""

from __future__ import annotations

import pytest

from bob.checks._firewalld import FirewalldStatus
from bob.checks.firewall import FirewallStatus, _firewalld_close_cmd, check_firewall
from bob.scoring import FindingLevel
from tests.helpers import _keys, _t


def _ufw_inactive() -> FirewallStatus:
    return FirewallStatus(installed=False, active=False, incoming_policy="unknown",
                          ufw_output="", numbered_output="", ipv6_ufw_enabled=False)


def _firewalld(target: str, zone: str = "FedoraServer") -> FirewalldStatus:
    return FirewalldStatus(active=True, default_zone=zone, services=["ssh", "cockpit"],
                           target=target)


def _run(target: str, zone: str = "FedoraServer"):
    return check_firewall(_ufw_inactive(), firewalld=_firewalld(target, zone), t=_t)


class TestAcceptIsAlerted:
    def test_accept_target_alerts_and_deducts_like_ufw(self):
        result = _run("ACCEPT")
        assert "firewall.firewalld_policy_open" in _keys(result)
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert finding.level == FindingLevel.ALERT
        assert [d.points for d in result.deductions
                if d.key == "firewall.firewalld_policy_open"] == [3]

    def test_firewalld_is_still_credited_as_running(self):
        """It IS running — the defect is its default, not its absence."""
        assert "firewall.firewalld_active" in _keys(_run("ACCEPT"))

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_rendered_message_names_the_zone(self, lang):
        """Through the real locale — a helper that echoes keys proves nothing."""
        from bob import i18n
        i18n.init(lang)
        try:
            result = check_firewall(_ufw_inactive(), firewalld=_firewalld("ACCEPT", zone="home"),
                                    t=i18n.t)
        finally:
            i18n.init(lang="en")  # conftest only initialises an uninitialised i18n
        finding = next(f for f in result.findings if f.key == "firewall.firewalld_policy_open")
        assert "'home'" in finding.message and "ACCEPT" in finding.message
        assert finding.template_vars == {"zone": "home"}


@pytest.mark.parametrize("target", ["default", "%%REJECT%%", "REJECT", "DROP"])
def test_filtering_targets_are_not_alerted(target):
    result = _run(target)
    assert "firewall.firewalld_policy_open" not in _keys(result)
    assert not result.deductions


def test_an_unread_target_is_not_taken_for_accept():
    """"" = firewall-cmd gave no target line; unknown is not ALLOW."""
    result = _run("")
    assert "firewall.firewalld_policy_open" not in _keys(result)
    assert not result.deductions


class TestTheFixDoesNotLockTheOperatorOut:
    def test_a_named_zone_keeps_ssh_before_closing(self):
        cmd = _firewalld_close_cmd("FedoraServer")
        assert cmd.index("--add-service=ssh") < cmd.index("--set-target=default")
        assert "--zone=FedoraServer" in cmd and cmd.endswith("sudo firewall-cmd --reload")

    def test_trusted_is_left_alone_and_the_default_moves(self):
        """``trusted`` exists to accept everything; rewriting it would surprise
        whatever deliberately binds an interface to it."""
        assert _firewalld_close_cmd("trusted") == "sudo firewall-cmd --set-default-zone=public"

    def test_a_hostile_zone_name_is_quoted(self):
        cmd = _firewalld_close_cmd("x; rm -rf /")
        assert "--zone='x; rm -rf /'" in cmd

    def test_the_finding_carries_the_fix(self):
        finding = next(f for f in _run("ACCEPT").findings
                       if f.key == "firewall.firewalld_policy_open")
        assert finding.cmd == _firewalld_close_cmd("FedoraServer")


# ---------------------------------------------------------------------------
# IPv6 — the same zone decides both families
# ---------------------------------------------------------------------------

class TestIpv6UnderFirewalld:
    """Measured on the same Fedora 44 (no ufw package): the IPv6 section said
    "UFW IPv6 configuration matches kernel" — about a UFW that is not there —
    and, under target ACCEPT, "IPv6 listeners are filtered by firewalld"."""

    @staticmethod
    def _run(policy: str, ufw_present: bool = False):
        from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                            ipv6_listeners=["22/tcp", "9090/tcp"], ufw_present=ufw_present)
        return check_ipv6(snap, ufw_active=False, t=_t, firewalld_active=True,
                          firewalld_policy=policy)

    @pytest.mark.parametrize("ufw_present", [False, True])
    def test_no_claim_about_ufw_when_firewalld_filters(self, ufw_present):
        """Also with UFW installed but inactive — the Ubuntu-plus-firewalld case."""
        keys = _keys(self._run("reject", ufw_present))
        assert "ipv6.config_ok" not in keys
        assert not any(k.startswith("ipv6.port_no_v6_rule") for k in keys)

    @pytest.mark.parametrize("policy", ["reject", "deny"])
    def test_a_filtering_zone_is_credited(self, policy):
        assert "ipv6.firewalld_v6" in _keys(self._run(policy))

    def test_an_accepting_zone_is_not_called_filtering(self):
        result = self._run("allow")
        assert "ipv6.firewalld_v6" not in _keys(result)
        finding = next(f for f in result.findings if f.key == "ipv6.firewalld_v6_open")
        assert finding.level == FindingLevel.INFO
        assert not result.deductions  # the firewall section already deducts once


def test_the_runner_hands_the_zone_policy_to_ipv6():
    """The unit tests above pass the policy by hand; this pins that the runner
    does too — without it every firewalld host reads as "filtered"."""
    import inspect

    import bob.runner as runner
    src = inspect.getsource(runner)
    assert 'firewalld_policy=fwd_status.incoming_policy if fwd_status.active else ""' in src


# ---------------------------------------------------------------------------
# `--check list` describes what each section really covers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lang", ["en", "fr"])
@pytest.mark.parametrize("section, must_name", [
    ("firewall", ("UFW", "firewalld", "nftables")),
    ("ipv6", ("UFW", "firewalld")),
    ("ports", ("UFW", "firewalld")),
    ("updates", ("apt", "dnf", "zypper", "pacman", "apk")),
])
def test_section_descriptions_name_every_backend(lang, section, must_name):
    """`--check list` said "UFW firewall — installed, active, default policy"
    for a section that has judged firewalld since 0.20.2 and raw rulesets since
    0.23.0, and "APT cache …" for updates read from five package managers."""
    import json
    from pathlib import Path
    desc = json.loads((Path(__file__).resolve().parent.parent / "bob" / "locales" /
                       f"{lang}.json").read_text(encoding="utf-8"))["sections"]["descriptions"][section]
    missing = [name for name in must_name if name not in desc]
    assert not missing, f"{lang} {section}: {desc!r} does not name {missing}"
