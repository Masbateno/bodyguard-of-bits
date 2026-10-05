"""v0.24.1 — wordings the Mint desktop audit showed to be inexact.

- Samba 445/139 allowed from ``192.168.1.11`` only was "restricted to local
  network by UFW rule", with advice to restrict it to trusted networks — it
  already admits one host.
- The SMTP risk context said "this finding fires when that default has been
  changed" above a postfix bound to 127.0.0.1, i.e. with the default intact.
(The "covered by a UFW rule" claim for a port covered by the default policy is
guarded in test_v0241_firewall_posture.py.)
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from bob.checks.services import Exposure, _allow_rule_source, _check_port_exposure, _single_host
from bob.scoring import CheckResult, FindingLevel

_RULES = """\
[ 3] 445/tcp                    ALLOW IN    192.168.1.11               # Samba
[ 5] 137/udp                    ALLOW IN    192.168.1.0/24             # Samba NetBIOS NS - LAN only
"""
_LOCALES = Path(__file__).resolve().parent.parent / "bob" / "locales"


def _t(key: str, **kw) -> str:
    return key + "".join(f"|{v}" for v in kw.values())


def test_rule_source_is_the_address_alone():
    assert _allow_rule_source("445/tcp", _RULES) == "192.168.1.11"
    assert _allow_rule_source("137/udp", _RULES) == "192.168.1.0/24"


def test_single_host_detection():
    assert _single_host("192.168.1.11")
    assert _single_host("fd00::5 (v6)")
    assert not _single_host("192.168.1.0/24")
    assert not _single_host("")


def _finding(source: str):
    result = CheckResult()
    snap = SimpleNamespace(local_sources={"445/tcp": source})
    _check_port_exposure(snap, "445/tcp", Exposure.OPEN_LOCAL, result, "local", True, _t)
    return result.findings[0]


def test_single_host_rule_is_named_not_called_local_network():
    f = _finding("192.168.1.11")
    assert f.key == "services.exposure.open_local_host"
    assert f.level == FindingLevel.INFO
    assert "192.168.1.11" in f.message


def test_subnet_rule_keeps_the_local_network_verdict():
    f = _finding("192.168.1.0/24")
    assert f.key == "services.exposure.open_local"
    assert f.level == FindingLevel.WARN


def test_smtp_context_no_longer_claims_it_fires_on_a_changed_default():
    for lang, phrase in (("en", "this finding fires when that default has been changed"),
                         ("fr", "ce finding se déclenche quand ce défaut a été changé")):
        text = json.loads((_LOCALES / f"{lang}.json").read_text(encoding="utf-8"))
        assert phrase not in text["service_risk"]["smtp_server_postfix_exim"]["exposure"]


def test_ipv6_link_local_listeners_are_said_reachable_from_the_lan():
    # Mint desktop: UFW IPV6=no, fe80:: on br0, sshd on [::]:22. "no internet
    # exposure" was true and left out that LAN neighbours reach these ports
    # with UFW filtering none of them.
    for lang, phrase in (("en", "reachable from the local network"),
                         ("fr", "joignable depuis le réseau local")):
        text = json.loads((_LOCALES / f"{lang}.json").read_text(encoding="utf-8"))
        assert phrase in text["ipv6"]["ufw_disabled_listeners_link_local"]
