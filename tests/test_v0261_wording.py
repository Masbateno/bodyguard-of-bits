"""v0.26.1 — wording found on a Mint host and in the review of its audit.

- The report's context line: "Local network only (203.0.113.42)" — that
  address is the public IP the internet sees (the box, behind NAT).
- SSH's risk context: "internet-exposed by default", two lines above BOB's own
  measured "not reachable from the internet on this network".
- An orphan UFW rule: "sudo ufw delete allow 41681/tcp" for Spotify Connect,
  which listens only while it runs.
- The French port line dropped "(no explicit UFW rule needed)".
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.report import AuditReport


@pytest.fixture
def report(tmp_path):
    r = AuditReport.open(directory=tmp_path, version="0.26.1")
    yield r
    r.close()


@pytest.mark.parametrize("lang, words", [("en", "public IP seen from outside: 203.0.113.42"),
                                         ("fr", "IP publique vue de l'extérieur : 203.0.113.42")])
def test_the_public_ip_is_named(report, lang, words):
    i18n.init(lang)
    try:
        report.write_summary(score=9, risk_level="LOW", network_context=i18n.t("scoring.context.local"),
                             public_ip="203.0.113.42", ok_count=1, warn_count=0, alert_count=0,
                             breakdown=[], labels={"context_with_ip": i18n.t("report.context_with_ip")})
    finally:
        i18n.init(lang="en")
    report.close()
    assert words in report.path.read_text(encoding="utf-8")


def test_the_display_hands_the_label():
    from bob import display
    assert '"context_with_ip": t("report.context_with_ip", context="{context}", ip="{ip}"),' in inspect.getsource(display)


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_ssh_risk_says_where_it_is_reachable(lang):
    i18n.init(lang)
    try:
        text = i18n.t("service_risk.ssh_server.exposure")
    finally:
        i18n.init(lang="en")
    assert "by default" not in text and "par défaut" not in text
    assert "internet" in text


def test_an_orphan_rule_says_it_may_still_be_needed():
    from bob.checks import firewall
    src = inspect.getsource(firewall)
    assert 'detail=t("firewall_rules.orphan_rule_detail"),' in src
    for lang, words in (("en", "only while it runs"), ("fr", "que lorsqu'il tourne")):
        i18n.init(lang)
        try:
            assert words in i18n.t("firewall_rules.orphan_rule_detail")
        finally:
            i18n.init(lang="en")


def test_the_french_port_line_keeps_its_parenthesis():
    i18n.init("fr")
    try:
        assert "(aucune règle UFW explicite nécessaire)" in i18n.t("services.exposure.no_rule")
    finally:
        i18n.init(lang="en")
