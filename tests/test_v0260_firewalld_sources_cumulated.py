"""v0.26.0 — what source-bound ACCEPT zones reach together is said.

Measured on openSUSE Leap 16 (firewalld 2.1.2): zones `bobA` (0.0.0.0/2) and
`bobB` (64.0.0.0/3), target ACCEPT, each got its own INFO and nothing said that
together they let every packet in from 37.5 % of IPv4 — 42.6 % of its public
addresses. Decided: an INFO that adds them up, not scored (BOB cannot judge
whether those sources deserve the trust).
"""

import pytest

from bob import i18n
from bob.checks._firewalld import ZoneBinding, source_coverage
from bob.checks.firewall import _pct


def _z(name, *sources):
    return ZoneBinding(name=name, sources=sources)


def test_the_measured_pair_is_added_up():
    [(family, names, share, public)] = source_coverage([_z("bobA", "0.0.0.0/2"), _z("bobB", "64.0.0.0/3")])
    assert family == "ipv4" and names == ("bobA", "bobB")
    assert share == 37.5 and round(public, 1) == 42.6


def test_a_whole_family_is_left_to_the_pooled_alert():
    assert source_coverage([_z("a", "0.0.0.0/1"), _z("b", "128.0.0.0/1")]) == []


def test_one_zone_alone_keeps_its_own_info():
    assert source_coverage([_z("a", "0.0.0.0/2")]) == []


def test_non_public_ranges_are_not_counted_public():
    [(_, _, share, public)] = source_coverage([_z("a", "10.0.0.0/8"), _z("b", "192.168.0.0/16")])
    assert share > 0 and public == 0


def test_mac_sources_are_not_addresses():
    assert source_coverage([_z("a", "aa:bb:cc:dd:ee:ff"), _z("b", "0.0.0.0/2")]) == []


@pytest.mark.parametrize("value, lang, text", [(37.5, "en", "37.5"), (37.5, "fr", "37,5"),
                                               (42.6012, "en", "42.6"), (0.00001, "fr", "< 0,1"),
                                               (0.0, "en", "0")])
def test_the_share_is_written_for_the_language(value, lang, text):
    assert _pct(value, lang) == text


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_info_renders(lang):
    i18n.init(lang)
    try:
        text = i18n.t("firewall.firewalld_source_zones_cumulated", zones="bobA, bobB",
                      family="IPv4", share=_pct(37.5, lang), public=_pct(42.6, lang))
    finally:
        i18n.init(lang="en")
    assert "bobA, bobB" in text and ("37.5%" in text or "37,5 %" in text)
