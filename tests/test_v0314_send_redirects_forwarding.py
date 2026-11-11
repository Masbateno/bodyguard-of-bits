"""v0.31.4 — send_redirects says whether a redirect can leave this host.

`hardening.send_redirects_enabled` said "unnecessary on a non-router, can be
abused for MITM", and the explain page "a desktop is never a router" and "if
this machine is a router, keep send_redirects=1". Measured on Linux Mint 22.3
(read-only, /proc): libvirt's network forwards on every interface, so BOB was
calling a forwarding host a non-router.

Measured on Linux 7.0 in network namespaces (Ubuntu Server 26.04, 9 November
2026, ~/.cache/bob-fieldtest/netnsbench/redir0314/):

| forwarding | send_redirects | packet leaves by | redirects | pings |
|---|---|---|---|---|
| 0 | 0 or 1 | any | 0 | 0/5 |
| 1 | 0 | same / other interface | 0 / 0 | 5/5 / 5/5 |
| 1 | 1 | same interface | 4 | 5/5 |
| 1 | 1 | other interface (a NAT) | 0 | 5/5 |

and the interface's own forwarding decides (all 0, eth0 1: 4 redirects;
all 1, eth0 0: none). Setting 0 never stops forwarding. The finding keeps its
point; its detail now names the interfaces that forward, or says none does.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import hardening as h
from tests.helpers import _t
from tests.test_v0310_sysctl_per_iface import _proc, _v4


class TestWhichInterfacesForward:
    def test_the_interfaces_own_value_decides(self, monkeypatch):
        _proc(monkeypatch, _v4("forwarding", all=True, default=False, enp3s0=False, virbr0=True),
              ifaces=("enp3s0", "virbr0"))
        assert h._forwarding_among(["enp3s0", "virbr0", "default"]) == ["virbr0"]

    def test_none_forwards(self, monkeypatch):
        _proc(monkeypatch, _v4("forwarding", all=False, default=False, enp3s0=False))
        assert h._forwarding_among(["enp3s0", "default"]) == []

    def test_an_unreadable_value_states_nothing(self, monkeypatch):
        _proc(monkeypatch, _v4("forwarding", default=False))
        assert h._forwarding_among(["enp3s0", "default"]) is None

    def test_from_system_reads_it(self, monkeypatch):
        """The Mint as measured: everything forwards (libvirt), everything sends."""
        _proc(monkeypatch, {**_v4("send_redirects", all=True, default=True, enp10s0=True, virbr0=True),
                            **_v4("forwarding", all=True, default=True, enp10s0=True, virbr0=True)},
              ifaces=("enp10s0", "virbr0"))
        monkeypatch.setattr(h, "_l2_port", lambda name: False)
        monkeypatch.setattr(h, "_effective_rp_filter", lambda: (2, 2, "enp10s0"))
        monkeypatch.setattr(h, "read_sysctl_boot_files", lambda: [])
        snap = h.HardeningSnapshot.from_system()
        assert snap.send_redirects_forwarding == ["enp10s0", "virbr0", "default"]

    def test_from_system_unread_knob_unread_case(self, monkeypatch):
        _proc(monkeypatch, {})
        monkeypatch.setattr(h, "_effective_rp_filter", lambda: (None, None, ""))
        monkeypatch.setattr(h, "read_sysctl_boot_files", lambda: [])
        assert h.HardeningSnapshot.from_system().send_redirects_forwarding is None


def _detail(forwarding):
    snap = h.HardeningSnapshot(send_redirects=True, send_redirects_where=["enp3s0", "default"],
                               send_redirects_forwarding=forwarding)
    result = h.check_hardening(snap, t=_t)
    f = next(f for f in result.findings if f.key == "hardening.send_redirects_enabled")
    # v0.32.0 — the point is gone where no interface forwards (test_v0320_send_redirects_inert).
    expected = [] if forwarding == [] else [1]
    assert [d.points for d in result.deductions if d.key == "hardening.send_redirects_enabled"] == expected
    return f.detail


class TestTheCaseIsStated:
    def test_forwarding_interfaces_are_named(self):
        assert "hardening.send_redirects_forwarding" in _detail(["enp3s0"])
        assert "hardening.send_redirects_idle" not in _detail(["enp3s0"])

    def test_no_forwarding_says_none_is_sent_today(self):
        assert "hardening.send_redirects_idle" in _detail([])
        assert "hardening.send_redirects_forwarding" not in _detail([])

    def test_unread_says_neither(self):
        d = _detail(None)
        assert "send_redirects_idle" not in d and "send_redirects_forwarding" not in d
        assert "hardening.send_redirects_detail" in d


@pytest.mark.parametrize("lang, words, gone", [
    ("en", ["Interfaces that forward, where a redirect can leave from: virbr0",
            "at 0 that packet is still forwarded"],
     ["non-router", "MITM"]),
    ("fr", ["Interfaces qui font du transfert, d'où une redirection peut partir : virbr0",
            "à 0, ce paquet est quand même transféré"],
     ["non-routeur", "MITM"])], ids=["en", "fr"])
def test_the_rendered_finding(lang, words, gone):
    i18n.init(lang)
    try:
        snap = h.HardeningSnapshot(send_redirects=True, send_redirects_where=["virbr0"],
                                   send_redirects_forwarding=["virbr0"])
        f = next(f for f in h.check_hardening(snap, t=i18n.t).findings
                 if f.key == "hardening.send_redirects_enabled")
        explain = i18n.t("explain.hardening.send_redirects_enabled.desktop.why")
    finally:
        i18n.init(lang="en")
    text = f.message + " " + f.detail
    assert all(w in text for w in words)
    assert not any(g in text for g in gone)
    assert "never" not in explain and "jamais un routeur" not in explain


@pytest.mark.parametrize("lang, gone", [
    ("en", "keep send_redirects=1"), ("fr", "conservez send_redirects=1")], ids=["en", "fr"])
def test_the_explain_no_longer_says_keep_it_on(lang, gone):
    i18n.init(lang)
    try:
        how = i18n.t("explain.hardening.send_redirects_enabled.how")
        why = i18n.t("explain.hardening.send_redirects_enabled.why")
    finally:
        i18n.init(lang="en")
    assert gone not in how
    assert "1" in why and ("7.0" in why)
