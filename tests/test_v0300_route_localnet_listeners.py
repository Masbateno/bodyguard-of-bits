"""v0.30.0, review of the changelog — "bound to localhost only — no external
exposure" was not always true.

Measured in a network namespace (2 November 2026,
`~/.cache/bob-fieldtest/netnsbench/localnet_audit.txt`, full audit, throwaway
HOME): with `route_localnet` 1 on the host, a client sending to 127.0.0.1 over
the wire reached a listener bound to 127.0.0.1 alone (port 8097), and 0.29.0
and the first draft of 0.30.0 both said "Port 8097/tcp — bound to localhost
only — no external exposure". Kubernetes' kube-proxy sets the switch
(CVE-2020-8558). With it on, or not read, the ports section, the services
section and CUPS no longer say the listener is not exposed: whether it is
reachable is not established — no points, the score marked as a ceiling.
At 0 nothing changes; ::1 is not concerned (IPv6 has no such switch).
"""

from __future__ import annotations

import inspect

import pytest

from bob import i18n
from bob.checks import cups as cups_mod
from bob.checks import ports as ports_mod
from bob.checks.cups import CupsSnapshot, check_cups
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from bob.checks.services import Exposure, check_services
from bob.visibility import is_visibility_key
from tests.test_services import make_service, make_snapshot


@pytest.fixture
def en():
    i18n.init("en")
    yield i18n.t
    i18n.init("en")


def _ports(address, reachable):
    snap = PortsSnapshot(ports=[ListeningPort(port=8097, proto="tcp", address=address, raw_line="")],
                         ufw_rules="", ss_output="", loopback_reachable=reachable)
    return check_ports(snap, ufw_active=False, default_incoming_policy="allow", t=i18n.t)


def _keyed(result, prefix):
    return [(f.key, f.message) for f in result.findings if f.key.startswith(prefix)]


class TestThePortsSection:

    @pytest.mark.parametrize("reachable, key", [
        (True, "ports.uncovered_local_localnet"),
        (None, "ports.uncovered_local_localnet_unread"),
        (False, "ports.uncovered_local"),
    ], ids=["on", "not-read", "off"])
    def test_what_is_said(self, en, reachable, key):
        found = _keyed(_ports("127.0.0.1", reachable), "ports.uncovered_local")
        assert [k for k, _ in found] == [key]
        message = found[0][1]
        assert ("no external exposure" in message) is (reachable is False)
        if reachable is not False:
            assert "whether this port is reachable is not established" in message

    def test_ipv6_loopback_is_not_concerned(self, en):
        found = _keyed(_ports("::1", True), "ports.uncovered_local")
        assert [k for k, _ in found] == ["ports.uncovered_local"]

    def test_read_with_the_listeners(self, monkeypatch):
        class R:
            ok, stdout, stderr, code = True, "", "", 0
        monkeypatch.setattr(ports_mod, "run_result", lambda *a, **k: R())
        monkeypatch.setattr(ports_mod, "_run", lambda *a, **k: "")
        import bob.checks.iptables_nftables as nf
        monkeypatch.setattr(nf, "_route_localnet", lambda: True)
        assert PortsSnapshot.from_system().loopback_reachable is True


class TestTheServicesSection:

    @staticmethod
    def _check(reachable, v4_ports=frozenset({"22/tcp"})):
        snap = make_snapshot(service=make_service(), exposures={"22/tcp": Exposure.LOOPBACK_NO_RULE})
        return check_services([snap], ufw_active=False, t=i18n.t,
                              loopback_reachable=reachable, loopback_v4_ports=v4_ports)

    @pytest.mark.parametrize("reachable, key", [
        (True, "services.exposure.loopback_localnet"),
        (None, "services.exposure.loopback_localnet_unread"),
        (False, "services.exposure.loopback_no_rule"),
    ], ids=["on", "not-read", "off"])
    def test_what_is_said(self, en, reachable, key):
        found = _keyed(self._check(reachable), "services.exposure")
        assert [k for k, _ in found] == [key]
        assert ("no external exposure" in found[0][1]) is (reachable is False)

    def test_ipv6_loopback_is_not_concerned(self, en):
        found = _keyed(self._check(True, v4_ports=frozenset()), "services.exposure")
        assert [k for k, _ in found] == ["services.exposure.loopback_no_rule"]

    def test_the_audit_hands_them(self):
        from bob import runner
        src = inspect.getsource(runner)
        assert "loopback_reachable=ports_snapshot.loopback_reachable," in src
        assert "loopback_v4_ports=ports_snapshot.loopback_v4_ports," in src


class TestCups:

    @staticmethod
    def _check(values, reachable):
        return check_cups(CupsSnapshot(cfg_present=True, listen_values=values,
                                       loopback_reachable=reachable), t=i18n.t)

    @pytest.mark.parametrize("values, reachable, key", [
        (["localhost:631"], True, "cups.listen_localhost_localnet"),
        (["127.0.0.1:631"], None, "cups.listen_localhost_localnet_unread"),
        (["localhost:631"], False, "cups.listen_localhost"),
        (["[::1]:631", "/run/cups/cups.sock"], True, "cups.listen_localhost"),
    ], ids=["on", "not-read", "off", "ipv6-and-socket-only"])
    def test_what_is_said(self, en, values, reachable, key):
        found = _keyed(self._check(values, reachable), "cups.listen")
        assert [k for k, _ in found] == [key]
        assert ("not network-exposed" in found[0][1]) is (key == "cups.listen_localhost")

    def test_read_with_the_configuration(self, monkeypatch):
        import bob.checks.iptables_nftables as nf
        monkeypatch.setattr(nf, "_route_localnet", lambda: None)
        monkeypatch.setattr(cups_mod, "path_exists", lambda p: False)
        assert CupsSnapshot.from_system().loopback_reachable is None


@pytest.mark.parametrize("key", [
    "ports.uncovered_local_localnet", "ports.uncovered_local_localnet_unread",
    "services.exposure.loopback_localnet", "services.exposure.loopback_localnet_unread",
    "cups.listen_localhost_localnet", "cups.listen_localhost_localnet_unread",
])
def test_each_is_a_ceiling(key):
    """Not established: no points, the score shown as an upper bound."""
    assert is_visibility_key(key)


@pytest.mark.parametrize("lang, key, words", [
    ("en", "ports.uncovered_local_localnet", "but route_localnet is on: a packet from the network reaches 127.0.0.0/8"),
    ("fr", "ports.uncovered_local_localnet", "mais route_localnet est actif : un paquet venu du réseau atteint 127.0.0.0/8"),
    ("en", "services.exposure.loopback_localnet_unread", "route_localnet could not be read"),
    ("fr", "cups.listen_localhost_localnet", "que le service d'impression soit exposé au réseau n'est pas établi"),
])
def test_the_words(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key, port="8097/tcp")
    finally:
        i18n.init("en")
