"""v0.26.0 — Docker's firewall backend decides what BOB advises.

Measured on openSUSE Leap 16 (Docker 29.4.0, firewalld): with the default
backend (`iptables+firewalld`) and with `"firewall-backend": "nftables"`
(`nftables+firewalld`, fresh boot, ip_forward set) a published port answered
from the LAN although the zone did not allow it. With the nftables backend
there is no DOCKER-USER chain, yet BOB offered it, tagged the port "bypasses the
host firewall via iptables" and said "while Docker's iptables management is
on". With `"iptables": false` the port was refused from the LAN and only the ip6
table was left — BOB said "UFW rules apply normally" on a firewalld host.
"""

import json

import pytest

from bob import i18n
from bob.checks import docker as dk
from bob.checks.docker import DockerSnapshot, ExposedPort, check_docker
from tests.helpers import _t


@pytest.mark.parametrize("driver, expected", [
    ("iptables+firewalld", "iptables"), ("nftables+firewalld", "nftables"),
    ("nftables", "nftables"), ("iptables", "iptables"),
])
def test_the_backend_comes_from_docker_info(monkeypatch, driver, expected):
    monkeypatch.setattr(dk, "_run", lambda *a, **k: json.dumps({"Driver": driver, "Info": []}))
    assert dk._firewall_backend() == expected


def test_without_docker_info_the_daemon_json_decides(monkeypatch, tmp_path):
    cfg = tmp_path / "daemon.json"
    cfg.write_text('{"firewall-backend": "nftables"}')
    monkeypatch.setattr(dk, "_run", lambda *a, **k: "")
    monkeypatch.setattr(dk, "DAEMON_JSON_PATH", cfg)
    assert dk._firewall_backend() == "nftables"
    cfg.write_text("{}")
    assert dk._firewall_backend() == "iptables"


def _published(backend):
    port = ExposedPort(container_name="bobweb", host_ip="0.0.0.0", host_port=8099,
                       container_port=8080, proto="tcp")
    return DockerSnapshot(installed=True, iptables_disabled=False, daemon_json_exists=True,
                          exposed_ports=[port], firewall_backend=backend)


def test_nftables_backend_gets_no_docker_user_advice():
    res = check_docker(_published("nftables"), t=_t)
    d3 = next(f for f in res.findings if f.key == "docker.iptables_bypass_detail3")
    assert d3.message == "docker.iptables_bypass_detail3_nftables"
    alert = next(f for f in res.findings if f.key == "docker.exposed_bypass_ufw")
    assert "docker.exposed_bypass_nftables" in alert.message


def test_iptables_backend_keeps_docker_user():
    res = check_docker(_published("iptables"), t=_t)
    d3 = next(f for f in res.findings if f.key == "docker.iptables_bypass_detail3")
    assert d3.message == "docker.iptables_bypass_detail3"


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_texts_name_no_ufw_and_no_iptables_where_wrong(lang):
    i18n.init(lang)
    try:
        nft3 = i18n.t("docker.iptables_bypass_detail3_nftables")
        off = i18n.t("docker.iptables_disabled")
        via = i18n.t("docker.exposed_bypass_nftables")
        port = i18n.t("ports.uncovered_firewalld_docker", port="8099/tcp")
        how = i18n.t("explain.docker.exposed_port.how")
        why = i18n.t("explain.docker.exposed_port.why")
    finally:
        i18n.init(lang="en")
    assert "DOCKER-USER" in nft3 and "nftables" in nft3 and "127.0.0.1" in nft3
    assert "UFW" not in off and "IPv6" in off
    assert "nftables" in via and "iptables" not in via
    assert "iptables management" not in port and "gestion iptables" not in port
    assert "nftables" in how and ("Not measured" in why or "Non mesuré" in why)


def test_with_docker_rules_off_the_port_follows_the_zone_again():
    """Measured on openSUSE (Docker 29.4.0, "iptables": false): the published
    port was refused from the LAN — the zone filtered it."""
    from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
    lp = ListeningPort(port=8099, proto="tcp", address="0.0.0.0", raw_line="", process="docker-proxy")
    snap = PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")
    on = check_ports(snap, ufw_active=False, firewalld_active=True, t=_t)
    off = check_ports(snap, ufw_active=False, firewalld_active=True, t=_t, docker_rules_off=True)
    msg = lambda r: next(f.message for f in r.findings if f.key == "ports.uncovered_firewalld")
    assert msg(on).startswith("ports.uncovered_firewalld_docker")
    assert msg(off).startswith("ports.uncovered_firewalld") and not msg(off).startswith("ports.uncovered_firewalld_docker")


def test_the_runner_hands_the_docker_rules_state():
    import inspect
    import bob.runner as runner
    assert "docker_rules_off=_docker_daemon_json()[1]" in inspect.getsource(runner)


class TestStrictForwardPorts:
    """After review, measured on Debian 13 (firewalld 2.3.1, Docker 26.1.5), a
    container publishing 8099, probed from the LAN: StrictForwardPorts=no —
    8099 answered (firewalld's forward chain: `ct status dnat accept`); =yes —
    rejected (`filter_FORWARD_dnat`: reject with icmpx admin-prohibited)."""

    # As `nft list chain inet firewalld filter_FORWARD` printed it on Debian 13.
    LIVE_NO = "\t\tct state { established, related } accept\n\t\tct status dnat accept\n"
    LIVE_YES = "\t\tct state { established, related } accept\n\t\tct status dnat jump filter_FORWARD_dnat\n"

    def test_the_live_setting_is_read(self):
        from bob.checks._firewalld import strict_forward_ports
        assert strict_forward_ports(self.LIVE_YES) is True
        assert strict_forward_ports(self.LIVE_NO) is False
        assert strict_forward_ports("") is None

    def test_not_the_file(self, monkeypatch):
        """Measured: file set to yes without a reload, the loaded chain still
        accepted DNAT'd packets — the live chain decides."""
        from bob.checks import _firewalld as fwd
        from bob.checks._run import CommandResult
        monkeypatch.setattr(fwd, "run_result", lambda *a, **k: CommandResult(stdout=self.LIVE_NO, ok=True, code=0))
        assert fwd.strict_forward_ports() is False

    def _snap(self):
        from bob.checks.docker import DockerSnapshot, ExposedPort
        return DockerSnapshot(installed=True, iptables_disabled=False, daemon_json_exists=False,
                              exposed_ports=[ExposedPort(container_name="bobweb", host_ip="0.0.0.0",
                                                         host_port=8099, container_port=8080, proto="tcp")])

    def test_strict_no_bypass_alert(self):
        from bob.checks.docker import check_docker
        res = check_docker(self._snap(), network_context="public", t=_t, firewalld_strict=True)
        keys = [f.key for f in res.findings]
        assert "docker.firewalld_strict_forward_ports" in keys and "docker.exposed_firewalld_strict" in keys
        assert "docker.exposed_bypass_ufw" not in keys and "docker.iptables_bypass" not in keys
        assert not res.deductions

    def test_default_still_alerts(self):
        from bob.checks.docker import check_docker
        res = check_docker(self._snap(), network_context="public", t=_t)
        assert "docker.exposed_bypass_ufw" in [f.key for f in res.findings] and res.deductions

    def test_the_runner_reads_it_only_with_firewalld_active(self):
        import inspect

        import bob.runner as runner
        src = inspect.getsource(runner)
        assert "_firewalld_strict = bool(fwd_status.active and strict_forward_ports())" in src
        assert src.count("firewalld_strict=_firewalld_strict") == 2     # ports and docker

    def test_the_port_line_follows_the_zone(self):
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        lp = ListeningPort(port=8099, proto="tcp", address="0.0.0.0", raw_line="", process="docker-proxy")
        snap = PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")
        res = check_ports(snap, ufw_active=False, firewalld_active=True, t=_t, firewalld_strict=True)
        msg = next(f.message for f in res.findings if f.key == "ports.uncovered_firewalld")
        assert not msg.startswith("ports.uncovered_firewalld_docker")


class TestAPortAZoneAlsoForwards:
    """After review: under StrictForwardPorts=yes, firewalld 2.3.1 accepts
    DNAT'd traffic to a port Docker publishes when a zone also forwards that
    port, whatever the ingress zone (firewalld issue #1536, confirmed
    upstream; not reproduced here) — such a port keeps the bypass alert."""

    LISTING = ("bobz (active)\n  target: default\n  forward-ports: \n"
               "\tport=8099:proto=tcp:toport=8080:toaddr=172.17.0.2\n"
               "  rich rules: \n\trule family=\"ipv4\" forward-port port=\"9000-9010\" protocol=\"udp\" to-port=\"53\"\n")

    def test_forward_ports_are_read(self):
        from bob.checks._firewalld import forwarded_ports, port_forwarded
        fwd = forwarded_ports(self.LISTING)
        assert fwd == frozenset({(8099, 8099, "tcp"), (9000, 9010, "udp")})
        assert port_forwarded(fwd, 8099, "tcp") and port_forwarded(fwd, 9005, "udp")
        assert not port_forwarded(fwd, 8099, "udp")

    def test_unlisted_zones_are_not_an_empty_set(self, monkeypatch):
        from bob.checks import _firewalld as fwd
        from bob.checks._run import CommandResult
        monkeypatch.setattr(fwd, "run_result", lambda *a, **k: CommandResult(stdout="", ok=False, code=1))
        assert fwd.forwarded_ports() is None

    def test_the_forwarded_port_keeps_the_alert(self):
        from bob.checks.docker import DockerSnapshot, ExposedPort, check_docker
        snap = DockerSnapshot(installed=True, iptables_disabled=False, daemon_json_exists=False,
                              exposed_ports=[ExposedPort("bobweb", 8099, 8080, "tcp", "0.0.0.0"),
                                             ExposedPort("other", 8097, 80, "tcp", "0.0.0.0")])
        res = check_docker(snap, network_context="local", t=_t, firewalld_strict=True,
                           firewalld_forwarded=frozenset({(8099, 8099, "tcp")}))
        alerts = [f.message for f in res.findings if f.key == "docker.exposed_bypass_ufw"]
        infos = [f.message for f in res.findings if f.key == "docker.exposed_firewalld_strict"]
        assert len(alerts) == 1 and "8099/tcp" in alerts[0]
        assert len(infos) == 1 and "8097/tcp" in infos[0]
        assert "docker.iptables_bypass" in [f.key for f in res.findings]   # not all rejected

    def test_the_port_line_keeps_its_docker_text(self):
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        lp = ListeningPort(port=8099, proto="tcp", address="0.0.0.0", raw_line="", process="docker-proxy")
        res = check_ports(PortsSnapshot(ports=[lp], ufw_rules="", ss_output=""), ufw_active=False,
                          firewalld_active=True, t=_t, firewalld_strict=True,
                          firewalld_forwarded=frozenset({(8099, 8099, "tcp")}))
        assert next(f.message for f in res.findings
                    if f.key == "ports.uncovered_firewalld").startswith("ports.uncovered_firewalld_docker_forwarded")

    def test_the_default_port_line_is_not_the_forwarded_one(self):
        from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
        lp = ListeningPort(port=8099, proto="tcp", address="0.0.0.0", raw_line="", process="docker-proxy")
        res = check_ports(PortsSnapshot(ports=[lp], ufw_rules="", ss_output=""), ufw_active=False,
                          firewalld_active=True, t=_t, firewalld_forwarded=frozenset({(8099, 8099, "tcp")}))
        msg = next(f.message for f in res.findings if f.key == "ports.uncovered_firewalld")
        assert msg.startswith("ports.uncovered_firewalld_docker") and "_forwarded" not in msg

    @pytest.mark.parametrize("lang, unmeasured", [("en", "not reproduced here"), ("fr", "non reproduite ici")])
    def test_the_port_lines_say_what_was_measured(self, lang, unmeasured):
        i18n.init(lang)
        try:
            default = i18n.t("ports.uncovered_firewalld_docker", port="8099/tcp")
            forwarded = i18n.t("ports.uncovered_firewalld_docker_forwarded", port="8099/tcp")
        finally:
            i18n.init(lang="en")
        assert "StrictForwardPorts" in default and "Debian" in default
        assert "#1536" in forwarded and unmeasured in forwarded

    def test_the_runner_drops_strict_when_zones_are_unread(self):
        import inspect

        import bob.runner as runner
        src = inspect.getsource(runner)
        assert ("    if _firewalld_forwarded is None:     # zones unread: not taken as rejected\n"
                "        _firewalld_strict, _firewalld_forwarded = False, frozenset()") in src
        assert src.count("firewalld_forwarded=_firewalld_forwarded") == 2


def test_the_docker_user_example_says_what_it_stops():
    from bob import i18n
    for lang, words in (("en", "until it expires"), ("fr", "jusqu'à son expiration")):
        i18n.init(lang)
        try:
            assert words in i18n.t("explain.docker.exposed_port.how")
        finally:
            i18n.init(lang="en")
