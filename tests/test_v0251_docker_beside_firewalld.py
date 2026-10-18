"""v0.25.1 — Docker on a firewalld host, as measured.

Fedora 44 Server (firewalld, interface in the FedoraServer zone allowing only
cockpit, dhcpv6-client and ssh; Docker 29.8.2 from moby-engine; SELinux
enforcing), 2026-10-17:

* a container publishing 8099 answered from the LAN; a host service on 8097
  was refused — the zone does not filter a published port. BOB said Docker
  "may bypass UFW rules" on a host without UFW, offered "three options" and
  listed two, recommended "explicit UFW rules", and the ports section said
  8099 (docker-proxy) was "governed by the firewalld zone";
* a container publishing on 127.0.0.1 answered locally, not from the LAN;
* with two containers running and no port published, BOB said "No running
  Docker containers detected" while its own Docker hardening section counted
  them.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.docker import DockerSnapshot, check_docker
from bob.checks.ports import ListeningPort, PortsSnapshot, check_ports
from tests.helpers import _keys, _t


def _render(lang, key, **kw):
    i18n.init(lang)
    try:
        return i18n.t(key, **kw)
    finally:
        i18n.init(lang="en")


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_no_published_port_is_not_no_container(lang):
    result = check_docker(DockerSnapshot.unsafe(exposed_ports=[]), t=_t)
    assert "docker.no_containers" in _keys(result)
    text = _render(lang, "docker.no_containers")
    assert ("publishes a port" if lang == "en" else "ne publie de port") in text


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_bypass_names_the_host_firewall(lang):
    for key in ("docker.iptables_bypass", "docker.exposed_bypass_ufw"):
        text = _render(lang, key)
        assert ("host firewall" if lang == "en" else "pare-feu de l'hôte") in text, text
    assert "UFW" not in _render(lang, "docker.exposed_bypass_ufw")


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_options_announced_are_the_options_listed(lang):
    announced = _render(lang, "docker.iptables_bypass_detail1")
    assert ("two options" if lang == "en" else "deux options") in announced
    listed = [_render(lang, f"docker.iptables_bypass_detail{i}") for i in (2, 3)]
    assert [s.strip()[:2] for s in listed] == ["1.", "2."]
    assert "UFW" not in listed[1] and "127.0.0.1" in listed[1]


def _proxy_port(process):
    lp = ListeningPort(port=8099, proto="tcp", address="0.0.0.0", raw_line="", process=process)
    return PortsSnapshot(ports=[lp], ufw_rules="", ss_output="")


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_a_docker_proxy_port_is_not_said_to_follow_the_zone(lang):
    i18n.init(lang)
    try:
        result = check_ports(_proxy_port("docker-proxy"), ufw_active=False,
                             firewalld_active=True, t=i18n.t)
        other = check_ports(_proxy_port("nginx"), ufw_active=False,
                            firewalld_active=True, t=i18n.t)
    finally:
        i18n.init(lang="en")
    proxy = next(f for f in result.findings if f.key == "ports.uncovered_firewalld")
    plain = next(f for f in other.findings if f.key == "ports.uncovered_firewalld")
    assert "Docker" in proxy.message and proxy.message != plain.message
    assert ("governed by the firewalld zone" if lang == "en" else "régi par la zone") in plain.message


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_docker_user_example_keeps_the_containers_network(lang):
    """Measured on Ubuntu 26.04 with Docker 29.1.3: the former example (an
    ACCEPT for the trusted source, then `-A DOCKER-USER -j DROP`) refused the
    other LAN hosts and also cut the containers' own DNS and internet access;
    with established connections returned first, both held. Both commands use
    -I, which inserts at the top: the RETURN line must be printed second so it
    ends up first — the order measured with iptables -S DOCKER-USER."""
    how = _render(lang, "explain.docker.exposed_port.how")
    assert "-A DOCKER-USER -j DROP" not in how
    assert how.index("--ctstate RELATED,ESTABLISHED -j RETURN") > how.index("! -s ")
    assert "nftables" in how
