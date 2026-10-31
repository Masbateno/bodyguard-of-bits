"""v0.29.0 — Docker's nftables backend over IPv6: the explanations say what was measured.

0.28.0 measured DOCKER-USER over IPv6 with the iptables backend only, and wrote
the limit. Measured with Docker 29 in a container (31 October 2026,
`~/.cache/bob-fieldtest/netnsbench/dockerv6nft.sh`), nftables backend, a client
on a veth: on a network without IPv6 the published port answers over IPv6
through docker-proxy, stopped by the host's IPv6 input filter and not by a
forward chain; with the userland proxy off it does not answer over IPv6; on a
network created with --ipv6 the host's input filter does not stop it, and
`table inet mine` with a forward chain at priority -10 and `iifname <ext> ct
state new tcp dport <port> drop` stops it over IPv4 and IPv6, the container
keeping its outbound access. Explanations only: no verdict changes.
"""

from __future__ import annotations

import pytest

from bob import i18n


@pytest.mark.parametrize("lang, key, words", [
    ("en", "explain.docker.exposed_bypass_ufw.why", "With Docker 29's nftables backend"),
    ("en", "explain.docker.exposed_bypass_ufw.why", "with the userland proxy off, IPv6 did not reach the container at all"),
    ("en", "explain.docker.exposed_bypass_ufw.how", "type filter hook forward priority -10"),
    ("en", "explain.docker.exposed_bypass_ufw.how", "ct state new tcp dport <container-port> drop"),
    ("en", "docker.iptables_bypass_detail3_nftables", "a forward chain at a priority before Docker's (-10)"),
    ("fr", "explain.docker.exposed_bypass_ufw.why", "Avec le backend nftables de Docker 29"),
    ("fr", "explain.docker.exposed_bypass_ufw.how", "type filter hook forward priority -10"),
    ("fr", "docker.iptables_bypass_detail3_nftables", "une chaîne forward est à une priorité avant celle de Docker (-10)"),
])
def test_what_is_said(lang, key, words):
    i18n.init(lang)
    try:
        assert words in i18n.t(key)
    finally:
        i18n.init(lang="en")
