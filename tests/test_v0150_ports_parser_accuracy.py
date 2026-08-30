"""
v0.15.0 — accuracy guards for the `ss` output parser.

Unlike the rest of this cycle, the headline result here is negative and worth
recording as such: parsed against the kernel's own socket tables
(`/proc/net/{tcp,tcp6,udp,udp6}`, filtered to the states `ss -l` reports), BOB
agreed exactly — 33 sockets, 20 distinct (proto, port) pairs, nothing missed in
either direction. The parser is sound.

That live comparison is deliberately *not* a test here. It races: a socket can
open or close between the `ss` call and the `/proc` read, and a guard that fails
for reasons unrelated to the code is a guard people learn to ignore. What is
pinned below are the output shapes, which are deterministic — including the ones
this host does not produce, which is where the one real gap was.
"""

from __future__ import annotations

import pytest

from bob.checks.ports import _parse_ss_output, _split_addr_port


class TestAddressSplitting:
    @pytest.mark.parametrize("raw,expected", [
        ("0.0.0.0:22",          ("0.0.0.0", "22", "")),
        ("127.0.0.1:5432",      ("127.0.0.1", "5432", "")),
        ("[::]:22",             ("::", "22", "")),
        ("[::1]:631",           ("::1", "631", "")),
        ("*:5353",              ("*", "5353", "")),
        # %scope, both families. The IPv4 branch always honoured this; the
        # IPv6 branch left the scope glued to the address and returned no
        # iface, so the documented contract held for one family only.
        ("0.0.0.0%virbr0:67",   ("0.0.0.0", "67", "virbr0")),
        ("127.0.0.53%lo:53",    ("127.0.0.53", "53", "lo")),
        ("[fe80::1%eth0]:546",  ("fe80::1", "546", "eth0")),
        ("[::%virbr0]:67",      ("::", "67", "virbr0")),
    ])
    def test_split(self, raw, expected):
        assert _split_addr_port(raw) == expected

    @pytest.mark.parametrize("raw", ["garbage", "", "0.0.0.0:", ":22", "[::]:"])
    def test_unparseable_input_is_rejected_not_guessed(self, raw):
        assert _split_addr_port(raw) == (None, None, "")


class TestAllInterfacesClassification:
    """`is_all_interfaces` drives the exposure verdict, and it is the one place
    the scope suffix could have mattered: a socket bound to a virtual bridge is
    not listening on the world."""

    @pytest.mark.parametrize("local,expected", [
        ("0.0.0.0:22",        True),
        ("[::]:22",           True),
        ("*:5353",            True),
        ("0.0.0.0%virbr0:67", False),
        ("[::%virbr0]:67",    False),
        ("127.0.0.1:5432",    False),
        ("[::1]:631",         False),
    ])
    def test_scoped_sockets_are_not_world_facing(self, local, expected):
        line = f"tcp LISTEN 0 128 {local} 0.0.0.0:*"
        assert _parse_ss_output(line)[0].is_all_interfaces is expected


class TestLineShapes:
    def test_the_header_row_is_not_a_socket(self):
        header = "Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:PortProcess"
        assert _parse_ss_output(header) == []

    def test_other_netids_are_ignored(self):
        assert _parse_ss_output("raw UNCONN 0 0 0.0.0.0:1 0.0.0.0:*") == []

    def test_a_missing_process_column_is_not_an_error(self):
        """`ss -p` yields no process column without root, which is how BOB runs
        on a good half of its invocations."""
        p = _parse_ss_output("tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*")[0]
        assert (p.port, p.proto, p.process) == (5432, "tcp", "")

    def test_the_first_of_several_processes_is_taken(self):
        line = ('tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* '
                'users:(("nginx",pid=2,fd=6),("nginx",pid=3,fd=6))')
        assert _parse_ss_output(line)[0].process == "nginx"

    def test_duplicate_sockets_collapse(self):
        """Two processes on the same multicast port produce two identical
        rows; the audit should report one socket, not two."""
        line = ("udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:*\n"
                "udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:*")
        assert len(_parse_ss_output(line)) == 1

    def test_the_same_port_on_two_addresses_stays_two_sockets(self):
        line = ("tcp LISTEN 0 128 127.0.0.1:53 0.0.0.0:*\n"
                "tcp LISTEN 0 128 192.168.1.1:53 0.0.0.0:*")
        assert len(_parse_ss_output(line)) == 2
