"""
v0.15.0 — every established connection was dropped, and a security check with
it.

`NetworkContextSnapshot` runs `ss -tnp state established`. When ss is given a
state filter it already knows the state, so it **omits the State column**:

    Recv-Q Send-Q  Local Address:Port   Peer Address:Port  Process
    0      0       192.168.1.10:56692   104.18.39.21:443   users:(("brave",…

The parser read Local at a fixed index 3, which is the *peer*, and the peer at
index 4, which is the process column. `_split_addr_port` rejects
`users:(("brave",…))`, so the line was skipped — every line, always. Measured on
this host: ss reported 32 established connections and the snapshot reported 0.

That is not a wrong verdict, it is a dead check. `network_context` flags an
established connection to an external IP on a sensitive port, with a 2-point
deduction, and it could not fire. The JSON `connections_count`, the top-remote-IP
list and the summary display were all zeroed the same way.

The two layouts are told apart by the fact that a state keyword is never numeric
and Recv-Q always is — no guessing, and the State-present form (`ss -tn`, and
the example in the function's own docstring) keeps working.
"""

from __future__ import annotations

import subprocess

import pytest

import bob.checks.network_context as nc
from bob.checks.network_context import _parse_connections

_NO_STATE = (
    "Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process\n"
    '0      0       192.168.1.10:56692  104.18.39.21:443  users:(("brave",pid=166519,fd=108))\n'
    '0      0       192.168.1.10:59176  157.240.196.17:443 users:(("brave",pid=166519,fd=64))\n'
)

_WITH_STATE = (
    "State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process\n"
    'ESTAB  0      0       192.168.1.42:52345  142.250.74.14:443 users:(("chrome",pid=1,fd=2))\n'
)


class TestTheStatelessLayout:
    """What `ss -tnp state established` actually prints."""

    def test_connections_are_no_longer_dropped(self):
        assert len(_parse_connections(_NO_STATE)) == 2

    def test_local_and_peer_are_not_swapped(self):
        c = _parse_connections(_NO_STATE)[0]
        assert (c.local_addr, c.local_port) == ("192.168.1.10", 56692)
        assert (c.remote_addr, c.remote_port) == ("104.18.39.21", 443)

    def test_the_process_is_read(self):
        assert _parse_connections(_NO_STATE)[0].process == "brave"

    def test_the_header_is_not_parsed_as_a_connection(self):
        assert len(_parse_connections(_NO_STATE.splitlines()[0])) == 0


class TestTheStatefulLayout:
    """`ss -tn` without a filter, and the example in the docstring."""

    def test_a_leading_state_keyword_shifts_the_columns(self):
        c = _parse_connections(_WITH_STATE)[0]
        assert (c.local_addr, c.local_port) == ("192.168.1.42", 52345)
        assert (c.remote_addr, c.remote_port) == ("142.250.74.14", 443)
        assert c.process == "chrome"

    def test_its_header_is_skipped_too(self):
        assert len(_parse_connections(_WITH_STATE)) == 1


class TestWithoutAProcessColumn:
    """`ss` yields no process column without the privilege to read it."""

    def test_a_connection_is_still_parsed(self):
        body = "0      0       10.0.0.1:1234  93.184.216.34:443\n"
        c = _parse_connections(body)
        assert len(c) == 1
        assert c[0].process == ""


def _as_ss_column(addr: str, port: int) -> str:
    """Rebuild the `address:port` form `ss` prints.

    v0.15.2 strips the brackets from an IPv6 literal: keeping them made every
    IPv6 peer fail `_is_private_or_loopback`, `[::1]` included, so a local
    PostgreSQL connection over loopback was reported as an external exposure.
    Comparing a parsed address against the raw column therefore has to put the
    brackets back.
    """
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


class TestTheIPv6ColumnForm:
    """Deterministic cover for the shape the live test only meets by luck.

    `ss` brackets an IPv6 literal. Whether the live check below exercises that
    at all depends on the machine happening to hold an IPv6 connection while
    the suite runs — it did on CI and not on the development host, which is how
    a change to the address grammar passed seventeen local runs and failed on
    push.
    """

    def test_a_mapped_ipv4_address_keeps_its_column_alignment(self):
        body = ("0 0 [::ffff:10.1.0.153]:53284 [::ffff:93.184.216.34]:443\n")
        parsed = _parse_connections(body)
        assert len(parsed) == 1
        conn = parsed[0]
        assert conn.local_port == 53284
        assert conn.remote_port == 443
        assert _as_ss_column(conn.local_addr, conn.local_port) == "[::ffff:10.1.0.153]:53284"
        assert _as_ss_column(conn.remote_addr, conn.remote_port) == "[::ffff:93.184.216.34]:443"

    def test_the_brackets_are_not_part_of_the_address(self):
        parsed = _parse_connections("0 0 [::1]:52344 [::1]:5432\n")
        assert parsed[0].remote_addr == "::1"

    def test_an_ipv4_column_is_unchanged(self):
        parsed = _parse_connections("0 0 10.0.0.1:1234 93.184.216.34:443\n")
        conn = parsed[0]
        assert _as_ss_column(conn.local_addr, conn.local_port) == "10.0.0.1:1234"


class TestAgainstTheLiveCommand:
    @pytest.mark.skipif(
        subprocess.run(["which", "ss"], capture_output=True).returncode != 0,
        reason="ss not installed")
    def test_the_parse_matches_ss_line_for_line(self):
        """The check that would have caught this on day one."""
        out = subprocess.run(["ss", "-tnp", "state", "established"],
                             capture_output=True, text=True).stdout
        rows = [ln for ln in out.splitlines()[1:] if ln.strip()]
        parsed = _parse_connections(out)
        assert len(parsed) == len(rows), \
            f"ss printed {len(rows)} connections, the parser produced {len(parsed)}"
        for conn, line in zip(parsed, rows):
            cols = line.split()
            assert _as_ss_column(conn.local_addr, conn.local_port) == cols[2]
            assert _as_ss_column(conn.remote_addr, conn.remote_port) == cols[3]


class TestTheSensitivePortFindingCanFire:
    """It could not, before: the list it iterates was always empty."""

    def test_an_external_connection_on_a_sensitive_port_is_flagged(self):
        port = sorted(nc._SENSITIVE_REMOTE_PORTS)[0]
        body = f"0 0 192.168.1.10:44444 93.184.216.34:{port}\n"
        snap = nc.NetworkContextSnapshot(
            interfaces=[], connections=_parse_connections(body))
        result = nc.check_network_context(snap)
        assert "network_context.sensitive_remote" in {f.key for f in result.findings}
        assert sum(d.points for d in result.deductions) > 0
