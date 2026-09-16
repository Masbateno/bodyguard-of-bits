"""A system-derived string rendered outside the Finding choke point must still
be sanitised before it reaches the terminal.

Finding.message / Deduction.reason pass through scoring's sanitiser, but some
display paths print snapshot fields directly. The kernel accepts an interface
name containing raw bytes (`ip link add name $'\x1b[31m…'` succeeds, and an
attacker with CAP_NET_ADMIN — a container, a VPN, a userns veth — can create
one), so display_network_context rendered its ANSI escapes straight into the
interface table. Found by the v0.20.x local stress pass.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from bob import output
from bob.checks.network_context import InterfaceInfo, NetworkContextSnapshot


def _render(snapshot) -> str:
    output.init(no_color=True)
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            from bob.display import display_network_context
            display_network_context(snapshot, lambda k, **kw: k, output)
        return buf.getvalue()
    finally:
        output.init(no_color=False)


def test_interface_name_ansi_does_not_reach_the_terminal():
    hostile = "e\x1b[31m\x1b]0;HIJACK\x07vil\r\x1b[2J"
    snap = NetworkContextSnapshot(
        interfaces=[InterfaceInfo(name=hostile, if_type="other",
                                  is_up=True, address="10.0.0.1/24")],
        connections=[], connections_readable=True,
    )
    out = _render(snap)
    # The security property: no terminal control bytes survive. The OSC payload
    # text (]0;HIJACK) is left as inert printable characters — harmless without
    # its escape — so the name still appears as data, just stripped of control.
    assert "\x1b" not in out, "ANSI escape from an interface name reached the terminal"
    assert "\r" not in out and "\x07" not in out
    assert "vil" in out, "the sanitised name should still be shown as data"


def test_interface_type_and_address_are_also_sanitised():
    snap = NetworkContextSnapshot(
        interfaces=[InterfaceInfo(name="eth0", if_type="ot\x1bher",
                                  is_up=False, address="1.2.3.4\x1b[5m/24")],
        connections=[], connections_readable=True,
    )
    out = _render(snap)
    assert "\x1b" not in out


def test_a_benign_interface_is_unchanged():
    snap = NetworkContextSnapshot(
        interfaces=[InterfaceInfo(name="enp3s0", if_type="ethernet",
                                  is_up=True, address="192.168.1.10/24")],
        connections=[], connections_readable=True,
    )
    out = _render(snap)
    assert "enp3s0" in out and "192.168.1.10/24" in out


def _render_disk(snapshot) -> str:
    output.init(no_color=True)
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            from bob.display import display_disk_partitions
            display_disk_partitions(snapshot, lambda k, **kw: k, output)
        return buf.getvalue()
    finally:
        output.init(no_color=False)


def test_disk_mountpoint_and_device_ansi_do_not_reach_the_terminal():
    """A userns tmpfs an unprivileged user mounts can have an ANSI mountpoint."""
    from bob.checks.disk import DiskSnapshot, PartitionInfo
    snap = DiskSnapshot(partitions=[
        PartitionInfo(mountpoint="/mnt/\x1b[31mevil", device="/dev/sd\x1b[2mx",
                      size_gb=10.0, used_pct=42),
    ])
    out = _render_disk(snap)
    assert "\x1b" not in out, "an ANSI mountpoint/device reached the terminal"
