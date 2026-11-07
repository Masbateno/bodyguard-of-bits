"""v0.31.1 — an interface whose name holds a dot (a VLAN, bob.99) is read and fixed.

sysctl writes such a name with "/" in a key (sysctl(8), sysctl.d(5)): the
first separator is a dot, so a slash stands for a dot inside a component.
BOB read ``/proc/sys/`` + key with every dot turned into a slash. Measured on
Kali (7 November 2026, netnsbench/dotted-iface.txt): a VLAN bob.99 at 1 for
send_redirects, conf/all at 0 — the kernel sends redirects there, and 0.31.0
left the VLAN out and read OK; ``sysctl -w net.ipv4.conf.bob.99.…=0`` failed
(".../conf/bob/99/...": no such file), while ``net.ipv4.conf.bob/99.…`` set
it, in a file too. After the fix (dotted-iface-fixed.txt): the VLAN read and
flagged; BOB's command and the native --fix path set it; the key it persists
was applied by udev when the VLAN was recreated.
"""

from __future__ import annotations

from bob import _sysctl_apply as sa
from bob.checks import hardening as h
from bob.checks._run import sysctl_fix_ifaces, sysctl_iface_key, sysctl_path


def test_the_key_writes_the_inner_dot_as_a_slash():
    assert sysctl_iface_key("net.ipv4.conf", "bob.99", "send_redirects") == "net.ipv4.conf.bob/99.send_redirects"
    assert sysctl_iface_key("net.ipv4.conf", "enp3s0", "send_redirects") == "net.ipv4.conf.enp3s0.send_redirects"


def test_the_path_keeps_the_dot_inside_the_name():
    assert str(sysctl_path("net.ipv4.conf.bob/99.send_redirects")) == "/proc/sys/net/ipv4/conf/bob.99/send_redirects"
    assert str(sysctl_path("net.ipv4.conf.all.send_redirects")) == "/proc/sys/net/ipv4/conf/all/send_redirects"


def test_a_vlan_is_read(monkeypatch, tmp_path):
    import pathlib
    conf = tmp_path / "net" / "ipv4" / "conf"
    for name, val in (("all", "0"), ("default", "0"), ("bob", "0"), ("bob.99", "1")):
        (conf / name).mkdir(parents=True)
        (conf / name / "send_redirects").write_text(val + "\n")
    real = pathlib.Path
    monkeypatch.setattr(h, "Path", lambda p, *a: tmp_path if str(p) == "/proc/sys" else real(p, *a))
    monkeypatch.setattr(h, "_IPV4_CONF", conf)
    monkeypatch.setattr(h, "_SYS_NET", tmp_path / "nosys")
    assert h._on(h._effective_by_iface("send_redirects", "or")) == ["bob.99"]


def test_the_fix_names_the_vlan_as_sysctl_does():
    fix = sysctl_fix_ifaces("net.ipv4.conf", "send_redirects", "0", ["bob.99"])
    assert "net.ipv4.conf.bob/99.send_redirects=0" in fix["cmd"]
    assert {"param": "net.ipv4.conf.bob/99.send_redirects=0",
            "conf": "/etc/sysctl.d/99-hardening.conf"} in fix["fix_action"]["params"]


def test_the_native_path_takes_it():
    assert sa.parse_param("net.ipv4.conf.bob/99.send_redirects=0") == ("net.ipv4.conf.bob/99.send_redirects", "0")


def test_a_name_the_shell_would_split_is_quoted():
    """Linux allows ';' in an interface name; the printed command quotes it."""
    fix = sysctl_fix_ifaces("net.ipv4.conf", "send_redirects", "0", ["a;b"])
    assert "'net.ipv4.conf.a;b.send_redirects=0'" in fix["cmd"].split("&&", 1)[0]
