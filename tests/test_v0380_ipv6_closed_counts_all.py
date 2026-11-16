"""v0.38.0 — "the IPv6 inbound is closed" counts every listener, avahi too.

Found reading a real 0.37.0 audit (Linux Mint 22.3, 14 November 2026): UFW with
IPV6=no, INPUT at DROP; the finding said "the 1 IPv6 service(s) are
unreachable — 22/tcp" while `ss -tulnp` also showed avahi-daemon on
[::]:5353. The internal processes (avahi, the stub resolver, dnsmasq…) are left
out of the listener list so BOB never tells anyone to open them; the same list
was reused to say what is closed. The verdict was right (DROP takes avahi too),
the count was not.
"""

from __future__ import annotations

from bob.checks import ipv6 as ipv6_mod
from bob.checks.ipv6 import IPv6Snapshot, check_ipv6
from bob import i18n


def _t(key, **kw):
    return key + " " + " ".join(f"{k}={v}" for k, v in sorted(kw.items()))

#: The two IPv6 wildcard lines of the real audit's `ss -tulnp`.
_SS = (
    'udp   UNCONN 0      0                [::]:5353          [::]:*    users:(("avahi-daemon",pid=1566,fd=13))\n'
    'tcp   LISTEN 0      4096             [::]:22            [::]:*    users:(("sshd",pid=2507,fd=4),("systemd",pid=1,fd=306))\n'
)


def test_internal_listeners_are_kept_apart_not_dropped():
    assert ipv6_mod._extract_ipv6_listeners(_SS) == {"22/tcp"}
    assert ipv6_mod._extract_ipv6_listeners(_SS, include_internal=True) == {"22/tcp", "5353/udp"}


def _blocked(internal):
    snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False,
                        ipv6_listeners=["22/tcp"], ipv6_internal_listeners=internal,
                        has_global_ipv6=True, ufw_present=True, ip6_input_policy="DROP",
                        ip6_input_rules=["-A INPUT -i lo -j ACCEPT"])
    return next(f for f in check_ipv6(snap, ufw_active=True, t=_t).findings if f.key == "ipv6.ufw_v6_off_blocked")


def test_closed_counts_avahi_too():
    f = _blocked(["5353/udp"])
    assert "count=2" in f.message
    assert "5353/udp" in f.detail and "22/tcp" in f.detail


def test_without_internal_listeners_nothing_changes():
    f = _blocked([])
    assert "count=1" in f.message and "5353" not in f.detail


def test_the_rendered_text_says_two():
    i18n.init("en")
    try:
        snap = IPv6Snapshot(kernel_ipv6_enabled=True, ufw_ipv6_enabled=False,
                            ipv6_listeners=["22/tcp"], ipv6_internal_listeners=["5353/udp"],
                            has_global_ipv6=True, ufw_present=True, ip6_input_policy="DROP",
                            ip6_input_rules=["-A INPUT -i lo -j ACCEPT"])
        f = next(f for f in check_ipv6(snap, ufw_active=True, t=i18n.t).findings if f.key == "ipv6.ufw_v6_off_blocked")
    finally:
        i18n.init(lang="en")
    assert "2 IPv6" in f.message or " 2 " in f.message, f.message
    assert "22/tcp, 5353/udp" in f.detail, f.detail


def test_the_snapshot_keeps_them(monkeypatch):
    class _R:
        ok, stdout, stderr, returncode = True, _SS, "", 0
    monkeypatch.setattr(ipv6_mod, "_read_kernel_ipv6", lambda: (True, True))
    monkeypatch.setattr(ipv6_mod, "_read_global_ipv6", lambda: False)
    monkeypatch.setattr(ipv6_mod, "_read_ufw_ipv6", lambda: True)
    monkeypatch.setattr(ipv6_mod, "run_result", lambda *a, **k: _R())
    monkeypatch.setattr(ipv6_mod, "_run", lambda *a, **k: "")
    monkeypatch.setattr(ipv6_mod._ufw, "read_app_profiles", lambda: {})
    snap = IPv6Snapshot.from_system()
    assert (snap.ipv6_listeners, snap.ipv6_internal_listeners) == (["22/tcp"], ["5353/udp"])
