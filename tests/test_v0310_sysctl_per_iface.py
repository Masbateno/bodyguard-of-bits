"""v0.31.0 — the redirect and source-route knobs are read as the kernel reads them.

BOB read conf/all alone for send_redirects, accept_redirects (IPv4 and IPv6),
accept_source_route and log_martians, and fixed conf/all alone. Measured on
Ubuntu 26.04 (6 November 2026, phase B, `phaseB/sysctl-roundtrip.txt`):
BOB's send_redirects fix set conf/all to 0, enp3s0 kept 1, and BOB said fixed.
The kernel's rules (include/linux/inetdevice.h and net/ipv6/route.c, Linux
6.18):

| knob | rule |
|---|---|
| send_redirects, log_martians | conf/all OR the interface |
| accept_source_route | conf/all AND the interface |
| accept_redirects (IPv4) | AND on an interface that forwards, OR on one that does not |
| accept_redirects (IPv6) | the interface's own value, none where it forwards; conf/all not read |

So on that Kubernetes node (forwarding on), BOB's −1 "IPv6 redirects
accepted" was false, and on a host that does not forward, conf/all = 0 left an
interface at 1 accepting IPv4 redirects while BOB said OK. Persisting
conf/all and conf/default was measured across a real reboot there: enp3s0
came back at 0 (`phaseB/persist-case-a.txt`).
"""

from __future__ import annotations

import pytest

from bob.checks import hardening as h
from bob.checks._run import sysctl_fix_ifaces
from tests.helpers import _t


def _proc(monkeypatch, values: dict, ifaces=("enp3s0",), v6_ifaces=None):
    """/proc/sys as *values* ({"net.ipv4.conf.enp3s0.send_redirects": True, ...})."""
    class Dir:
        def __init__(self, names):
            self.names = names

        def iterdir(self):
            return [type("E", (), {"name": n})() for n in ["all", "default", "lo", *self.names]]
    monkeypatch.setattr(h, "_IPV4_CONF", Dir(list(ifaces)))
    monkeypatch.setattr(h, "_IPV6_CONF", Dir(list(v6_ifaces if v6_ifaces is not None else ifaces)))
    monkeypatch.setattr(h, "_read_sysctl_bool", lambda key: values.get(key))


def _v4(knob, **by):
    return {f"net.ipv4.conf.{name}.{knob}": on for name, on in by.items()}


def _v6(knob, **by):
    return {f"net.ipv6.conf.{name}.{knob}": on for name, on in by.items()}


class TestTheKernelsRules:

    def test_send_redirects_conf_all_alone_does_not_decide(self, monkeypatch):
        """Measured: conf/all 0, enp3s0 1 — still sends."""
        _proc(monkeypatch, _v4("send_redirects", all=False, default=True, enp3s0=True))
        assert h._effective_by_iface("send_redirects", "or") == {"enp3s0": True, "default": True}

    def test_send_redirects_off_everywhere(self, monkeypatch):
        _proc(monkeypatch, _v4("send_redirects", all=False, default=False, enp3s0=False))
        assert h._on(h._effective_by_iface("send_redirects", "or")) == []

    def test_conf_all_on_turns_every_interface_on(self, monkeypatch):
        _proc(monkeypatch, _v4("send_redirects", all=True, default=False, enp3s0=False))
        assert h._on(h._effective_by_iface("send_redirects", "or")) == ["enp3s0", "default"]

    def test_lo_is_not_an_interface_here(self, monkeypatch):
        _proc(monkeypatch, {**_v4("send_redirects", all=False, default=False, enp3s0=False),
                            "net.ipv4.conf.lo.send_redirects": True})
        assert h._on(h._effective_by_iface("send_redirects", "or")) == []

    @pytest.mark.parametrize("forwards, on", [(True, []), (False, ["enp3s0", "default"])],
                             ids=["forwarding-and", "not-forwarding-or"])
    def test_ipv4_accept_redirects(self, monkeypatch, forwards, on):
        """Measured on the node: all 0, default 1, enp3s0 1, forwarding 1 — not accepted."""
        _proc(monkeypatch, {**_v4("accept_redirects", all=False, default=True, enp3s0=True),
                            **_v4("forwarding", default=forwards, enp3s0=forwards)})
        assert h._on(h._effective_by_iface("accept_redirects", "redirects")) == on

    def test_ipv4_accept_redirects_forwarding_with_conf_all_on(self, monkeypatch):
        _proc(monkeypatch, {**_v4("accept_redirects", all=True, default=False, enp3s0=True),
                            **_v4("forwarding", default=True, enp3s0=True)})
        assert h._on(h._effective_by_iface("accept_redirects", "redirects")) == ["enp3s0"]

    @pytest.mark.parametrize("all_on, own, on", [(False, True, []), (True, True, ["enp3s0"]), (True, False, [])])
    def test_accept_source_route_needs_both(self, monkeypatch, all_on, own, on):
        _proc(monkeypatch, _v4("accept_source_route", all=all_on, default=False, enp3s0=own))
        assert h._on(h._effective_by_iface("accept_source_route", "and")) == on

    @pytest.mark.parametrize("forwards, on", [(True, []), (False, ["enp3s0", "default"])],
                             ids=["forwarding-ignores", "not-forwarding"])
    def test_ipv6_accept_redirects(self, monkeypatch, forwards, on):
        """Measured on the node: enp3s0 1 and forwarding 1 — the kernel ignores redirects."""
        _proc(monkeypatch, {**_v6("accept_redirects", all=True, default=True, enp3s0=True),
                            **_v6("forwarding", default=forwards, enp3s0=forwards)})
        assert h._on(h._effective_by_iface("accept_redirects", "v6", family="ipv6")) == on

    def test_ipv6_conf_all_is_not_read(self, monkeypatch):
        """Measured: setting conf/all to 0 left enp3s0 at 1, and the kernel reads enp3s0."""
        _proc(monkeypatch, {**_v6("accept_redirects", all=False, default=False, enp3s0=True),
                            **_v6("forwarding", default=False, enp3s0=False)})
        assert h._on(h._effective_by_iface("accept_redirects", "v6", family="ipv6")) == ["enp3s0"]

    def test_log_martians_off_where(self, monkeypatch):
        _proc(monkeypatch, _v4("log_martians", all=False, default=False, enp3s0=True))
        by = h._effective_by_iface("log_martians", "or")
        assert h._off(by) == ["default"] and h._all_on(by) is False

    def test_log_martians_conf_all_on_is_enough(self, monkeypatch):
        _proc(monkeypatch, _v4("log_martians", all=True, default=False, enp3s0=False))
        assert h._all_on(h._effective_by_iface("log_martians", "or")) is True

    def test_not_read(self, monkeypatch):
        _proc(monkeypatch, {})
        assert h._effective_by_iface("send_redirects", "or") is None
        assert h._any_on(None) is None and h._all_on(None) is None

    def test_an_interface_gone_while_read_is_left_out(self, monkeypatch):
        _proc(monkeypatch, _v4("send_redirects", all=False, default=False, enp3s0=True), ifaces=("enp3s0", "veth9"))
        assert h._effective_by_iface("send_redirects", "or") == {"enp3s0": True, "default": False}

    def test_an_interface_without_forwarding_read_is_left_out(self, monkeypatch):
        _proc(monkeypatch, {**_v4("accept_redirects", all=False, default=False, enp3s0=True),
                            **_v4("forwarding", default=False)})
        assert h._effective_by_iface("accept_redirects", "redirects") == {"default": False}


class TestTheSnapshot:

    def test_from_system_reads_each_interface(self, monkeypatch):
        """The node as measured: conf/all off, enp3s0 on — enabled, on enp3s0."""
        values = {**_v4("send_redirects", all=False, default=False, enp3s0=True),
                  **_v4("accept_redirects", all=False, default=True, enp3s0=True),
                  **_v4("forwarding", default=True, enp3s0=True),
                  **_v4("accept_source_route", all=False, default=False, enp3s0=False),
                  **_v4("log_martians", all=False, default=False, enp3s0=False),
                  **_v6("accept_redirects", all=True, default=True, enp3s0=True),
                  **_v6("forwarding", default=True, enp3s0=True)}
        _proc(monkeypatch, values)
        monkeypatch.setattr(h, "_effective_rp_filter", lambda: (2, 2, "enp3s0"))
        monkeypatch.setattr(h, "read_sysctl_boot_files", lambda: [])
        snap = h.HardeningSnapshot.from_system()
        assert (snap.send_redirects, snap.send_redirects_where) == (True, ["enp3s0"])
        assert (snap.accept_redirects, snap.accept_redirects_where) == (False, [])
        assert (snap.accept_redirects_v6, snap.accept_redirects_v6_where) == (False, [])
        assert (snap.log_martians, snap.log_martians_off) == (False, ["enp3s0", "default"])
        assert snap.accept_source_route is False


class TestTheFix:

    def test_every_interface_now_conf_all_and_default_kept(self):
        fix = sysctl_fix_ifaces("net.ipv4.conf", "send_redirects", "0", ["enp3s0", "default"])
        assert fix["cmd"].startswith("sudo sysctl -w net.ipv4.conf.all.send_redirects=0 "
                                     "net.ipv4.conf.default.send_redirects=0 net.ipv4.conf.enp3s0.send_redirects=0 && ")
        assert "tee -a /etc/sysctl.d/99-hardening.conf" in fix["cmd"]
        # v0.31.1 — the interface's own value is persisted too.
        assert "net.ipv4.conf.enp3s0.send_redirects=0 | sudo tee" in fix["cmd"].split("&&", 1)[1]
        assert fix["fix_action"]["params"] == [
            {"param": "net.ipv4.conf.all.send_redirects=0", "conf": "/etc/sysctl.d/99-hardening.conf"},
            {"param": "net.ipv4.conf.default.send_redirects=0", "conf": "/etc/sysctl.d/99-hardening.conf"},
            {"param": "net.ipv4.conf.enp3s0.send_redirects=0", "conf": "/etc/sysctl.d/99-hardening.conf"},
        ]

    def test_the_finding_names_the_interfaces_and_fixes_them(self):
        snap = h.HardeningSnapshot(send_redirects=True, send_redirects_where=["enp3s0", "default"])
        f = next(f for f in h.check_hardening(snap, t=_t).findings if f.key == "hardening.send_redirects_enabled")
        assert "net.ipv4.conf.enp3s0.send_redirects=0" in f.cmd
        assert "hardening.where_or" in f.detail

    @pytest.mark.parametrize("field, key, where_key, knob", [
        ("accept_redirects", "hardening.redirects_enabled", "hardening.where_redirects", "net.ipv4.conf.enp3s0.accept_redirects=0"),
        ("accept_redirects_v6", "hardening.accept_redirects_v6_enabled", "hardening.where_v6", "net.ipv6.conf.enp3s0.accept_redirects=0"),
    ])
    def test_the_redirect_findings(self, field, key, where_key, knob):
        snap = h.HardeningSnapshot(**{field: True, f"{field}_where": ["enp3s0"]})
        f = next(f for f in h.check_hardening(snap, t=_t).findings if f.key == key)
        assert knob in f.cmd and where_key in f.detail

    def test_accept_source_route_conf_all_is_enough(self):
        snap = h.HardeningSnapshot(accept_source_route=True, accept_source_route_where=["enp3s0"])
        f = next(f for f in h.check_hardening(snap, t=_t).findings if f.key == "hardening.accept_source_route_enabled")
        assert "net.ipv4.conf.all.accept_source_route=0" in f.cmd and "enp3s0.accept_source_route" not in f.cmd
        assert "hardening.where_and" in f.detail

    def test_log_martians_names_where_not_logged(self):
        snap = h.HardeningSnapshot(log_martians=False, log_martians_off=["enp3s0"])
        f = next(f for f in h.check_hardening(snap, t=_t).findings if f.key == "hardening.log_martians_disabled")
        assert "hardening.where_off_or" in f.detail and "net.ipv4.conf.all.log_martians=1" in f.cmd

    def test_default_is_named_as_the_template(self):
        assert h._where(lambda k, **kw: f"{k}:{kw.get('where', '')}", "hardening.where_or", ["enp3s0", "default"]) \
            == "hardening.where_or:enp3s0, hardening.where_default:"


class TestApplying:

    def test_each_value_set_and_only_conf_all_and_default_persisted(self, monkeypatch, tmp_path):
        from bob import fixes
        from bob import _sysctl_apply as sa
        calls = []

        def apply(param, conf):
            calls.append((param, conf))
            return sa.SysctlResult(True, conf is not None)
        monkeypatch.setattr(sa, "apply_sysctl", apply)
        conf = str(tmp_path / "99-hardening.conf")
        action = {"kind": "sysctl", "params": [{"param": "net.ipv4.conf.all.send_redirects=0", "conf": conf},
                                               {"param": "net.ipv4.conf.enp3s0.send_redirects=0", "conf": ""}]}
        assert fixes._apply_native(action) == ("ok", 0, b"")
        assert calls[1] == ("net.ipv4.conf.enp3s0.send_redirects=0", None)

    def test_the_first_failure_stops(self, monkeypatch, tmp_path):
        from bob import fixes
        from bob import _sysctl_apply as sa
        calls = []

        def apply(param, conf):
            calls.append(param)
            return sa.SysctlResult(False, False, "kernel holds '1'")
        monkeypatch.setattr(sa, "apply_sysctl", apply)
        action = {"kind": "sysctl", "params": [{"param": "a.b=0", "conf": str(tmp_path / "x")},
                                               {"param": "c.d=0", "conf": ""}]}
        assert fixes._apply_native(action) == ("failed", None, b"kernel holds '1'")
        assert calls == ["a.b=0"]

    def test_set_without_persisting(self, monkeypatch, tmp_path):
        from bob import _sysctl_apply as sa
        monkeypatch.setattr(sa.subprocess, "run", lambda *a, **k: type("P", (), {"returncode": 0, "stderr": b""})())
        monkeypatch.setattr(sa, "_read_live", lambda key: "0")
        result = sa.apply_sysctl("net.ipv4.conf.enp3s0.send_redirects=0", None)
        assert result.applied and not result.persisted and not list(tmp_path.iterdir())
