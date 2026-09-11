"""Reverse-path filtering is per interface — conf/all alone lied.

For a packet arriving on interface X the kernel enforces
``max(conf/all/rp_filter, conf/X/rp_filter)``. BOB read conf/all and nothing
else, so on the whole systemd family — which ships ``conf/all = 0`` while
``conf/default = 2`` gives every real interface an effective 2 — it warned
"reverse path filtering disabled" and took a point.

Measured on a Raspberry Pi Zero W (Raspbian 13):

    conf/all/rp_filter      0
    conf/default/rp_filter  2
    conf/wlan0/rp_filter    2      → effective on wlan0 = max(0, 2) = 2 (loose)

BOB 0.18.0 said disabled. wlan0 was filtering.

The security order is strict (1) > loose (2) > off (0) — not the integer
order — so the machine's posture is the weakest interface by that ranking,
which is why a plain min() of the values would be wrong.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import bob.checks.hardening as H
from bob import i18n
from bob.checks.hardening import HardeningSnapshot, check_hardening


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


@pytest.fixture
def proc_conf(monkeypatch):
    """Stand in for /proc/sys/net/ipv4/conf with a given per-interface map."""
    def _install(values: "dict[str, int]"):
        tmp = Path(tempfile.mkdtemp())
        for name, v in values.items():
            (tmp / name).mkdir()
            (tmp / name / "rp_filter").write_text(str(v), encoding="ascii")
        monkeypatch.setattr(H, "_IPV4_CONF", tmp)
        real = H._read_sysctl_int

        def read(key: str):
            if key.startswith("net.ipv4.conf.") and key.endswith(".rp_filter"):
                name = key[len("net.ipv4.conf."):-len(".rp_filter")]
                f = tmp / name / "rp_filter"
                return int(f.read_text()) if f.exists() else None
            return real(key)

        monkeypatch.setattr(H, "_read_sysctl_int", read)
        return tmp
    return _install


# ---------------------------------------------------------------------------
# The collector
# ---------------------------------------------------------------------------

def test_the_pi_config_is_loose_not_disabled(proc_conf):
    proc_conf({"all": 0, "default": 2, "lo": 2, "wlan0": 2})
    posture, all_val, iface = H._effective_rp_filter()
    assert posture == 2, "wlan0's effective max(0, 2) is loose, not off"
    assert all_val == 0
    assert iface == "wlan0"


def test_all_zero_everywhere_is_genuinely_off(proc_conf):
    proc_conf({"all": 0, "default": 0, "eth0": 0})
    posture, _, iface = H._effective_rp_filter()
    assert posture == 0 and iface == "eth0"


def test_conf_all_one_lifts_a_zero_interface_to_strict(proc_conf):
    proc_conf({"all": 1, "default": 1, "eth0": 0})
    assert H._effective_rp_filter()[0] == 1


def test_the_weakest_interface_by_security_wins_not_the_lowest_number(proc_conf):
    """eth0 strict (1), eth1 loose (2): loose is weaker, so the posture is 2."""
    proc_conf({"all": 0, "default": 0, "eth0": 1, "eth1": 2})
    posture, _, iface = H._effective_rp_filter()
    assert posture == 2 and iface == "eth1", (
        "min(1, 2) would pick strict; loose is the weaker guarantee"
    )


def test_loopback_at_zero_does_not_read_as_disabled(proc_conf):
    """lo cannot receive a spoofed packet; it is not counted."""
    proc_conf({"all": 0, "default": 2, "lo": 0})
    assert H._effective_rp_filter()[0] == 2


def test_no_readable_interface_falls_back_to_the_default_template(proc_conf):
    proc_conf({"all": 0, "default": 2})
    posture, all_val, iface = H._effective_rp_filter()
    assert posture == 2 and iface == "", "max(all, default) when no real iface"


def test_an_absent_conf_all_is_not_read_as_a_value(monkeypatch):
    monkeypatch.setattr(H, "_read_sysctl_int", lambda key: None)
    assert H._effective_rp_filter() == (None, None, "")


def test_from_system_computes_the_effective_posture_not_conf_all(proc_conf):
    """Drive the collector, not just the helper: the defect was from_system
    reading conf/all alone, and a helper test leaves that path uncovered.

    from_system reads the other knobs from the real /proc/sys; only the
    rp_filter fields are asserted here.
    """
    proc_conf({"all": 0, "default": 2, "lo": 2, "wlan0": 2})
    snap = HardeningSnapshot.from_system()
    assert snap.rp_filter == 2, "conf/all=0 alone would say disabled"
    assert snap.rp_filter_all == 0
    assert snap.rp_filter_iface == "wlan0"


# ---------------------------------------------------------------------------
# The verdict, as rendered
# ---------------------------------------------------------------------------

def _rp(result):
    return next((f for f in result.findings if f.key.startswith("hardening.rp_filter")), None)


def test_the_pi_posture_renders_as_info_with_no_deduction():
    snap = HardeningSnapshot(rp_filter=2, rp_filter_all=0, rp_filter_iface="wlan0")
    result = check_hardening(snap, t=i18n.t)
    f = _rp(result)
    assert f.key == "hardening.rp_filter_loose"
    assert f.level.name == "INFO"
    assert not any(d.key == "hardening.rp_filter_loose" for d in result.deductions)


def test_the_detail_explains_why_conf_all_zero_is_not_the_verdict():
    snap = HardeningSnapshot(rp_filter=2, rp_filter_all=0, rp_filter_iface="wlan0")
    detail = _rp(check_hardening(snap, t=i18n.t)).detail
    assert "wlan0" in detail
    assert "conf/all" in detail and "0" in detail
    assert "max" in detail


def test_a_genuinely_disabled_stack_still_warns_and_costs():
    snap = HardeningSnapshot(rp_filter=0, rp_filter_all=0, rp_filter_iface="eth0")
    result = check_hardening(snap, t=i18n.t)
    assert _rp(result).key == "hardening.rp_filter_disabled"
    assert any(d.key == "hardening.rp_filter_disabled" for d in result.deductions)


def test_strict_is_still_ok():
    result = check_hardening(
        HardeningSnapshot(rp_filter=1, rp_filter_all=1, rp_filter_iface="eth0"), t=i18n.t)
    assert _rp(result).key == "hardening.rp_filter_ok"
    assert not result.deductions
