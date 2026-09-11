"""zram swap is compressed RAM — the disk-oriented swappiness advice is inverted.

Measured on a Raspberry Pi Zero W, whose only swap is /dev/zram0: RAM 58%
free, zram 16% used, vm.swappiness=60. BOB 0.18.0 warned:

    ⚠ Swap in use (16%) while 58% of RAM is still free — swappiness=60 is
      too aggressive

and offered `sysctl vm.swappiness=1`. That advice is backwards for zram: it
is a compressed block device in RAM, swapping to it trades CPU for usable
RAM by design, and it benefits from a *high* swappiness. There is no SSD to
wear either — but zram's rotational flag reads 0, so BOB had also mistaken
it for an SSD.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks.memory import MemorySnapshot, check_memory, _is_zram, _detect_swap_on_ssd


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


def _snap(**kw):
    d = dict(mem_total_kb=436000, mem_available_kb=250000,
             swap_total_kb=436220, swap_free_kb=369552, swappiness=60,
             swap_on_ssd=False, swap_on_zram=True, swap_devices=["/dev/zram0"])
    d.update(kw)
    return MemorySnapshot(**d)


def _keys(result):
    return [f.key for f in result.findings]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device,zram", [
    ("/dev/zram0", True), ("/dev/zram12", True),
    ("/dev/sda5", False), ("/dev/nvme0n1p3", False), ("/swapfile", False),
    ("/swap/zram-backup", False),   # a file named zram is not /dev/zramN
    ("/dev/zram0x", False),         # trailing junk is not a device

])
def test_is_zram(device, zram):
    assert _is_zram(device) is zram


def test_zram_is_not_counted_as_an_ssd():
    """zram's rotational flag is 0; it must not read as an SSD to wear out."""
    assert _detect_swap_on_ssd(["/dev/zram0"]) is False


def test_from_system_excludes_zram_before_the_ssd_probe(monkeypatch):
    """Drive the collector: zram must be filtered out of the SSD check, not
    left for _detect_swap_on_ssd to (mis)read as rotational 0 = SSD."""
    import bob.checks.memory as M
    monkeypatch.setattr(M, "_read_meminfo", lambda: (436000, 250000, 436220, 369552))
    monkeypatch.setattr(M, "_read_swappiness", lambda: 60)
    monkeypatch.setattr(M, "_read_swap_devices", lambda: ["/dev/zram0"])
    seen = {}

    def fake_ssd(devices):
        seen["devices"] = list(devices)
        return bool(devices)   # would say True if zram were passed in

    monkeypatch.setattr(M, "_detect_swap_on_ssd", fake_ssd)
    snap = M.MemorySnapshot.from_system()
    assert snap.swap_on_zram is True
    assert seen["devices"] == [], "zram was handed to the SSD probe"
    assert snap.swap_on_ssd is False


# ---------------------------------------------------------------------------
# The Pi case, as rendered
# ---------------------------------------------------------------------------

def test_zram_swap_is_reported_without_a_deduction():
    result = check_memory(_snap(), t=i18n.t)
    assert "memory.swap_zram" in _keys(result)
    assert not result.deductions


def test_no_lower_swappiness_advice_on_zram():
    result = check_memory(_snap(), t=i18n.t)
    assert "memory.swappiness_unjustified" not in _keys(result)
    assert "memory.swappiness_suboptimal" not in _keys(result)
    assert "memory.swappiness_ssd_wear" not in _keys(result)
    for f in result.findings:
        assert "swappiness=1" not in (f.cmd or ""), "the backwards fix on zram"


def test_the_detail_says_the_disk_guidance_is_inverted():
    f = next(f for f in check_memory(_snap(), t=i18n.t).findings
             if f.key == "memory.swap_zram")
    assert "high swappiness" in f.detail
    assert "no SSD wear" in f.detail.lower() or "no ssd wear" in f.detail.lower()


# ---------------------------------------------------------------------------
# Mirrors: a real disk still gets the disk advice
# ---------------------------------------------------------------------------

def test_a_real_ssd_still_gets_the_wear_warning():
    result = check_memory(
        MemorySnapshot(mem_total_kb=8_000_000, mem_available_kb=6_000_000,
                       swap_total_kb=2_000_000, swap_free_kb=1_000_000,
                       swappiness=60, swap_on_ssd=True, swap_on_zram=False,
                       swap_devices=["/dev/nvme0n1p3"]),
        t=i18n.t)
    assert "memory.swappiness_ssd_wear" in _keys(result)
    assert any(d.key == "memory.swappiness_ssd_wear" for d in result.deductions)


def test_unjustified_swap_still_fires_on_a_disk():
    result = check_memory(
        MemorySnapshot(mem_total_kb=8_000_000, mem_available_kb=6_000_000,
                       swap_total_kb=2_000_000, swap_free_kb=1_000_000,
                       swappiness=60, swap_on_ssd=False, swap_on_zram=False,
                       swap_devices=["/dev/sda5"]),
        t=i18n.t)
    assert "memory.swappiness_unjustified" in _keys(result)


def test_zram_alongside_a_real_disk_does_not_short_circuit():
    """Mixed swap: a genuine disk is present, so disk advice still applies."""
    result = check_memory(
        MemorySnapshot(mem_total_kb=8_000_000, mem_available_kb=6_000_000,
                       swap_total_kb=2_000_000, swap_free_kb=1_000_000,
                       swappiness=60, swap_on_ssd=True, swap_on_zram=True,
                       swap_devices=["/dev/zram0", "/dev/nvme0n1p3"]),
        t=i18n.t)
    assert "memory.swap_zram" not in _keys(result), (
        "with a real disk in the mix, the disk guidance is not suppressed"
    )
