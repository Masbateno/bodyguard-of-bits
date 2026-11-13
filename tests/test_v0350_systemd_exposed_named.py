"""v0.35.0 — every running unit systemd-analyze rates UNSAFE or EXPOSED is named.

Field audit, Mint desktop (12 November 2026): "44 service(s) … 24 UNSAFE,
4 EXPOSED, 16 OK/medium", then five units named, all UNSAFE. The other
nineteen UNSAFE and the four EXPOSED were counted and never named.
"""

from __future__ import annotations

from bob.checks.systemd_hardening import ServiceHardeningSnapshot, check_service_hardening


def _infos(units):
    snap = ServiceHardeningSnapshot(available=True, units=units, total=len(units) + 3)
    return {f.key: f.message for f in check_service_hardening(snap).findings}


def test_the_field_case_names_every_unit():
    units = ([(f"u{i}.service", 9.6, "UNSAFE") for i in range(7)]
             + [("e1.service", 7.4, "EXPOSED"), ("e2.service", 7.1, "EXPOSED")])
    got = _infos(units)
    assert all(f"u{i}.service" in got["systemd_hardening.worst"] for i in range(5))
    assert "u5.service (9.6)" in got["systemd_hardening.more_unsafe"]
    assert "u6.service" in got["systemd_hardening.more_unsafe"]
    assert "e1.service (7.4)" in got["systemd_hardening.exposed_units"]
    assert "e2.service (7.1)" in got["systemd_hardening.exposed_units"]
    assert "u0.service" not in got["systemd_hardening.more_unsafe"]


def test_units_already_in_the_top_five_are_not_repeated():
    units = [("u0.service", 9.6, "UNSAFE"), ("e1.service", 7.4, "EXPOSED")]
    got = _infos(units)
    assert "systemd_hardening.more_unsafe" not in got and "systemd_hardening.exposed_units" not in got


def test_medium_units_are_not_listed():
    units = [(f"u{i}.service", 9.6, "UNSAFE") for i in range(5)] + [("m.service", 5.0, "MEDIUM")]
    got = _infos(units)
    assert "m.service" not in " ".join(got.values())
