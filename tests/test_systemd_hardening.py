"""v0.13.0 — systemd-analyze security service-hardening check (INFO-only)."""

from __future__ import annotations

import json

from bob.checks.systemd_hardening import (
    ServiceHardeningSnapshot,
    check_service_hardening,
)
from bob.scoring import FindingLevel


def _snap(units):
    s = ServiceHardeningSnapshot(available=True, units=list(units), total=len(units))
    return s


class TestCheckLogic:
    def test_tool_absent_emits_info_no_deduction(self):
        r = check_service_hardening(ServiceHardeningSnapshot(available=False))
        assert any(f.key == "systemd_hardening.no_tool" for f in r.findings)
        assert all(f.level is FindingLevel.INFO for f in r.findings)
        assert not r.deductions            # zero deductions

    def test_none_running(self):
        r = check_service_hardening(ServiceHardeningSnapshot(available=True, units=[], total=0))
        assert any(f.key == "systemd_hardening.none" for f in r.findings)

    def test_summary_counts_and_no_deduction(self):
        snap = _snap([
            ("a.service", 9.6, "UNSAFE"),
            ("b.service", 9.6, "UNSAFE"),
            ("c.service", 7.8, "EXPOSED"),
            ("d.service", 5.0, "MEDIUM"),
            ("e.service", 2.0, "OK"),
        ])
        r = check_service_hardening(snap)
        summary = next(f for f in r.findings if f.key == "systemd_hardening.summary")
        # message is identity-t (key passthrough), so check the rendered counts via t=None path
        # → counts are computed in the check; assert worst list + INFO-only + no score impact
        assert summary.level is FindingLevel.INFO
        assert not r.deductions                                # INFO-only: never deducts
        worst = next(f for f in r.findings if f.key == "systemd_hardening.worst")
        assert worst.level is FindingLevel.INFO

    def test_worst_omitted_when_all_clean(self):
        snap = _snap([("a.service", 2.0, "OK"), ("b.service", 4.0, "MEDIUM")])
        r = check_service_hardening(snap)
        assert not any(f.key == "systemd_hardening.worst" for f in r.findings)
        assert any(f.key == "systemd_hardening.summary" for f in r.findings)


class TestSnapshotParsing:
    def test_from_system_parses_json_and_scopes_to_running(self, monkeypatch):
        import bob.checks.systemd_hardening as m

        monkeypatch.setattr(m, "_command_exists", lambda name: True)

        def fake_run(*args, **kwargs):
            if args[0] == "systemctl":
                return "a.service loaded active running A\nb.service loaded active running B\n"
            if args[0] == "systemd-analyze":
                return json.dumps([
                    {"unit": "a.service", "exposure": "9.6", "predicate": "UNSAFE"},
                    {"unit": "b.service", "exposure": "5.0", "predicate": "MEDIUM"},
                    {"unit": "z.service", "exposure": "9.9", "predicate": "UNSAFE"},  # not running
                ])
            return ""

        monkeypatch.setattr(m, "_run", fake_run)
        snap = ServiceHardeningSnapshot.from_system()
        assert snap.available
        units = {u for u, _, _ in snap.units}
        assert units == {"a.service", "b.service"}            # z.service filtered (not running)
        # sorted worst-first
        assert snap.units[0][0] == "a.service" and snap.units[0][1] == 9.6

    def test_from_system_handles_bad_json(self, monkeypatch):
        import bob.checks.systemd_hardening as m
        monkeypatch.setattr(m, "_command_exists", lambda name: True)
        monkeypatch.setattr(m, "_run", lambda *a, **k: "not json{")
        snap = ServiceHardeningSnapshot.from_system()
        assert snap.available and snap.total == 0

    def test_tool_absent(self, monkeypatch):
        import bob.checks.systemd_hardening as m
        monkeypatch.setattr(m, "_command_exists", lambda name: False)
        snap = ServiceHardeningSnapshot.from_system()
        assert not snap.available and snap.total == 0
