"""
v0.15.0 — a failed security service was invisible to the check that exists to
report failed security services.

`systemctl list-units` prefixes a unit systemd considers "not ok" with a status
glyph, which shifts every column by one. Which glyph depends on the locale:
`●` under UTF-8, `*` under the `LC_ALL=C` environment `_run` uses by default, so
BOB's captures carry the asterisk. 27 units on the development host are printed
this way.

`services_state` read `line.split()[0]` as the unit name and `[2]` as the active
state. On a bulleted line that is `"*"` and `"loaded"`:

    * auditd.service  loaded failed failed Security Auditing Service
      unit = "*"          (not in SECURITY_SERVICES -> skipped)
      state = "loaded"    (not in ("inactive", "failed") -> skipped)

An enabled-but-failed security service is exactly the finding this check
produces, and exactly the case systemd marks with the glyph. The check could not
see its own subject.

`systemd_hardening._running_services` had the same read. `socket_units` and
`systemd_timers` were already immune — the first scans tokens for the `.socket`
suffix and even documents the glyph, the second matches by regex. So the tool
knew about this and handled it in two parsers out of four.
"""

from __future__ import annotations

import pytest

import bob.checks.services_state as ss
from bob.checks._run import strip_unit_glyph
from bob.checks.systemd_hardening import _running_services

_FAILED = "auditd.service   loaded failed failed Security Auditing Service"
_RUNNING = "auditd.service   loaded active running Security Auditing Service"


class TestStripUnitGlyph:
    @pytest.mark.parametrize("glyph", ["*", "●"])
    def test_both_locale_glyphs_are_removed(self, glyph):
        assert strip_unit_glyph(f"{glyph} {_FAILED}") == _FAILED

    def test_an_indented_glyph_is_still_removed(self):
        assert strip_unit_glyph(f"   * {_FAILED}") == _FAILED

    @pytest.mark.parametrize("line", [
        _FAILED,
        f"  {_RUNNING}",
        "",
        "*broken-no-space",
    ])
    def test_anything_else_is_returned_untouched(self, line):
        assert strip_unit_glyph(line) == line

    def test_a_glyph_alone_does_not_crash(self):
        strip_unit_glyph("*")
        strip_unit_glyph("●")


class TestServicesStateSeesFailedUnits:
    @pytest.fixture
    def collect(self, monkeypatch):
        def _run(list_units_output: str):
            calls = {"n": 0}

            def fake(*args, **kwargs):
                calls["n"] += 1
                if "list-unit-files" in args:
                    return "auditd.service enabled enabled\n"
                if "list-units" in args:
                    return list_units_output
                return ""
            monkeypatch.setattr(ss, "_run", fake)
            monkeypatch.setattr(ss, "_command_exists", lambda n: True)
            return ss.ServicesStateSnapshot.from_system()
        return _run

    @pytest.mark.parametrize("prefix", ["* ", "● ", "  ", ""])
    def test_a_failed_enabled_service_is_reported_whatever_the_prefix(
            self, collect, prefix):
        snap = collect(prefix + _FAILED + "\n")
        assert "auditd" in snap.enabled_inactive, \
            f"a failed service prefixed {prefix!r} was invisible to the check"

    @pytest.mark.parametrize("prefix", ["* ", "  "])
    def test_a_running_service_is_not_reported(self, collect, prefix):
        snap = collect(prefix + _RUNNING + "\n")
        assert snap.enabled_inactive == []


class TestRunningServicesScoping:
    def test_a_glyphed_running_unit_is_still_counted(self, monkeypatch):
        import bob.checks.systemd_hardening as sh
        monkeypatch.setattr(
            sh, "_run",
            lambda *a, **k: "* odd.service   loaded active running Odd\n"
                            "  fine.service  loaded active running Fine\n")
        assert _running_services() == {"odd.service", "fine.service"}
