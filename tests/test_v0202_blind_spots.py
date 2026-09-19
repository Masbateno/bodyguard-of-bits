"""Blind spots found in the v0.20.2 exhaustive CLI pass on a real Fedora host.

Each was a place where output escaped the contract it claimed to honour:
  - #2  --min-level filtered findings routed through display_result, but any
        line printed directly (audit-start banner, "profile: server", GeoIP2
        notice, "score unchanged", …) sailed past the threshold. The fix moves
        the threshold check into the print primitives, so it holds wherever the
        line is printed from.
  - #3  watch mode runs each cycle with config.quiet=True but leaves the output
        module un-quieted (it prints its own summary). display_risk_context was
        not gated on that quiet, so every cycle dumped the full multi-line risk
        block per high/critical service. The gate now lives inside the function,
        screen-only (the report archive still gets the finding).
  - #5  the --output-dir mkdir-failure message was hardcoded English in an
        otherwise fully-localised tool.
"""

from __future__ import annotations

from pathlib import Path

import bob.output as o
from bob import i18n


def _reset_output():
    """Return the output module to its default state (threshold 0, not quiet)."""
    o.init(no_color=True)


# ---------------------------------------------------------------------------
# #2 — --min-level is honoured at the primitive, not only in display_result
# ---------------------------------------------------------------------------

class TestMinLevelAtPrimitive:
    def test_min_level_alert_suppresses_direct_info_and_ok(self, capsys):
        o.init(no_color=True, min_level="alert")
        try:
            o.print_info("a meta info line")
            o.print_ok("a meta ok line")
            o.print_warn("a warn line")
            o.print_alert("a real alert line")
            out = capsys.readouterr().out
        finally:
            _reset_output()
        assert "a meta info line" not in out
        assert "a meta ok line" not in out
        assert "a warn line" not in out
        assert "a real alert line" in out   # alerts always clear the threshold

    def test_min_level_warn_keeps_warn_drops_info(self, capsys):
        o.init(no_color=True, min_level="warn")
        try:
            o.print_info("an info line")
            o.print_warn("a warn line")
            out = capsys.readouterr().out
        finally:
            _reset_output()
        assert "an info line" not in out
        assert "a warn line" in out

    def test_no_threshold_shows_everything(self, capsys):
        _reset_output()
        o.print_info("info shows")
        o.print_ok("ok shows")
        out = capsys.readouterr().out
        assert "info shows" in out
        assert "ok shows" in out


# ---------------------------------------------------------------------------
# #3 — display_risk_context is screen-silent under quiet, archive still written
# ---------------------------------------------------------------------------

class _CapturingReport:
    def __init__(self):
        self.findings = []

    def write_finding(self, *args, **kwargs):
        self.findings.append((args, kwargs))


class TestRiskContextQuiet:
    def test_quiet_silences_screen_but_keeps_the_archive(self, capsys):
        i18n.init("en")
        _reset_output()
        report = _CapturingReport()
        try:
            from bob.display import display_risk_context
            display_risk_context("SSH Server", "en", i18n.t, report, quiet=True)
            out = capsys.readouterr().out
        finally:
            _reset_output()
        assert out.strip() == ""        # screen: nothing
        assert report.findings          # archive: risk context recorded

    def test_not_quiet_prints_the_risk_block(self, capsys):
        i18n.init("en")
        _reset_output()
        report = _CapturingReport()
        try:
            from bob.display import display_risk_context
            display_risk_context("SSH Server", "en", i18n.t, report, quiet=False)
            out = capsys.readouterr().out
        finally:
            _reset_output()
        assert out.strip() != ""        # screen: risk context shown
        assert report.findings          # archive still written


# ---------------------------------------------------------------------------
# #5 — the --output-dir mkdir failure message is localised, not hardcoded
# ---------------------------------------------------------------------------

class TestOutputDirFailureIsLocalised:
    def test_unwritable_output_dir_uses_locale_key_and_falls_back(self, capsys):
        i18n.init("fr")
        try:
            from bob.manage_logs import get_or_prompt_log_dir

            class _Cfg:
                output_dir = "/proc/bob_cannot_create_here"

            class _UC:
                def get(self, *a, **k):
                    return None

            result = get_or_prompt_log_dir(_UC(), _Cfg(), i18n.t)
            out = capsys.readouterr().out
        finally:
            i18n.init("en")
        # French locale text, not the old hardcoded "falling back to cwd".
        assert "Impossible de créer" in out
        assert "falling back to cwd" not in out
        assert result == Path.cwd()
