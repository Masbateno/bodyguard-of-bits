"""v0.38.0 — a risk card for a service that does not run says so.

The card ("Risk context — CRITICAL • LAN", exposure, threat) is shown for a
high-risk service that is installed but not running, on purpose: a dormant
danger. Found reading a real 0.37.0 audit (Linux Mint 22.3, 14 November 2026):
Telnet was "CRITICAL" while systemd had skipped it and nothing listened — the
card itself did not say. Its level line now carries "not running", on screen
and in the report; a running service's card is unchanged.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.display import display_risk_context


class _Report:
    def __init__(self):
        self.findings = []

    def write_finding(self, *args, **kwargs):
        self.findings.append(" ".join(str(a) for a in args))


@pytest.mark.parametrize("lang, words", [("en", "not running"), ("fr", "ne tourne pas")])
def test_a_card_for_a_service_that_does_not_run_says_so(lang, words, capsys):
    i18n.init(lang)
    try:
        report = _Report()
        display_risk_context("Telnet Server", lang, i18n.t, report, is_local=True, running=False)
        out = capsys.readouterr().out
    finally:
        i18n.init(lang="en")
    assert words in out and words in report.findings[0]


def test_a_running_service_card_is_unchanged(capsys):
    i18n.init("en")
    report = _Report()
    display_risk_context("Telnet Server", "en", i18n.t, report, is_local=True)
    out = capsys.readouterr().out
    assert "not running" not in out and "not running" not in report.findings[0]


def test_the_audit_passes_the_service_state():
    import inspect
    from bob import runner
    src = inspect.getsource(runner)
    assert "quiet=config.quiet, running=snap.is_active)" in src
