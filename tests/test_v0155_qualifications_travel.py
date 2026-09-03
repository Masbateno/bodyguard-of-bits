"""
v0.15.5 — a qualification that stayed behind while the finding it qualified travelled.

The fifth axis: composed verdicts. ``correlation.py`` builds findings out of
other findings' keys — six rules, three of them ALERT, the tool's top severity.
A qualification lived only as a sibling entry in a flat list, and ``Finding``
had no field linking one to another, so nothing carried it across.

Demonstrated before the change, on a host whose sshd_config had been hardened
but never reloaded::

    ALERT  corr.root_no_protection
           triggered_by : ['fail2ban.service_inactive', 'ssh.permit_root_login']
           mentions the caveat : False

The same audit had just printed "the findings describe the file, not the
running service", and the composed ALERT stated the host's live posture anyway.

**Three of six rules consume ssh.permit_root_login or ssh.password_auth** —
precisely the keys that caveat qualifies — and all three are ALERT.

**What was checked and found sound, so the fix stays narrow.** ``active`` is
filtered to WARN and ALERT, so an INFO qualification cannot feed a rule: every
caveat in this release that *replaces* a verdict (backup, logs, suid_audit,
ipv6, memory, firmware) needs nothing here. Only a qualification that leaves
its finding charged has to travel, and this release introduced the only two —
three commits earlier. ``corr.password_auth_under_attack`` consumes
``auth_log.brute_force``, which reads real failed logins, not the firewall-drop
counter narrowed earlier in this release.

The other key consumers had the same blindness and are additive now:
``json_output`` and ``webhook`` emit ``qualified_by`` beside ``key``.
``compare`` is deliberately untouched — its ``finding_keys`` list is a baseline
contract, and key identity is the right thing for it to compare.
"""

from __future__ import annotations

import pytest

from bob.correlation import run_correlations
from bob.scoring import CheckResult, FindingLevel


class _Engine:
    def __init__(self, findings):
        self.findings = findings


def _drifted_result():
    r = CheckResult()
    r.info(message="sshd_config is newer than the applied configuration",
           key="ssh.config_newer_than_service")
    mark = len(r.findings)
    r.alert_with_deduction(key="ssh.permit_root_login", message="Root login permitted",
                           reason="root", points=3, nature="improvement")
    r.qualify("ssh.config_newer_than_service", since=mark)
    r.warn_with_deduction(key="fail2ban.service_inactive", message="fail2ban inactive",
                          reason="f2b", points=1, nature="action")
    return r


class TestQualifyMarksWhatTheBlockProduced:

    def test_it_marks_from_the_index_onward(self):
        r = CheckResult()
        r.warn(message="before", key="before")
        mark = len(r.findings)
        r.warn(message="after", key="after")
        r.qualify("q", since=mark)
        by_key = {f.key: f.qualified_by for f in r.findings}
        assert by_key["after"] == ("q",)
        assert by_key["before"] == ()

    def test_the_qualifier_never_qualifies_itself(self):
        """A self-link would recurse through every consumer that follows it."""
        r = CheckResult()
        r.info(message="caveat", key="q")
        r.warn(message="x", key="x")
        r.qualify("q", since=0)
        assert {f.key: f.qualified_by for f in r.findings}["q"] == ()

    def test_marking_twice_does_not_duplicate(self):
        r = CheckResult()
        r.warn(message="x", key="x")
        r.qualify("q")
        r.qualify("q")
        assert r.findings[0].qualified_by == ("q",)


class TestTheCompositionLayerCarriesIt:

    def test_a_correlated_alert_names_the_qualification(self):
        result = run_correlations(_Engine(_drifted_result().findings), lambda k: k)
        assert len(result) == 1
        assert result[0].qualified_by == ["ssh.config_newer_than_service"]

    def test_the_note_itself_travels_not_just_the_key(self):
        """The caveat is a sentence already written for a human."""
        result = run_correlations(_Engine(_drifted_result().findings), lambda k: "BASE")
        assert result[0].message.startswith("BASE — ")
        assert "newer than the applied configuration" in result[0].message

    def test_an_unqualified_correlation_is_unchanged(self):
        """The polarity twin — the ordinary ALERT must not grow a suffix."""
        r = CheckResult()
        r.alert_with_deduction(key="ssh.permit_root_login", message="Root login",
                               reason="root", points=3, nature="improvement")
        r.warn_with_deduction(key="fail2ban.service_inactive", message="inactive",
                              reason="f2b", points=1, nature="action")
        result = run_correlations(_Engine(r.findings), lambda k: "BASE")
        assert result[0].message == "BASE"
        assert result[0].qualified_by == []

    def test_info_still_never_feeds_a_rule(self):
        """
        The design that made this fix narrow. If INFO ever reached `active`,
        every replaced verdict in this release would start composing ALERTs.
        """
        r = CheckResult()
        r.info(message="root login", key="ssh.permit_root_login")
        r.info(message="inactive", key="fail2ban.service_inactive")
        assert run_correlations(_Engine(r.findings), lambda k: k) == []


class TestTheMachineSurfacesExposeIt:

    def test_the_json_sink_serialises_it(self):
        """
        A consumer reading keys alone cannot tell a qualified finding from an
        unqualified one — the same blindness the correlation layer had.
        """
        from types import SimpleNamespace

        from bob.json_output import _populate_v2_full_blocks

        data: dict = {}
        engine = _Engine(_drifted_result().findings)
        empty = SimpleNamespace(ports=[])
        try:
            _populate_v2_full_blocks(data, engine, [], empty, None, None, None, None)
        except AttributeError:
            # The blocks past `findings` need snapshots this test has no reason
            # to build; the findings block is already populated by then.
            pass
        by_key = {f["key"]: f["qualified_by"] for f in data["findings"]}
        assert by_key["ssh.permit_root_login"] == ["ssh.config_newer_than_service"]
        assert by_key["fail2ban.service_inactive"] == []

    def test_the_webhook_sink_serialises_it(self):
        from pathlib import Path

        source = Path("bob/webhook.py").read_text(encoding="utf-8")
        assert '"qualified_by": list(f.qualified_by)' in source, (
            "the webhook payload must carry the field too — a monitoring stack "
            "alerting on keys has to see that the audit qualified one"
        )
