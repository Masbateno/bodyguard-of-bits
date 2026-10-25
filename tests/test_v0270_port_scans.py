"""v0.27.0 — a port scan: one source across many ports.

BOB recognised repeated attempts on one port, never one source across many.
Measured on a Mint host (24 October 2026), UFW at its default LOGLEVEL=low: a
real TCP scan of 300 ports from a libvirt VM left a burst of 10 distinct ports
in 3 seconds, then one every 20 seconds — UFW's log limit, a burst of ten then
three a minute. Over the host's 30 days of real logs, no other source reached 6
distinct ports in a minute or 13 in ten minutes (the busiest, a TV box), once
the late replies from Cloudflare and Meta on 443 to ephemeral ports were left
out. Decided by the user: a local source is reported (INFO), a public one
weighs like a repeated public attempt (WARN −1).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from bob import i18n
from bob.checks import logs as L
from bob.checks.logs import LogEntry, LogsSnapshot, check_logs
from bob.cli import AuditConfig
from bob.display import display_log_results
from bob.scoring import FindingLevel

T0 = datetime.now() - timedelta(hours=2)


def _e(src, port, s, proto="TCP", spt=40000):
    return LogEntry(timestamp=T0 + timedelta(seconds=s), src_ip=src, dst_port=port, proto=proto, src_port=spt)


def _measured_scan(src):
    """The VM's scan as UFW logged it: 10 ports in 3 s, then one every 20 s."""
    burst = [_e(src, p, p * 0.3, spt=50000 + p) for p in range(1, 11)]
    trickle = [_e(src, 70 + i * 67, 21 + i * 20, spt=51000 + i) for i in range(8)]
    return burst + trickle


def _result(entries):
    snap = LogsSnapshot(entries=entries, days_available=7, log_days=7)
    return check_logs(snap, t=lambda k, **kw: k)


def _keys(entries):
    res, _ = _result(entries)
    return {f.key: f for f in res.findings if f.key.startswith("logs.port_scan")}


class TestTheScan:

    def test_the_measured_scan_from_a_public_source_weighs(self):
        res, _ = _result(_measured_scan("203.0.113.7"))
        f = next(x for x in res.findings if x.key == "logs.port_scan_public")
        assert f.level == FindingLevel.WARN
        assert sum(d.points for d in res.deductions) == 1

    def test_from_the_local_network_no_point_moves(self):
        res, _ = _result(_measured_scan("192.168.122.210"))
        assert not res.deductions

    def test_from_the_local_network_it_is_reported(self):
        f = _keys(_measured_scan("192.168.122.210"))["logs.port_scan_local"]
        assert f.level == FindingLevel.INFO

    def test_a_slow_scan_at_ufws_rate_is_seen(self):
        """Three a minute, the most LOGLEVEL=low writes once its burst is spent."""
        slow = [_e("203.0.113.8", 1000 + i, i * 20, spt=52000 + i) for i in range(25)]
        assert "logs.port_scan_public" in _keys(slow)

    def test_exactly_at_the_thresholds(self):
        assert "logs.port_scan_public" in _keys([_e("203.0.113.9", 1000 + i, i * 6) for i in range(10)])
        assert "logs.port_scan_public" in _keys([_e("203.0.113.9", 1000 + i, i * 24) for i in range(25)])

    @pytest.mark.parametrize("entries", [
        [_e("203.0.113.9", 1000 + i, i * 6) for i in range(9)],             # 9 in a minute
        [_e("203.0.113.9", 1000 + i, i * 24) for i in range(24)],           # 24 in ten
    ])
    def test_below_the_thresholds_nothing(self, entries):
        assert not _keys(entries)

    def test_late_replies_are_not_a_scan(self):
        """Measured: a CDN on 443 to 41 distinct ephemeral ports of this host."""
        # A documentation address (RFC 5737) stands for the CDN measured on the host.
        replies = [_e("198.51.100.82", 40000 + i * 97, i * 2, spt=443) for i in range(41)]
        assert not _keys(replies)

    def test_the_tv_box_profile_is_not_a_scan(self):
        """Measured: at most 4 distinct ports in a minute, 13 in ten."""
        tv = [_e("192.168.1.50", 30000 + i, i * 45, proto="UDP", spt=5000) for i in range(13)]
        assert not _keys(tv)


class _Report:
    def __getattr__(self, name):
        return lambda *a, **k: None


class TestOnePointPerSource:
    """Decided by the user after the review: a public source that both scans and
    repeats attempts on one port costs one point; both findings are said."""

    @staticmethod
    def _repeats(src):
        return [_e(src, 22, 400 + i * 2, spt=52000 + i) for i in range(12)]

    def test_scan_and_repeats_from_one_source(self):
        res, _ = _result(_measured_scan("203.0.113.7") + self._repeats("203.0.113.7"))
        keys = [f.key for f in res.findings]
        assert "logs.port_scan_public" in keys and "logs.blocked_repeat_public" in keys
        assert sum(d.points for d in res.deductions) == 1

    def test_two_sources_two_points(self):
        res, _ = _result(_measured_scan("203.0.113.7") + self._repeats("198.51.100.4"))
        assert sum(d.points for d in res.deductions) == 2


class TestItIsSaid:

    def _out(self, entries, lang, capsys):
        i18n.init(lang)
        try:
            snap = LogsSnapshot(entries=entries, days_available=7, log_days=7)
            res, rep = check_logs(snap, t=i18n.t)
            display_log_results(res, snap, rep, AuditConfig(), i18n.t, _Report())
        finally:
            i18n.init(lang="en")
        return capsys.readouterr().out

    @pytest.mark.parametrize("lang, words", [("en", "a port scan, all of it dropped"),
                                             ("fr", "un balayage de ports, entièrement rejeté")])
    def test_a_public_scan_is_printed_and_the_verdict_says_so(self, capsys, lang, words):
        out = self._out(_measured_scan("203.0.113.7"), lang, capsys)
        assert words in out and ("Suspicious activity" in out or "Activité suspecte" in out)

    @pytest.mark.parametrize("lang, words", [("en", "a port scan from the local network is reported below"),
                                             ("fr", "un balayage de ports depuis le réseau local est signalé ci-dessous")])
    def test_a_local_scan_is_printed_and_not_called_no_pattern(self, capsys, lang, words):
        out = self._out(_measured_scan("192.168.122.210"), lang, capsys)
        assert words in out and "no recognised attack pattern" not in out and "aucun motif d'attaque" not in out
        assert "192.168.122.210" in out

    def test_it_has_its_explain_and_cis_reference(self):
        from bob.cis_refs import get_cis_ref
        from bob.explain import EXPLAIN_KEYS
        assert "logs.port_scan_public" in EXPLAIN_KEYS and get_cis_ref("logs.port_scan_public")
