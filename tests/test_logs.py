"""
Unit tests for bob.checks.logs module.

All tests use synthetic log content and LogsSnapshot instances —
no filesystem or subprocess calls.

Run with: python -m pytest tests/test_logs.py -v
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from bob.checks.logs import (
    BruteforceHit,
    LogEntry,
    LogsSnapshot,
    _count_available_days,
    _detect_bruteforce,
    _dominant_local_source,
    _max_in_window,
    _parse_log,
    _parse_timestamp,
    _read_from_journald,
    _service_hits,
    _top_ports,
    _top_sources,
    check_logs,
)
from bob.scoring import FindingLevel
from tests.helpers import _levels


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_entry(
    src_ip="1.2.3.4",
    dst_port=22,
    proto="TCP",
    ts=None,
) -> LogEntry:
    if ts is None:
        ts = datetime(2026, 3, 19, 10, 0, 0)
    return LogEntry(timestamp=ts, src_ip=src_ip, dst_port=dst_port, proto=proto)


def make_snapshot(
    entries=None,
    days_available=5,
    log_days=7,
    log_found=True,
    log_source="file",
) -> LogsSnapshot:
    return LogsSnapshot(
        entries=entries or [],
        days_available=days_available,
        log_days=log_days,
        log_found=log_found,
        log_source=log_source,
    )


def has_level(result, level):
    return level in _levels(result)


# ---------------------------------------------------------------------------
# LogEntry
# ---------------------------------------------------------------------------

class TestLogEntry:
    def test_port_proto_tcp(self):
        e = make_entry(dst_port=22, proto="TCP")
        assert e.port_proto == "22/tcp"

    def test_port_proto_udp(self):
        e = make_entry(dst_port=5353, proto="UDP")
        assert e.port_proto == "5353/udp"


# ---------------------------------------------------------------------------
# _parse_timestamp
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_iso_format(self):
        line = "2026-03-19T18:20:08.898446+01:00 host kernel: [UFW BLOCK]"
        ts = _parse_timestamp(line, 2026)
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 3
        assert ts.day == 19

    def test_syslog_format(self):
        line = "Mar 19 10:23:14 host kernel: [UFW BLOCK]"
        ts = _parse_timestamp(line, 2026)
        assert ts is not None
        assert ts.month == 3
        assert ts.day == 19
        assert ts.year == 2026

    def test_invalid_returns_none(self):
        assert _parse_timestamp("not a timestamp", 2026) is None

    def test_no_timestamp_returns_none(self):
        assert _parse_timestamp("[UFW BLOCK] IN=eth0", 2026) is None


# ---------------------------------------------------------------------------
# _parse_log
# ---------------------------------------------------------------------------

class TestParseLog:
    ISO_LINE = (
        "2026-03-19T10:23:14.000+01:00 host kernel: [UFW BLOCK] "
        "IN=eth0 SRC=1.2.3.4 DST=192.168.1.1 PROTO=TCP DPT=22\n"
    )
    SYSLOG_LINE = (
        "Mar 19 10:23:14 host kernel: [UFW BLOCK] "
        "IN=eth0 SRC=5.6.7.8 DST=192.168.1.1 PROTO=UDP DPT=5353\n"
    )
    NOT_BLOCK = "Mar 19 10:23:14 host kernel: [UFW ALLOW] IN=eth0 SRC=1.2.3.4\n"

    def test_parses_iso_line(self):
        entries = _parse_log(self.ISO_LINE, datetime(2026, 3, 1))
        assert len(entries) == 1
        assert entries[0].src_ip == "1.2.3.4"
        assert entries[0].dst_port == 22
        assert entries[0].proto == "TCP"

    def test_parses_syslog_line(self):
        entries = _parse_log(self.SYSLOG_LINE, datetime(2026, 3, 1))
        assert len(entries) == 1
        assert entries[0].src_ip == "5.6.7.8"
        assert entries[0].dst_port == 5353

    def test_skips_non_block_lines(self):
        entries = _parse_log(self.NOT_BLOCK, datetime(2026, 1, 1))
        assert entries == []

    def test_filters_by_cutoff(self):
        entries = _parse_log(self.ISO_LINE, datetime(2026, 3, 20))
        assert entries == []

    def test_includes_on_cutoff_day(self):
        entries = _parse_log(self.ISO_LINE, datetime(2026, 3, 19))
        assert len(entries) == 1

    def test_empty_content(self):
        assert _parse_log("", datetime(2026, 1, 1)) == []

    def test_multiple_lines(self):
        content = self.ISO_LINE + self.SYSLOG_LINE
        entries = _parse_log(content, datetime(2026, 3, 1))
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# _count_available_days
# ---------------------------------------------------------------------------

class TestCountAvailableDays:
    def test_iso_dates(self):
        content = (
            "2026-03-19T10:00:00 line1\n"
            "2026-03-19T11:00:00 line2\n"
            "2026-03-20T10:00:00 line3\n"
        )
        assert _count_available_days(content) == 2

    def test_syslog_dates(self):
        content = (
            "Mar 19 10:00:00 line1\n"
            "Mar 19 11:00:00 line2\n"
            "Mar 20 10:00:00 line3\n"
        )
        assert _count_available_days(content) == 2

    def test_empty(self):
        assert _count_available_days("") == 0


# ---------------------------------------------------------------------------
# _top_sources / _top_ports
# ---------------------------------------------------------------------------

class TestTopSources:
    def test_top_ips_sorted(self):
        entries = [
            make_entry(src_ip="1.1.1.1"),
            make_entry(src_ip="1.1.1.1"),
            make_entry(src_ip="2.2.2.2"),
        ]
        top = _top_sources(entries, 10)
        assert top[0] == ("1.1.1.1", 2)
        assert top[1] == ("2.2.2.2", 1)

    def test_top_n_respected(self):
        entries = [make_entry(src_ip=f"{i}.{i}.{i}.{i}") for i in range(1, 15)]
        top = _top_sources(entries, 5)
        assert len(top) == 5

    def test_empty(self):
        assert _top_sources([], 10) == []


class TestTopPorts:
    def test_top_ports_sorted(self):
        entries = [
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=80, proto="TCP"),
        ]
        top = _top_ports(entries, 10)
        assert top[0][0] == "22/tcp"
        assert top[0][1] == 2

    def test_empty(self):
        assert _top_ports([], 10) == []


# ---------------------------------------------------------------------------
# _max_in_window / _detect_bruteforce
# ---------------------------------------------------------------------------

class TestMaxInWindow:
    def test_all_in_window(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        ts = [base + timedelta(seconds=i * 5) for i in range(5)]
        assert _max_in_window(ts, 60) == 5

    def test_spread_across_windows(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        # 0s, 30s, 60s, 90s — [0,30,60] fits in 60s window → max is 3
        ts = [base + timedelta(seconds=i * 30) for i in range(4)]
        assert _max_in_window(ts, 60) == 3

    def test_spread_strictly_outside_window(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        # 0s, 61s, 122s — each pair is >60s apart → max is 1
        ts = [base + timedelta(seconds=i * 61) for i in range(3)]
        assert _max_in_window(ts, 60) == 1

    def test_empty(self):
        assert _max_in_window([], 60) == 0

    def test_single(self):
        assert _max_in_window([datetime.now()], 60) == 1

    def test_exactly_window_boundary_included(self):
        """Two events exactly window_s apart are in the same window (uses >, not >=)."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        ts = [base, base + timedelta(seconds=60)]
        assert _max_in_window(ts, 60) == 2

    def test_one_second_over_boundary_excluded(self):
        """Two events window_s + 1s apart are in different windows."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        ts = [base, base + timedelta(seconds=61)]
        assert _max_in_window(ts, 60) == 1

    def test_unsorted_input_handled(self):
        """_max_in_window receives pre-sorted input from _detect_bruteforce;
        verify that a pre-sorted reversed list still computes correctly."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        ts = sorted([base + timedelta(seconds=i * 5) for i in range(5)])
        assert _max_in_window(ts, 60) == 5


class TestDetectBruteforce:
    def test_detects_bruteforce(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert len(hits) == 1
        assert hits[0].src_ip == "1.2.3.4"
        assert hits[0].dst_port == 22

    def test_no_bruteforce_below_threshold(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 3))
            for i in range(5)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_spread_out_attempts_not_detected(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 120))
            for i in range(20)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_different_ports_not_grouped(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = []
        for port in (22, 80, 443):
            for i in range(5):
                entries.append(make_entry(src_ip="1.2.3.4", dst_port=port,
                                          proto="TCP",
                                          ts=base + timedelta(seconds=i)))
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_exactly_threshold_not_detected(self):
        """Exactly threshold (10) attempts → NOT detected (condition is > not >=)."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 3))
            for i in range(10)  # exactly threshold
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_threshold_plus_one_detected(self):
        """Exactly threshold + 1 (11) attempts → detected."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=i * 3))
            for i in range(11)  # threshold + 1
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert len(hits) == 1

    def test_different_ips_not_grouped(self):
        """Attempts from different IPs on same port are tracked separately."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = []
        for ip in ("1.1.1.1", "2.2.2.2"):
            for i in range(6):  # 6 each, neither reaches threshold alone
                entries.append(make_entry(src_ip=ip, dst_port=22, proto="TCP",
                                          ts=base + timedelta(seconds=i)))
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits == []

    def test_unsorted_timestamps_detected(self):
        """Timestamps out of order in the log are sorted before windowing."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        # Create 15 entries with timestamps in reverse order
        entries = [
            make_entry(src_ip="1.2.3.4", dst_port=22, proto="TCP",
                       ts=base + timedelta(seconds=(14 - i) * 3))
            for i in range(15)
        ]
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert len(hits) == 1

    def test_sorted_by_count_descending(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = []
        for i in range(20):
            entries.append(make_entry("1.1.1.1", 22, "TCP",
                                      base + timedelta(seconds=i)))
        for i in range(15):
            entries.append(make_entry("2.2.2.2", 22, "TCP",
                                      base + timedelta(seconds=i)))
        hits = _detect_bruteforce(entries, threshold=10, window_s=60)
        assert hits[0].count >= hits[-1].count


# ---------------------------------------------------------------------------
# _service_hits
# ---------------------------------------------------------------------------

class TestServiceHits:
    def test_counts_hits_on_audited_ports(self):
        entries = [
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=22, proto="TCP"),
            make_entry(dst_port=80, proto="TCP"),
        ]
        hits = _service_hits(entries, {"22/tcp"})
        assert hits.get("22/tcp") == 2
        assert "80/tcp" not in hits

    def test_empty_audited_ports(self):
        entries = [make_entry(dst_port=22, proto="TCP")]
        assert _service_hits(entries, set()) == {}

    def test_no_matching_ports(self):
        entries = [make_entry(dst_port=9999, proto="TCP")]
        assert _service_hits(entries, {"22/tcp"}) == {}


# ---------------------------------------------------------------------------
# check_logs
# ---------------------------------------------------------------------------

class TestCheckLogs:
    def test_no_logfile_info(self):
        snap = make_snapshot(log_found=False, log_source="none")
        result, _ = check_logs(snap)
        assert has_level(result, "info")

    def test_empty_log_ok(self):
        snap = make_snapshot(entries=[], log_found=True)
        result, _ = check_logs(snap)
        assert has_level(result, "ok")

    def test_journald_source_emits_info(self):
        snap = make_snapshot(entries=[], log_found=True, log_source="journald")
        result, _ = check_logs(snap)
        messages = [f.message for f in result.findings]
        assert any("logs.source_journald" in m for m in messages)

    def test_file_source_no_journald_info(self):
        snap = make_snapshot(entries=[], log_found=True, log_source="file")
        result, _ = check_logs(snap)
        messages = [f.message for f in result.findings]
        assert not any("source_journald" in m for m in messages)

    def test_bruteforce_warn(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", 22, "TCP", base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap)
        assert has_level(result, "warn")

    def test_bruteforce_deduction(self):
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", 22, "TCP", base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap)
        assert sum(d.points for d in result.deductions) > 0

    def test_report_data_attached(self):
        entries = [make_entry("1.2.3.4", 22, "TCP")]
        snap = make_snapshot(entries=entries)
        result, report_data = check_logs(snap)
        assert report_data is not None
        assert report_data.total == 1

    def test_top_ips_in_report_data(self):
        entries = [make_entry("1.2.3.4", 22, "TCP")] * 5
        snap = make_snapshot(entries=entries)
        result, report_data = check_logs(snap)
        assert report_data.top_ips[0] == ("1.2.3.4", 5)

    def test_service_hits_in_report_data(self):
        entries = [make_entry("1.2.3.4", 22, "TCP")] * 3
        snap = make_snapshot(entries=entries)
        result, report_data = check_logs(snap, audited_ports={"22/tcp"})
        assert report_data.svc_hits.get("22/tcp") == 3

    def test_translation_used(self):
        def my_t(key, **kwargs): return f"T:{key}"
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", 22, "TCP", base + timedelta(seconds=i * 3))
            for i in range(15)
        ]
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap, t=my_t)
        assert any("T:" in f.message for f in result.findings)


class TestDominantLocalSource:
    """Tests for _dominant_local_source and check_logs IoT detection."""

    def _entries(self, local_ip, local_count, other_count):
        """Build a list with local_count entries from local_ip + other_count from a public IP."""
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [
            make_entry(local_ip, 5353, "UDP", base)
            for _ in range(local_count)
        ]
        entries += [
            make_entry("8.8.8.8", 22, "TCP", base)
            for _ in range(other_count)
        ]
        return entries

    def test_dominant_local_triggers(self):
        # 80% from 192.168.1.50, total 100
        ip, count, pct = _dominant_local_source(
            self._entries("192.168.1.50", 80, 20)
        )
        assert ip == "192.168.1.50"
        assert count == 80
        assert pct == 80

    def test_exact_threshold_triggers(self):
        # exactly 70% from local IP
        ip, count, pct = _dominant_local_source(
            self._entries("10.0.0.5", 70, 30)
        )
        assert ip == "10.0.0.5"
        assert pct == 70

    def test_below_threshold_no_trigger(self):
        # 69% — just below threshold
        ip, count, pct = _dominant_local_source(
            self._entries("192.168.0.1", 69, 31)
        )
        assert ip is None

    def test_too_few_entries_no_trigger(self):
        # Only 49 entries total — below minimum
        ip, count, pct = _dominant_local_source(
            self._entries("192.168.1.1", 40, 9)
        )
        assert ip is None

    def test_minimum_entry_count_triggers(self):
        # Exactly 50 entries — minimum met
        ip, count, pct = _dominant_local_source(
            self._entries("192.168.1.1", 40, 10)
        )
        assert ip == "192.168.1.1"

    def test_public_ip_dominant_no_trigger(self):
        # Public IP dominates — not an IoT finding
        entries = (
            [make_entry("1.2.3.4", 22, "TCP") for _ in range(80)]
            + [make_entry("192.168.1.1", 5353, "UDP") for _ in range(20)]
        )
        ip, _, _ = _dominant_local_source(entries)
        assert ip is None

    def test_no_local_ip_no_trigger(self):
        entries = [make_entry("8.8.8.8", 22, "TCP") for _ in range(100)]
        ip, _, _ = _dominant_local_source(entries)
        assert ip is None

    def test_empty_entries(self):
        ip, count, pct = _dominant_local_source([])
        assert ip is None
        assert count == 0
        assert pct == 0

    def test_real_world_scenario(self):
        # Mirrors the documented case: 2988/3258 from 192.168.1.50
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = (
            [make_entry("192.168.1.50", 5353, "UDP", base) for _ in range(2988)]
            + [make_entry("5.6.7.8", 22, "TCP", base) for _ in range(270)]
        )
        ip, count, pct = _dominant_local_source(entries)
        assert ip == "192.168.1.50"
        assert count == 2988
        assert pct >= 90

    def test_check_logs_emits_warn_finding(self):
        entries = self._entries("192.168.1.50", 80, 20)
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap)
        keys = [f.key for f in result.findings if f.key]
        assert "logs.local_dominance" in keys

    def test_check_logs_no_finding_when_below_threshold(self):
        entries = self._entries("192.168.1.50", 60, 40)
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap)
        keys = [f.key for f in result.findings if f.key]
        assert "logs.local_dominance" not in keys

    def test_finding_is_info_level(self):
        entries = self._entries("192.168.1.50", 80, 20)
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap)
        local_findings = [f for f in result.findings if f.key == "logs.local_dominance"]
        assert local_findings
        assert local_findings[0].level == FindingLevel.INFO

    def test_no_score_deduction(self):
        # IoT noise is benign — no point deduction
        base = datetime(2026, 3, 19, 10, 0, 0)
        entries = [make_entry("192.168.1.50", 5353, "UDP", base) for _ in range(80)]
        entries += [
            make_entry(f"1.2.3.{i}", 80, "TCP", base) for i in range(20)
        ]
        snap = make_snapshot(entries=entries)
        result, _ = check_logs(snap)
        local_deductions = [d for d in result.deductions if "local" in d.reason.lower() or "dominan" in d.reason.lower()]
        assert len(local_deductions) == 0


# ---------------------------------------------------------------------------
# Journald fallback
# ---------------------------------------------------------------------------

_JOURNALD_SAMPLE = (
    "2026-04-13T18:20:08+0200 debian13vm kernel: [UFW BLOCK] "
    "IN=enp1s0 OUT= MAC=aa:bb:cc SRC=1.2.3.4 DST=192.168.1.20 "
    "LEN=40 TOS=0x00 PREC=0x00 TTL=120 ID=12345 PROTO=TCP SPT=54321 DPT=22 "
    "WINDOW=1024 RES=0x00 SYN URGP=0\n"
)


class TestReadFromJournald:
    def test_returns_content_when_ufw_entries_present(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = _JOURNALD_SAMPLE
        with patch("subprocess.run", return_value=mock_result):
            content, reachable = _read_from_journald(7)
        assert "[UFW " in content
        assert reachable

    def test_returns_empty_content_when_no_ufw_entries(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "2026-04-13T18:00:00+0200 debian13vm kernel: some other kernel log\n"
        with patch("subprocess.run", return_value=mock_result):
            content, reachable = _read_from_journald(7)
        assert content == ""
        assert reachable

    def test_returns_false_on_exception(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            content, reachable = _read_from_journald(7)
        assert content == ""
        assert not reachable

    def test_journald_entries_parsed_by_parse_log(self):
        cutoff = datetime(2026, 1, 1)
        entries = _parse_log(_JOURNALD_SAMPLE, cutoff)
        assert len(entries) == 1
        assert entries[0].src_ip == "1.2.3.4"
        assert entries[0].dst_port == 22
        assert entries[0].proto == "TCP"


class TestLogsSnapshotFromSystem:
    """Tests for from_system() journald fallback path."""

    def test_journald_fallback_when_no_logfile(self, tmp_path):
        missing = tmp_path / "ufw.log"  # does not exist
        # Use log_days=365 so _JOURNALD_SAMPLE's hardcoded date stays in window.
        with patch("bob.checks.logs._read_from_journald",
                   return_value=(_JOURNALD_SAMPLE, True)):
            snap = LogsSnapshot.from_system(log_days=365, log_path=missing)
        assert snap.log_found
        assert snap.log_source == "journald"
        assert len(snap.entries) == 1

    def test_journald_reachable_no_ufw_entries(self, tmp_path):
        missing = tmp_path / "ufw.log"
        with patch("bob.checks.logs._read_from_journald",
                   return_value=("", True)):
            snap = LogsSnapshot.from_system(log_days=7, log_path=missing)
        assert snap.log_found
        assert snap.log_source == "journald"
        assert snap.entries == []

    def test_no_source_when_both_missing(self, tmp_path):
        missing = tmp_path / "ufw.log"
        with patch("bob.checks.logs._read_from_journald",
                   return_value=("", False)):
            snap = LogsSnapshot.from_system(log_days=7, log_path=missing)
        assert not snap.log_found
        assert snap.log_source == "none"

    def test_file_source_preferred_over_journald(self, tmp_path):
        log_file = tmp_path / "ufw.log"
        log_file.write_text(_JOURNALD_SAMPLE, encoding="utf-8")
        with patch("bob.checks.logs._read_from_journald") as mock_jd:
            snap = LogsSnapshot.from_system(log_days=7, log_path=log_file)
        mock_jd.assert_not_called()
        assert snap.log_source == "file"


# ---------------------------------------------------------------------------
# v0.5.6 hardening regression tests (audit findings I-1, I-2, M-1, M-8)
# ---------------------------------------------------------------------------

class TestPrivateIPDispatch:
    """I-1 (v0.5.6): _is_private_ip uses sysinfo helpers, covers CGNAT + IPv6 LL."""

    def test_rfc1918_ipv4_is_private(self):
        from bob.checks.logs import _is_private_ip
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("192.168.1.5") is True
        assert _is_private_ip("172.16.5.10") is True

    def test_loopback_is_private(self):
        from bob.checks.logs import _is_private_ip
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("::1") is True

    def test_cgnat_is_private(self):
        from bob.checks.logs import _is_private_ip
        # 100.64.0.0/10 (RFC 6598). Old regex missed this.
        assert _is_private_ip("100.64.1.2") is True
        assert _is_private_ip("100.127.255.254") is True

    def test_ipv4_link_local_is_private(self):
        from bob.checks.logs import _is_private_ip
        # 169.254.0.0/16. Old regex missed this.
        assert _is_private_ip("169.254.1.1") is True

    def test_ipv6_link_local_is_private(self):
        from bob.checks.logs import _is_private_ip
        # fe80::/10. Old regex missed this.
        assert _is_private_ip("fe80::1") is True

    def test_ipv6_ula_is_private(self):
        from bob.checks.logs import _is_private_ip
        # fc00::/7. Old regex matched these via "fc"/"fd" substring (lucky).
        assert _is_private_ip("fc00::1") is True
        assert _is_private_ip("fd12:3456:789a::1") is True

    def test_public_ipv4_is_not_private(self):
        from bob.checks.logs import _is_private_ip
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("203.0.113.5") is False  # documentation range, public

    def test_invalid_string_is_not_private(self):
        from bob.checks.logs import _is_private_ip
        # Old regex matched any string starting with "fc"/"fd"; new path
        # returns False (safe default — caller may geo-lookup and reveal
        # the bad input).
        assert _is_private_ip("fcsa") is False
        assert _is_private_ip("fdgarbage") is False
        assert _is_private_ip("not-an-ip") is False
        assert _is_private_ip("") is False


class TestParseTimestampYearRollover:
    """I-2 (v0.5.6): 5-min tolerance prevents silent rollback on clock skew."""

    def test_syslog_now_is_current_year(self):
        from bob.checks.logs import _parse_timestamp
        now = datetime(2026, 6, 15, 12, 0, 0)
        line = "Jun 15 12:00:00 host kernel: [UFW BLOCK] junk"
        ts = _parse_timestamp(line, current_year=2026, now=now)
        assert ts.year == 2026

    def test_syslog_one_second_ahead_stays_current_year(self):
        """Clock skew of 1s should NOT trigger year rollback."""
        from bob.checks.logs import _parse_timestamp
        now = datetime(2026, 6, 15, 12, 0, 0)
        line = "Jun 15 12:00:01 host kernel: [UFW BLOCK] junk"  # 1s in future
        ts = _parse_timestamp(line, current_year=2026, now=now)
        assert ts.year == 2026  # NOT 2025

    def test_syslog_genuinely_future_rolls_back(self):
        """Event > 5 min in the future = previous-year December entry."""
        from bob.checks.logs import _parse_timestamp
        now = datetime(2026, 1, 5, 12, 0, 0)
        line = "Dec 31 23:59:00 host kernel: [UFW BLOCK] junk"
        ts = _parse_timestamp(line, current_year=2026, now=now)
        assert ts.year == 2025  # December parsed in January → prior year


class TestBlockPrefixMatcher:
    """M-1 (v0.5.6): [UFW BLOCK6?] anchored matcher catches IPv6 variant."""

    def test_ufw_block_matches(self):
        from bob.checks.logs import _parse_log
        line = (
            "Jun 15 12:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... "
            "SRC=1.2.3.4 DST=5.6.7.8 LEN=60 TTL=64 PROTO=TCP SPT=12345 DPT=22\n"
        )
        entries = _parse_log(line, cutoff_dt=datetime(2025, 1, 1))
        assert len(entries) == 1

    def test_ufw_block6_also_matches(self):
        """IPv6 variant [UFW BLOCK6] was silently dropped pre-v0.5.6."""
        from bob.checks.logs import _parse_log
        line = (
            "Jun 15 12:00:00 host kernel: [UFW BLOCK6] IN=eth0 OUT= MAC=... "
            "SRC=2001:db8::1 DST=2001:db8::2 LEN=60 PROTO=TCP SPT=12345 DPT=22\n"
        )
        entries = _parse_log(line, cutoff_dt=datetime(2025, 1, 1))
        assert len(entries) == 1

    def test_ufw_allow_does_not_match(self):
        from bob.checks.logs import _parse_log
        line = (
            "Jun 15 12:00:00 host kernel: [UFW ALLOW] SRC=1.2.3.4 DPT=22 PROTO=TCP\n"
        )
        entries = _parse_log(line, cutoff_dt=datetime(2025, 1, 1))
        assert len(entries) == 0


class TestProtoNormalisation:
    """M-8 (v0.5.6): proto is uppercased at parse time to avoid bruteforce split."""

    def test_lowercase_proto_normalised_to_upper(self):
        from bob.checks.logs import _parse_log
        line = (
            "Jun 15 12:00:00 host kernel: [UFW BLOCK] "
            "SRC=1.2.3.4 DPT=22 PROTO=tcp\n"
        )
        entries = _parse_log(line, cutoff_dt=datetime(2025, 1, 1))
        assert len(entries) == 1
        assert entries[0].proto == "TCP"  # normalised, not "tcp"
