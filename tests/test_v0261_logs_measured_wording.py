"""v0.26.1 — the UFW log section says what it read and what it measured.

Measured on a Mint host (0.26.0): /var/log/ufw.log held 3 days, ufw.log.1 the
7 before it (some 10 000 blocks in the last week). BOB printed "3 day(s) of logs
available" and "1764 blocked attempt(s) over 7 day(s)". It reads the current
file only — reading the rotated one can change scores and waits for 0.27.0 —
and now says so, and counts over the days it covered.

The same audit called a TV box "likely IoT discovery traffic (mDNS/SSDP/UPnP),
not an attack": 1348 unicast UDP packets to 413 distinct high ports, none to
5353 or 1900. The INFO now gives the protocols and port count, and says
"discovery" only when every port is a discovery port.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from bob import i18n
from bob.checks.logs import LogEntry, LogReportData, LogsSnapshot, check_logs
from bob.cli import AuditConfig
from bob.display import display_log_results


def _e(src, port, proto="UDP"):
    return LogEntry(timestamp=datetime.now(), src_ip=src, dst_port=port, proto=proto)


def _snap(entries, days_available=3):
    return LogsSnapshot(entries=entries, days_available=days_available, log_days=7,
                        log_found=True, log_source="file")


@pytest.mark.parametrize("available, covered", [(3, 3), (0, 7), (10, 7)])
def test_the_days_covered(available, covered):
    rep = LogReportData(log_days=7, days_available=available, total=0, brute_hits=[], top_ips=[],
                        top_ports=[], svc_hits={})
    assert rep.days_covered == covered


class _Report:
    def __getattr__(self, name):
        return lambda *a, **k: None


def test_the_section_says_what_it_read(capsys):
    i18n.init("en")
    snap = _snap([_e("8.8.8.8", 443, "TCP")] * 5)
    res, rep = check_logs(snap, t=i18n.t)
    display_log_results(res, snap, rep, AuditConfig(), i18n.t, _Report())
    out = capsys.readouterr().out
    assert "Requested window: 7 day(s); 3 day(s) covered by /var/log/ufw.log" in out
    assert "over 3 day(s)" in out and "over 7 day(s)" not in out


def _dominance(entries):
    res, _ = check_logs(_snap(entries), t=lambda k, **kw: f"{k}|{kw.get('protos')}|{kw.get('ports')}")
    return next(f.message for f in res.findings if f.key == "logs.local_dominance")


def test_the_tv_box_is_not_called_discovery():
    tv = [_e("192.168.1.50", 30000 + i) for i in range(90)] + [_e("8.8.8.8", 443, "TCP")] * 10
    assert _dominance(tv) == "logs.local_dominance|UDP|90"


def test_discovery_ports_only_are_called_so():
    disc = [_e("192.168.1.20", 5353)] * 50 + [_e("192.168.1.20", 1900)] * 40 + [_e("8.8.8.8", 443, "TCP")] * 10
    assert _dominance(disc) == "logs.local_dominance_discovery|UDP|1900, 5353"


@pytest.mark.parametrize("lang, words", [("en", "does not identify"), ("fr", "n'identifie pas")])
def test_the_texts_render(lang, words):
    i18n.init(lang)
    try:
        text = i18n.t("logs.local_dominance", ip="192.168.1.50", count=1, total=2, pct=50, protos="UDP", ports=3)
        period = i18n.t("logs.period_files", requested=7, days=7, files="/var/log/ufw.log, /var/log/ufw.log.1")
    finally:
        i18n.init(lang="en")
    assert words in text and "UDP" in text and "ufw.log.1" in period


@pytest.mark.parametrize("lang, words", [("en", "conventional discovery ports"), ("fr", "ports conventionnels de découverte")])
def test_discovery_is_said_of_the_ports_not_the_traffic(lang, words):
    """After review: a conventional port does not prove the protocol it carries."""
    i18n.init(lang)
    try:
        text = i18n.t("logs.local_dominance_discovery", ip="192.168.1.20", count=9, total=10, pct=90,
                      ports="1900, 5353", protos="UDP")
    finally:
        i18n.init(lang="en")
    assert words in text and "announcing" not in text and "annoncent" not in text


@pytest.mark.parametrize("lang, words", [("en", "with a destination port"), ("fr", "avec port de destination")])
def test_the_count_says_what_it_counts(lang, words):
    """After review round 15, measured on the Mint host: of 5018 [UFW BLOCK]
    lines, BOB counted 3514 — the 1503 IGMP lines (PROTO=2, no port) are
    left out. "N blocked attempt(s)" read as every block; it says which."""
    from datetime import datetime, timedelta
    from bob.checks import logs as L
    now = datetime.now()
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
    content = (f"{stamp} host kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.7 DST=224.0.0.1 PROTO=2\n"
               f"{stamp} host kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.7 DST=192.0.2.1 PROTO=UDP SPT=5 DPT=50000\n")
    assert len(L._parse_log(content, now - timedelta(days=7))) == 1
    i18n.init(lang)
    try:
        texts = [i18n.t(k, total=3514, days=6) for k in ("logs.verdict_ok", "logs.verdict_warn", "logs.total_blocks")]
    finally:
        i18n.init(lang="en")
    assert all(words in x for x in texts)
