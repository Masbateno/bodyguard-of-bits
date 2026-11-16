"""v0.38.0 — the detailed report says what "repeated attempts" means.

Found reading a real 0.37.0 audit (Linux Mint 22.3, 14 November 2026): the
report said "No repeated blocked connection attempts in the analysed period"
beside 9390 blocks from one LAN address. True by BOB's criterion — more than
BRUTEFORCE_THRESHOLD attempts from one address to one port within
BRUTEFORCE_WINDOW_S seconds; that address hit 2705 different ports — but the
reader could not know it. The title and the "none" line now carry it, read
from the constants so they cannot drift apart.

The first 0.38.0 draft said "at least {threshold}" while the detector tests
``attempts > threshold``: off by one, found re-reading the code for the
documentation. The last test below pins the words to the operator.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from bob import i18n
from bob.checks.logs import BRUTEFORCE_THRESHOLD, BRUTEFORCE_WINDOW_S, LogEntry, LogsSnapshot, check_logs
from bob.cli import AuditConfig
from bob.display import display_log_results


class _Report:
    def __init__(self):
        self.lines = []

    def write_raw(self, line):
        self.lines.append(line)

    def __getattr__(self, name):
        return lambda *a, **k: None


@pytest.mark.parametrize("lang, none_words", [("en", "No address made more than"), ("fr", "Aucune adresse n'a dépassé")])
def test_the_criterion_is_in_the_report(lang, none_words):
    i18n.init(lang)
    try:
        entries = [LogEntry(timestamp=datetime.now(), src_ip="10.0.0.9", dst_port=30000 + i, proto="UDP")
                   for i in range(50)]
        snap = LogsSnapshot(entries=entries, days_available=7, log_days=7, log_found=True, log_source="file")
        res, rep = check_logs(snap, t=i18n.t)
        cfg = AuditConfig()
        cfg.detailed = True
        report = _Report()
        display_log_results(res, snap, rep, cfg, i18n.t, report)
    finally:
        i18n.init(lang="en")
    text = "\n".join(report.lines)
    crit = f"{BRUTEFORCE_THRESHOLD}"
    title = next(line for line in report.lines if line.startswith("--- ") and crit in line and f"{BRUTEFORCE_WINDOW_S} s" in line)
    assert title
    none = next(line for line in report.lines if none_words in line)
    assert crit in none and f"{BRUTEFORCE_WINDOW_S} s" in none, text


@pytest.mark.parametrize("extra, hit", [(0, False), (1, True)])
def test_the_words_match_the_detector(extra, hit):
    from datetime import timedelta
    from bob.checks.logs import _detect_bruteforce
    t0 = datetime(2026, 11, 14, 12, 0, 0)
    n = BRUTEFORCE_THRESHOLD + extra
    entries = [LogEntry(timestamp=t0 + timedelta(seconds=i), src_ip="203.0.113.9", dst_port=22,
                        proto="TCP", src_port=40000 + i) for i in range(n)]
    assert bool(_detect_bruteforce(entries, BRUTEFORCE_THRESHOLD, BRUTEFORCE_WINDOW_S)) is hit
    i18n.init("en")
    assert "more than" in i18n.t("logs.brute_title", threshold=BRUTEFORCE_THRESHOLD, window=BRUTEFORCE_WINDOW_S)
    i18n.init("fr")
    try:
        assert "plus de" in i18n.t("logs.brute_title", threshold=BRUTEFORCE_THRESHOLD, window=BRUTEFORCE_WINDOW_S)
    finally:
        i18n.init(lang="en")
