"""v0.27.0 — the UFW log section reads the rotations it needs, and says what it left out.

Measured on a Mint host (24 October 2026): /var/log/ufw.log held 18 to 24
October and ufw.log.1 the week before. 0.26.1 read ufw.log alone — 3514 blocks
"over 7 day(s)" for a window that reached into ufw.log.1 — and counted no IGMP
line (no port) nor the one [UFW BLOCK] line led by 219 NUL bytes. Read with its
rotations: 7170 blocks over the 7 days, ufw.log and ufw.log.1; over 30 days,
35976, from ufw.log to ufw.log.4.gz. Reading more can bring a brute-force
finding the current file alone did not show: a score change, hence 0.27.0.
"""

from __future__ import annotations

import gzip
import os
from datetime import datetime, timedelta

import pytest

from bob import i18n
from bob.checks import logs as L
from bob.checks.logs import LogsSnapshot, check_logs
from bob.cli import AuditConfig
from bob.display import display_log_results


def _line(ts: datetime, src="203.0.113.9", dpt="22", proto="TCP", spt="40000", extra=""):
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
    port = f" SPT={spt} DPT={dpt}" if dpt is not None else ""
    return (f"{extra}{stamp} host kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src} DST=192.0.2.1 "
            f"PROTO={proto}{port}\n")


def _days_ago(n: float) -> datetime:
    return datetime.now() - timedelta(days=n)


@pytest.fixture
def logdir(tmp_path):
    return tmp_path


def _write(path, lines, gz=False):
    data = "".join(lines).encode()
    if gz:
        with gzip.open(path, "wb") as fh:
            fh.write(data)
    else:
        path.write_bytes(data)


def _snap(logdir, days):
    return LogsSnapshot.from_system(log_days=days, log_path=logdir / "ufw.log")


class TestTheRotationsAreRead:

    def test_until_the_window_is_covered(self, logdir):
        _write(logdir / "ufw.log", [_line(_days_ago(1)), _line(_days_ago(2))])
        _write(logdir / "ufw.log.1", [_line(_days_ago(6)), _line(_days_ago(5))])
        _write(logdir / "ufw.log.2.gz", [_line(_days_ago(12)), _line(_days_ago(11))], gz=True)
        snap = _snap(logdir, 7)
        assert [os.path.basename(f) for f in snap.files_read] == ["ufw.log", "ufw.log.1", "ufw.log.2.gz"]
        assert len(snap.entries) == 4            # day 11 and 12 are outside the 7 days

    def test_no_further_than_needed(self, logdir):
        _write(logdir / "ufw.log", [_line(_days_ago(9)), _line(_days_ago(1))])
        _write(logdir / "ufw.log.1", [_line(_days_ago(12))])
        snap = _snap(logdir, 7)
        assert [os.path.basename(f) for f in snap.files_read] == ["ufw.log"]

    @pytest.mark.parametrize("gz", [False, True])
    def test_a_file_read_from_its_tail_only_ends_the_reading(self, logdir, monkeypatch, gz):
        # Found by the changelog review: a file over the size cap is read from
        # its tail, so its head is missing; reading the older rotation after it
        # left a hole inside a window the period line called covered.
        monkeypatch.setattr(L, "_MAX_LOG_SIZE", 400)
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        name = "ufw.log.1.gz" if gz else "ufw.log.1"
        _write(logdir / name, [_line(_days_ago(5 - i / 10)) for i in range(8)], gz=gz)
        _write(logdir / "ufw.log.2", [_line(_days_ago(6))])
        snap = _snap(logdir, 7)
        assert [os.path.basename(f) for f in snap.files_read] == ["ufw.log", name]

    def test_the_current_file_cut_reads_no_rotation(self, logdir, monkeypatch):
        monkeypatch.setattr(L, "_MAX_LOG_SIZE", 400)
        _write(logdir / "ufw.log", [_line(_days_ago(2 - i / 10)) for i in range(8)])
        _write(logdir / "ufw.log.1", [_line(_days_ago(5))])
        assert [os.path.basename(f) for f in _snap(logdir, 7).files_read] == ["ufw.log"]

    def test_a_compressed_rotation_is_read(self, logdir):
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        _write(logdir / "ufw.log.2.gz", [_line(_days_ago(3))], gz=True)
        assert len(_snap(logdir, 7).entries) == 2

    def test_dateext_names_newest_first(self, logdir):
        _write(logdir / "ufw.log", [])
        for name in ("ufw.log-20261001.gz", "ufw.log-20261017", "ufw.log-20261010.gz"):
            (logdir / name).write_bytes(b"")
        names = [p.name for p in L._rotated_logs(logdir / "ufw.log")]
        assert names == ["ufw.log-20261017", "ufw.log-20261010.gz", "ufw.log-20261001.gz"]

    def test_an_unreadable_rotation_is_named_and_the_window_stops(self, logdir):
        if os.geteuid() == 0:
            pytest.skip("root reads a 0000 file")
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        _write(logdir / "ufw.log.1", [_line(_days_ago(4))])
        _write(logdir / "ufw.log.2.gz", [_line(_days_ago(6))], gz=True)
        (logdir / "ufw.log.1").chmod(0)
        try:
            snap = _snap(logdir, 7)
        finally:
            (logdir / "ufw.log.1").chmod(0o640)
        assert [os.path.basename(f) for f in snap.files_unread] == ["ufw.log.1"]
        assert len(snap.entries) == 1            # ufw.log.2.gz not read past the gap

    def test_a_compressed_rotation_that_expands_too_far_is_refused(self, logdir, monkeypatch):
        monkeypatch.setattr(L, "_MAX_GZ_EXPANDED", 1024)
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        _write(logdir / "ufw.log.2.gz", [_line(_days_ago(3))] * 200, gz=True)
        snap = _snap(logdir, 7)
        assert [os.path.basename(f) for f in snap.files_unread] == ["ufw.log.2.gz"]

    def test_a_brute_force_split_across_the_rotation_is_seen(self, logdir):
        """The score change: attempts in the minute ufw.log was rotated at."""
        t0 = _days_ago(2)
        older = [_line(t0 + timedelta(seconds=i), spt=str(41000 + i)) for i in range(6)]
        newer = [_line(t0 + timedelta(seconds=6 + i), spt=str(42000 + i)) for i in range(6)]
        _write(logdir / "ufw.log", newer)
        _write(logdir / "ufw.log.1", older)
        _, rep = check_logs(_snap(logdir, 7))
        assert rep.brute_hits and rep.brute_hits[0].attempts == 12


class TestWhatIsLeftOutIsTallied:

    def test_the_reasons(self, logdir):
        now = _days_ago(0.1)
        _write(logdir / "ufw.log", [
            _line(now, dpt=None, proto="2"),                       # IGMP: no port
            _line(now, dpt=None, proto="ICMP"),
            "garbage [UFW BLOCK] SRC=1.2.3.4 PROTO=TCP DPT=22\n",  # no timestamp
            _line(now, dpt="70000"),                               # port out of range
            _line(now),                                            # counted
        ])
        snap = _snap(logdir, 7)
        assert len(snap.entries) == 1
        assert snap.skipped == {"no_port": 2, "no_timestamp": 1, "unparsed": 1}

    def test_a_line_led_by_nul_bytes_is_read(self, logdir):
        _write(logdir / "ufw.log", [_line(_days_ago(1), extra="\x00" * 219)])
        snap = _snap(logdir, 7)
        assert len(snap.entries) == 1 and not snap.skipped
        assert L._count_available_days((logdir / "ufw.log").read_text()) == 1


class _Report:
    def __init__(self):
        self.raw = []

    def write_raw(self, text):
        self.raw.append(text)

    def __getattr__(self, name):
        return lambda *a, **k: None


class TestItIsSaid:

    def _run(self, logdir, lang, capsys):
        cfg = AuditConfig()
        cfg.detailed = True
        i18n.init(lang)
        try:
            snap = _snap(logdir, 7)
            res, rep = check_logs(snap, t=i18n.t)
            report = _Report()
            display_log_results(res, snap, rep, cfg, i18n.t, report)
        finally:
            i18n.init(lang="en")
        return capsys.readouterr().out, report.raw

    @pytest.mark.parametrize("lang, period, skipped", [
        ("en", "covered by {d}/ufw.log, {d}/ufw.log.1", "1 [UFW BLOCK] line(s) in the window not counted: 1 without a destination port"),
        ("fr", "couverts par {d}/ufw.log, {d}/ufw.log.1", "1 ligne(s) [UFW BLOCK] de la fenêtre non comptée(s) : 1 sans port de destination"),
    ])
    def test_the_files_and_the_tally(self, logdir, capsys, lang, period, skipped):
        _write(logdir / "ufw.log", [_line(_days_ago(1)), _line(_days_ago(1), dpt=None, proto="2")])
        _write(logdir / "ufw.log.1", [_line(_days_ago(9))])
        out, raw = self._run(logdir, lang, capsys)
        assert period.format(d=logdir) in out and skipped in out
        assert any(period.format(d=logdir) in r for r in raw) and any(skipped in r for r in raw)

    def test_an_unread_rotation_is_said(self, logdir, capsys):
        if os.geteuid() == 0:
            pytest.skip("root reads a 0000 file")
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        _write(logdir / "ufw.log.1", [_line(_days_ago(4))])
        (logdir / "ufw.log.1").chmod(0)
        try:
            out, _ = self._run(logdir, "en", capsys)
        finally:
            (logdir / "ufw.log.1").chmod(0o640)
        assert f"{logdir}/ufw.log.1 could not be read, so the window stops there" in out

    def test_nothing_left_out_says_nothing(self, logdir, capsys):
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        out, _ = self._run(logdir, "en", capsys)
        assert "not counted" not in out


class TestAWindowPartlyReadIsACeiling:
    """Found by the external review: a rotation BOB could not read, or read
    from its tail only, leaves part of the window unread — and a scan or
    repeated attempts there would charge the score. The logs exist; they were
    not all read: not established, a ceiling. A log simply shorter than the
    window is not a gap."""

    def test_an_expanded_too_far_rotation_before_the_window(self, logdir, monkeypatch):
        monkeypatch.setattr(L, "_MAX_GZ_EXPANDED", 1024)
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        _write(logdir / "ufw.log.2.gz", [_line(_days_ago(3))] * 200, gz=True)
        snap = _snap(logdir, 7)
        assert snap.window_gap
        res, _ = check_logs(snap, t=lambda k, **kw: k)
        assert "logs.window_partly_read" in {f.key for f in res.findings}

    def test_a_cut_file_before_the_window(self, logdir, monkeypatch):
        monkeypatch.setattr(L, "_MAX_LOG_SIZE", 400)
        _write(logdir / "ufw.log", [_line(_days_ago(2 - i / 10)) for i in range(8)])
        _write(logdir / "ufw.log.1", [_line(_days_ago(5))])
        snap = _snap(logdir, 7)
        assert snap.window_gap and [os.path.basename(f) for f in snap.files_cut] == ["ufw.log"]

    def test_a_cut_file_that_still_covers_the_window_is_no_gap(self, logdir, monkeypatch):
        monkeypatch.setattr(L, "_MAX_LOG_SIZE", 400)
        _write(logdir / "ufw.log", [_line(_days_ago(9 - i)) for i in range(8)])
        snap = _snap(logdir, 3)
        assert snap.files_cut and not snap.window_gap

    def test_a_log_shorter_than_the_window_is_no_gap(self, logdir):
        _write(logdir / "ufw.log", [_line(_days_ago(1))])
        assert not _snap(logdir, 7).window_gap

    def test_it_bounds_the_score(self):
        from bob.visibility import is_visibility_key
        assert is_visibility_key("logs.window_partly_read")
