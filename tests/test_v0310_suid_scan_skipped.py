"""
v0.31.0 — a SUID scan that never finished leaves the score a ceiling.

Measured on the real Kali (rotating disk): the ``find`` over the SUID roots
took 55 s with the page cache dropped and 1.5 s warm, for a 30 s budget. Cold —
which is how a cron audit usually starts — the check reported
``suid_audit.scan_skipped`` as a plain INFO, the 15 unexpected SUID binaries
and their −1 vanished, the System Hardening domain went from 5 to 6, and
``unverified`` stayed empty: BOB saw less and the number said nothing.
``suid_audit.ok_partial`` was already a visibility limit; the skipped scan,
which saw nothing at all, was not.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from bob.checks import suid_audit as suid_mod
from bob.checks.suid_audit import SuidSnapshot, check_suid_audit
from bob.scoring import ScoreEngine


def _engine_for(snapshot: SuidSnapshot) -> ScoreEngine:
    engine = ScoreEngine()
    engine.apply(check_suid_audit(snapshot))
    return engine


def _timed_out(monkeypatch) -> SuidSnapshot:
    def _run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 30))
    monkeypatch.setattr(suid_mod.subprocess, "run", _run)
    monkeypatch.setattr(suid_mod.os.path, "isdir", lambda p: True)
    return SuidSnapshot.from_system()


class TestATimedOutScanIsNotAClean:

    def test_the_timeout_is_a_skipped_scan(self, monkeypatch):
        assert _timed_out(monkeypatch).scan_skipped is True

    def test_the_skipped_scan_bounds_the_score(self, monkeypatch):
        engine = _engine_for(_timed_out(monkeypatch))
        assert engine.unverified == ["suid_audit.scan_skipped"]
        assert engine.score_is_upper_bound is True

    def test_a_finished_scan_does_not_bound_it(self, monkeypatch):
        """Polarity twin: a walk that finished with nothing unexpected is a value."""
        monkeypatch.setattr(
            suid_mod.subprocess, "run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        monkeypatch.setattr(suid_mod.os.path, "isdir", lambda p: True)
        snap = SuidSnapshot.from_system()
        assert snap.scan_skipped is False
        engine = _engine_for(snap)
        assert engine.unverified == []
        assert engine.score_is_upper_bound is False
