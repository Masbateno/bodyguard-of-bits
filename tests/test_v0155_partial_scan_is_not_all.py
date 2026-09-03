"""
v0.15.5 — "All SUID binaries are known-safe", over a walk find could not finish.

The aggregation axis: a verdict that quantifies over a set BOB has not seen in
full. ``suid_audit`` runs one ``find`` pass, reads its stdout, and reports
``All SUID binaries are known-safe ({suid_count} SUID, {sgid_count} SGID)``.
The return code was never examined.

**Established against the tool BOB actually invokes.** A first probe measured
``bfs`` — this host has ``find`` aliased in the interactive shell — while
``subprocess.run(["find", ...])`` resolves through PATH to ``/usr/bin/find``,
GNU findutils 4.9.0. Re-run against that one, over a tree with an unreadable
subdirectory:

    rc     = 1
    stdout = the entries it did reach
    stderr = /usr/bin/find: '<dir>': Permission denied

So a partial walk and a complete one are indistinguishable from stdout alone,
and the exit code — the portable signal, not the stderr text, which differs
between implementations — was being discarded.

**The ordinary case is running BOB without sudo.** On this host, unprivileged,
the scan reaches 22 SUID and 13 SGID binaries and cannot enter every directory;
before this change the audit answered "All SUID binaries are known-safe (22
SUID, 13 SGID)" over exactly that walk.

The empty variant is worse and is handled separately: a non-zero exit with no
output at all used to yield "All SUID binaries are known-safe (0 SUID, 0
SGID)", a clean bill of health for a scan that saw nothing.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

import bob.checks.suid_audit as suid_mod
from bob.checks.suid_audit import SuidSnapshot, check_suid_audit


def _keys(result):
    return {f.key for f in result.findings}


@pytest.fixture
def find_answers(monkeypatch):
    """Drive SuidSnapshot.from_system with a scripted find(1).

    os.stat is scripted too: the classifier requires st_uid == 0 for a SUID
    entry, so a file owned by the test user would silently classify as nothing
    and every case would look like an empty scan.
    """
    import stat as stat_mod

    def _apply(returncode, emit_binary):
        stdout = "/usr/bin/sudo\n" if emit_binary else ""
        monkeypatch.setattr(
            suid_mod.subprocess, "run",
            lambda *a, **k: SimpleNamespace(returncode=returncode,
                                            stdout=stdout, stderr=""),
        )
        monkeypatch.setattr(suid_mod.os.path, "isdir", lambda p: True)
        # *args/**kwargs, not a bare (p): pathlib calls os.stat with
        # follow_symlinks=, and a narrower signature made the tests *error*
        # rather than fail — which a mutation count that greps for FAILED
        # reads as "the guard held".
        monkeypatch.setattr(
            suid_mod.os, "stat",
            lambda *a, **k: SimpleNamespace(st_mode=0o104755 | stat_mod.S_ISUID,
                                            st_uid=0),
        )
        return SuidSnapshot.from_system()

    return _apply


class TestTheExitCodeIsRead:

    def test_a_clean_walk_is_neither_partial_nor_skipped(self, find_answers):
        snap = find_answers(0, True)
        assert snap.scan_partial is False
        assert snap.scan_skipped is False

    def test_results_with_a_non_zero_exit_are_a_partial_walk(self, find_answers):
        snap = find_answers(1, True)
        assert snap.scan_partial is True
        assert snap.scan_skipped is False

    def test_no_results_with_a_non_zero_exit_is_a_skipped_scan(self, find_answers):
        """
        The worse variant: this used to report "0 SUID, 0 SGID" as a pass.
        """
        snap = find_answers(1, False)
        assert snap.scan_skipped is True


class TestTheVerdictDoesNotQuantifyOverWhatItDidNotSee:

    def _result(self, partial):
        snap = SuidSnapshot(
            suid_paths=["/usr/bin/sudo"],
            sgid_paths=[],
            unexpected_suid=[],
            unexpected_sgid=[],
            scan_partial=partial,
        )
        return check_suid_audit(snap)

    def test_a_partial_walk_does_not_say_all(self):
        keys = _keys(self._result(True))
        assert "suid_audit.ok_partial" in keys
        assert "suid_audit.ok" not in keys

    def test_a_complete_walk_still_says_all(self):
        """The polarity twin — the ordinary verdict must survive."""
        keys = _keys(self._result(False))
        assert "suid_audit.ok" in keys
        assert "suid_audit.ok_partial" not in keys

    def test_an_unexpected_binary_still_warns_on_a_partial_walk(self):
        """
        Partial cuts the positive claim, never the negative one: something
        found is found, whatever else was missed.
        """
        snap = SuidSnapshot(
            suid_paths=["/opt/vendor/tool"],
            sgid_paths=[],
            unexpected_suid=["/opt/vendor/tool"],
            unexpected_sgid=[],
            scan_partial=True,
        )
        result = check_suid_audit(snap)
        assert "suid_audit.unexpected_suid" in {
            d.key for d in getattr(result, "deductions", [])
        }
