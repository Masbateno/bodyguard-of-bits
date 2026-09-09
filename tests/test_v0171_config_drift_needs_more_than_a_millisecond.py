"""Drift is only drift when systemd's own resolution can show it.

Measured on a Debian 13 VM, v0.17.1 development::

    /etc/ssh/sshd_config   mtime  1788960328.004764624
    systemctl show ssh -p StateChangeTimestamp --value --timestamp=unix
                                  @1788960328

The administrator had edited the file and reloaded sshd — the correct
sequence — and BOB printed:

    ℹ /etc/ssh/sshd_config was modified at 2026-09-09 15:25, after sshd last
      applied its configuration at 2026-09-09 15:25 — the SSH findings below
      describe the file, not the running service

Two identical timestamps, one declared to be after the other, and every SSH
finding below demoted to a statement about a file. The whole difference was
four milliseconds, and it was an artefact: `--timestamp=unix` answers in whole
seconds, `st_mtime` does not, so the systemd side is always the floor of the
real moment and a plain `>` is biased by up to a second — always towards
announcing drift.

`unit_config_applied_at`'s own docstring says why this matters: "A guard that
fires on people doing the right thing gets switched off."
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bob.checks._run import _APPLIED_RESOLUTION, config_drifted

_SRC = Path(__file__).resolve().parent.parent / "bob"


class TestTheMeasuredIncident:
    def test_the_exact_vm_numbers_are_not_drift(self):
        assert config_drifted(1788960328.004764624, 1788960328.0) is False, (
            "four milliseconds of measurement artefact reported as a "
            "configuration drift, on a host where the reload was done right"
        )

    def test_an_edit_a_second_and_a_half_later_still_is(self):
        assert config_drifted(1788960329.5, 1788960328.0) is True

    def test_a_file_older_than_the_reload_is_never_drift(self):
        assert config_drifted(1788960300.0, 1788960328.0) is False

    @pytest.mark.parametrize("gap", [0.0, 0.001, 0.4, 0.999])
    def test_nothing_below_systemd_s_resolution_counts(self, gap):
        assert config_drifted(1788960328.0 + gap, 1788960328.0) is False, (
            f"a gap of {gap}s is inside the second systemd rounded away — it "
            "is not evidence of anything"
        )

    @pytest.mark.parametrize("gap", [1.0, 2.0, 60.0, 3600.0])
    def test_everything_that_clears_it_does(self, gap):
        assert config_drifted(1788960328.0 + gap, 1788960328.0) is True

    def test_the_tolerance_is_the_resolution_and_no_more(self):
        """Not a fudge factor that could grow: it is one systemd second."""
        assert _APPLIED_RESOLUTION == 1.0


class TestBothCallersGoThroughIt:
    """ssh and journald had the same line written twice; now they share one."""

    @pytest.mark.parametrize("rel", [
        "checks/ssh/_snapshot.py",
        "checks/log_rotation.py",
    ])
    def test_no_bare_comparison_survives(self, rel):
        src = (_SRC / rel).read_text(encoding="utf-8")
        assert not re.search(r"newest(_mtime)?\s*>\s*applied", src), (
            f"{rel} compares a float mtime against a whole-second systemd "
            "timestamp directly — the bias this guard exists for"
        )

    @pytest.mark.parametrize("rel", [
        "checks/ssh/_snapshot.py",
        "checks/log_rotation.py",
    ])
    def test_each_one_calls_the_shared_helper(self, rel):
        src = (_SRC / rel).read_text(encoding="utf-8")
        assert "config_drifted(" in src, f"{rel} no longer uses config_drifted"


class TestTheSentenceShowsItsEvidence:
    """A claim that one moment follows another must print both moments."""

    @pytest.mark.parametrize("rel", [
        "checks/ssh/_snapshot.py",
        "checks/log_rotation.py",
    ])
    def test_timestamps_are_rendered_to_the_second(self, rel):
        src = (_SRC / rel).read_text(encoding="utf-8")
        assert '"%Y-%m-%d %H:%M"' not in src, (
            f"{rel} renders drift timestamps to the minute, so a real "
            "thirty-second drift prints as two identical strings and the "
            "sentence reads as a contradiction"
        )
        assert '"%Y-%m-%d %H:%M:%S"' in src
