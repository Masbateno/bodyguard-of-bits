"""v0.25.0 — chrony says whether it is in sync; BOB reads what it says.

Without timedatectl (an OpenRC host) the sync state came from ``chronyc
tracking``, and any output counted as "synchronised". Measured on Alpine 3.22:
chrony pointed at an unreachable server printed "Leap status : Not
synchronised", and BOB said "NTP time synchronisation active (chronyd)" — OK.
The command for an unsynchronised clock was ``timedatectl set-ntp true`` there
too, on a host with no timedatectl.
"""

from __future__ import annotations

import pytest

from bob.checks import ntp
from bob.checks._run import CommandResult
from bob.checks.ntp import NtpSnapshot, check_ntp
from bob.scoring import FindingLevel

#: ``chronyc tracking`` shaped output; the two "Leap status" lines are the ones
#: measured on Alpine 3.22, the lines above them are illustrative.
_SYNCED = """Reference ID    : D8EF2300 (time.cloudflare.com)
Stratum         : 4
Ref time (UTC)  : Tue Oct 13 15:02:11 2026
System time     : 0.000012553 seconds fast of NTP time
Leap status     : Normal
"""
_UNSYNCED = """Reference ID    : 00000000 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan 01 00:00:00 1970
System time     : 0.000000000 seconds fast of NTP time
Leap status     : Not synchronised
"""


@pytest.fixture
def chronyc(monkeypatch):
    monkeypatch.setattr(ntp, "_command_exists", lambda c: c == "chronyc")

    def answer(out, ok=True):
        monkeypatch.setattr(ntp, "run_result", lambda *a, **k: CommandResult(out, ok))
    return answer


class TestTheLeapStatus:
    def test_in_sync(self, chronyc):
        chronyc(_SYNCED)
        assert ntp._check_sync_fallback("chronyd") is True

    def test_not_in_sync(self, chronyc):
        chronyc(_UNSYNCED)
        assert ntp._check_sync_fallback("chronyd") is False

    @pytest.mark.parametrize("out, ok", [("", True), ("506 Cannot talk to daemon\n", False),
                                         ("Reference ID : 0\n", True)])
    def test_no_readable_answer_is_unknown(self, chronyc, out, ok):
        chronyc(out, ok)
        assert ntp._check_sync_fallback("chronyd") is None


class TestTheFix:
    def test_systemd_gets_timedatectl(self):
        r = check_ntp(NtpSnapshot(ntp_enabled=True, ntp_synchronized=False, timedatectl_ok=True))
        assert r.findings[0].cmd == "sudo timedatectl set-ntp true"

    def test_no_timedatectl_no_command(self):
        r = check_ntp(NtpSnapshot(ntp_enabled=True, ntp_synchronized=False, ntp_service="chronyd"))
        f = r.findings[0]
        assert f.key == "ntp.not_synchronized" and f.level == FindingLevel.WARN
        assert not f.cmd
