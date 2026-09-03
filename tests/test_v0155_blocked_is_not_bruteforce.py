"""
v0.15.5 — "Bruteforce attempts", from packets the firewall had already dropped.

Closing the over-interpretation angle. A UFW BLOCK is a packet that was
discarded: it never reached a service, so no credential was ever offered.
"Brute force" means repeated credential guessing, and that conclusion is out of
reach of this evidence by construction. The check nonetheless emitted
``Bruteforce attempts from {ip} on {port}``, WARN, −1 point, and its explain
entry called it "a brute-force signature".

**Reproduced on the bench before anything was changed**, with a crafted
/var/log/ufw.log bind-mounted over the real one — three scenarios, 67 lines:

  1. a LAN NAS making *two* TCP connection attempts to 445, each retransmitted
     by the kernel (tcp_syn_retries=6 → SYNs at 0, 1, 3, 7, 15, 31 s, all from
     the same source port) — 12 packets;
  2. an IoT device doing SSDP discovery on 1900/udp — 15 packets;
  3. a sustained external scan of 22/tcp — 40 packets.

BOB reported **three deductions, three points**, calling all three brute force.
Two of them cannot be an authentication attack at all. ``local_dominance``, the
exception hand-carved into this module for exactly this kind of false positive,
did not fire: the local sources were 27 of 67 blocks, under its 70% threshold.

Three things were wrong and each is tested here.

**The threshold counted packets.** A packet is not an attempt. A retransmission
reuses its source port and a new attempt does not, so distinct SPT values in the
window are the attempts — evidence already present in every log line and never
read. Scenario 1 drops from 12 to 2 and stops firing.

**Local and UDP sources cannot be authentication attacks.** A private address is
a device on the operator's own network; UDP has no handshake, and the ports that
dominate these logs (1900 SSDP, 5353 mDNS, 137 NetBIOS) have no credential to
guess. Both are now reported without a deduction.

**Reclassifying nearly made BOB fall silent.** ``display.py`` rendered WARN
findings only, so moving these to INFO removed them from the screen altogether.
Withdrawing a deduction is not a licence to stop mentioning what was measured,
and the render loop now prints both levels.
"""

# v0.16.0 renamed the key to `logs.blocked_repeat_public`, joining the two
# siblings this fix created. v0.15.5 shipped the message change alone because a
# rename breaks baselines, ignore.yml and --explain, and those belong in a
# planned bundle. See bob/_v0160_renames.py.

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from bob.checks.logs import (
    BRUTEFORCE_THRESHOLD,
    BRUTEFORCE_WINDOW_S,
    LogEntry,
    LogsSnapshot,
    _detect_bruteforce,
    _max_attempts_in_window,
    check_logs,
)

_T0 = datetime(2026, 6, 15, 12, 0, 0)


def _entries(src, port, proto, spts, step=1):
    return [
        LogEntry(timestamp=_T0 + timedelta(seconds=i * step), src_ip=src,
                 dst_port=port, proto=proto, src_port=spt)
        for i, spt in enumerate(spts)
    ]


def _keys(result):
    return {f.key for f in result.findings}


def _deducted(result):
    return {d.key for d in getattr(result, "deductions", [])}


class TestAPacketIsNotAnAttempt:

    def test_retransmissions_of_one_connection_count_once(self):
        """Six SYNs from one source port are one attempt, not six."""
        events = [(_T0 + timedelta(seconds=s), 51001) for s in (0, 1, 3, 7, 15, 31)]
        assert _max_attempts_in_window(events, 60) == 1

    def test_distinct_source_ports_count_separately(self):
        events = [(_T0 + timedelta(seconds=i), 33000 + i) for i in range(40)]
        assert _max_attempts_in_window(events, 60) == 40

    def test_lines_without_a_source_port_fall_back_to_packets(self):
        """
        An older UFW, or an ICMP rule, carries no SPT. Answering "no attempts"
        because a field is missing is the substitution this release removed.
        """
        events = [(_T0 + timedelta(seconds=i), None) for i in range(12)]
        assert _max_attempts_in_window(events, 60) == 12

    def test_the_reproduced_nas_no_longer_fires(self):
        """Scenario 1: two attempts, twelve packets, threshold of ten."""
        entries = []
        for spt in (51001, 51002):
            entries += _entries("192.168.1.50", 445, "TCP", [spt] * 6, step=3)
        hits = _detect_bruteforce(entries, BRUTEFORCE_THRESHOLD, BRUTEFORCE_WINDOW_S)
        assert hits == []

    def test_a_real_scan_still_fires(self):
        """The polarity twin: forty separate attempts must still be seen."""
        entries = _entries("203.0.113.7", 22, "TCP", list(range(33000, 33040)))
        hits = _detect_bruteforce(entries, BRUTEFORCE_THRESHOLD, BRUTEFORCE_WINDOW_S)
        assert len(hits) == 1
        assert hits[0].attempts == 40


class TestOnlyWhatCanBeAnAttackIsCharged:

    def _check(self, src, port, proto):
        entries = _entries(src, port, proto, list(range(40000, 40015)))
        snap = LogsSnapshot(entries=entries, log_days=7, days_available=1)
        return check_logs(snap)[0]

    def test_a_public_tcp_source_still_deducts(self):
        result = self._check("203.0.113.7", 22, "TCP")
        assert "logs.blocked_repeat_public" in _deducted(result)

    def test_a_local_source_is_reported_but_not_charged(self):
        result = self._check("192.168.1.77", 445, "TCP")
        assert "logs.blocked_repeat_public" not in _deducted(result)
        assert "logs.blocked_repeat_local" in _keys(result)

    def test_udp_is_reported_but_not_charged(self):
        result = self._check("203.0.113.7", 1900, "UDP")
        assert "logs.blocked_repeat_public" not in _deducted(result)
        assert "logs.blocked_repeat_udp" in _keys(result)

    def test_the_message_states_the_measurement(self, ):
        result = self._check("203.0.113.7", 22, "TCP")
        text = " ".join(f.message for f in result.findings)
        assert "15" in text
        assert "bruteforce" not in text.lower()


class TestReclassifyingDidNotSilenceTheSection:
    """display.py rendered WARN only; INFO would have vanished from the screen."""

    # A first version of this guard asserted that the three key names appeared
    # in display.py, and deleting the `else: print_info(...)` branch left it
    # green — a guard that does not bite is worse than none, because it reports
    # confidence it has not earned. It renders the section for real instead.

    def _render(self, capsys, src, port, proto):
        from types import SimpleNamespace

        from bob.display import display_log_results

        entries = _entries(src, port, proto, list(range(40000, 40015)))
        snap = LogsSnapshot(entries=entries, log_days=7, days_available=1)
        result, report_data = check_logs(snap)
        report = SimpleNamespace(write_raw=lambda *a, **k: None,
                                 write_line=lambda *a, **k: None)
        config = SimpleNamespace(quiet=False, lang="en", offline=True,
                                 detailed=False)
        display_log_results(result, snap, report_data, config,
                            lambda key, **kw: key, report)
        return capsys.readouterr().out

    def test_a_local_source_is_still_printed(self, capsys):
        out = self._render(capsys, "192.168.1.77", 445, "TCP")
        assert "logs.blocked_repeat_local" in out, (
            "the finding was moved to INFO and the render loop printed WARN "
            "only, so it vanished from the screen entirely"
        )

    def test_udp_is_still_printed(self, capsys):
        out = self._render(capsys, "203.0.113.7", 1900, "UDP")
        assert "logs.blocked_repeat_udp" in out

    def test_a_charged_hit_is_still_printed(self, capsys):
        out = self._render(capsys, "203.0.113.7", 22, "TCP")
        assert "logs.blocked_repeat_public" in out

    def test_the_verdict_follows_the_charged_hits(self, capsys):
        """A NAS remounting a share used to head the section with "suspicious"."""
        local = self._render(capsys, "192.168.1.77", 445, "TCP")
        assert "logs.verdict_warn" not in local
        assert "logs.verdict_ok" in local
        public = self._render(capsys, "203.0.113.7", 22, "TCP")
        assert "logs.verdict_warn" in public


class TestTheParserKeepsTheSourcePort:

    def test_spt_is_read(self, tmp_path):
        # Recent, because the parser drops anything older than the analysis
        # window — a fixed date in the past silently yields zero entries.
        log = tmp_path / "ufw.log"
        ts = (datetime.now() - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.000+02:00")
        log.write_text(
            f"{ts} h kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.5 "
            f"DST=10.0.0.1 LEN=60 PROTO=TCP SPT=51515 DPT=22 \n"
        )
        snap = LogsSnapshot.from_system(log_path=log)
        assert snap.entries and snap.entries[0].src_port == 51515
