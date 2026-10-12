"""v0.24.4 — NTP on an OpenRC host, as measured on Alpine 3.24.2.

Alpine runs BusyBox ``ntpd`` as an OpenRC service (``rc-service ntpd status``:
started; ``NTPD_OPTS="-N -p pool.ntp.org"``; the clock within half a second of
an NTP-synchronised LAN host). BOB 0.24.3 asked only systemctl, so it reported
"NTP time synchronisation is not enabled" — WARN -1 — and offered
``sudo systemctl enable --now systemd-timesyncd`` on a host with no systemd.

BusyBox ntpd has no query tool, so whether the clock is in sync cannot be read
on the host: the fallback used to assume it was. It now says it could not
verify (INFO), which is neither "not enabled" nor "synchronised".
"""

from __future__ import annotations

from unittest.mock import patch

from bob.checks import ntp
from bob.checks.ntp import NtpSnapshot, check_ntp
from tests.helpers import _keys, _t


def _alpine(running=("ntpd",), scripts=("ntpd",)):
    return (
        patch("bob.checks.ntp._command_exists", side_effect=lambda c: c in ("rc-service",)),
        patch("bob.checks.ntp.openrc_available", return_value=True),
        patch("bob.checks.ntp.unit_active_state",
              side_effect=lambda s: "active" if s in running else ("inactive" if s in scripts else None)),
        patch("bob.checks.ntp.path_exists", side_effect=lambda p: p.name in scripts),
    )


def _snap_from(patches):
    with patches[0], patches[1], patches[2], patches[3]:
        return NtpSnapshot.from_system()


class TestTheRunningClientIsSeen:
    def test_busybox_ntpd_under_openrc(self):
        snap = _snap_from(_alpine())
        assert (snap.ntp_enabled, snap.ntp_service, snap.ntp_synchronized) == (True, "ntpd", None)

    def test_it_is_neither_disabled_nor_called_synchronised(self):
        result = check_ntp(_snap_from(_alpine()), t=_t)
        assert "ntp.sync_unknown" in _keys(result)
        assert "ntp.not_enabled" not in _keys(result) and "ntp.synchronized" not in _keys(result)
        assert not result.deductions

    def test_no_tool_no_assumed_sync(self):
        with patch("bob.checks.ntp._command_exists", return_value=False):
            assert ntp._check_sync_fallback("ntpd") is None


class TestTheNotEnabledFix:
    def test_openrc_starts_its_own_client(self):
        snap = _snap_from(_alpine(running=()))
        assert snap.openrc_client == "ntpd" and not snap.ntp_enabled
        with patch("bob.checks._run.openrc_available", return_value=True), \
             patch("bob.checks._run._command_exists", side_effect=lambda c: c != "systemctl"):
            finding = next(f for f in check_ntp(snap, t=_t).findings if f.key == "ntp.not_enabled")
        assert finding.cmd == "sudo rc-update add ntpd default && sudo rc-service ntpd start"

    def test_openrc_without_a_client_gets_no_command(self):
        snap = NtpSnapshot()
        with patch("bob.checks.ntp.openrc_available", return_value=True), \
             patch("bob.checks.ntp._command_exists", return_value=False):
            finding = next(f for f in check_ntp(snap, t=_t).findings if f.key == "ntp.not_enabled")
        assert not finding.cmd

    def test_systemd_keeps_timesyncd(self):
        with patch("bob.checks.ntp.openrc_available", return_value=False):
            finding = next(f for f in check_ntp(NtpSnapshot(), t=_t).findings if f.key == "ntp.not_enabled")
        assert finding.cmd == "sudo systemctl enable --now systemd-timesyncd"


def test_the_rendered_message_names_the_client():
    from bob import i18n
    i18n.init("fr")
    try:
        msg = next(f for f in check_ntp(NtpSnapshot(ntp_enabled=True, ntp_synchronized=None,
                                                    ntp_service="ntpd"), t=i18n.t).findings
                   if f.key == "ntp.sync_unknown").message
    finally:
        i18n.init(lang="en")
    assert "ntpd" in msg and "{" not in msg


def test_an_unverified_clock_bounds_the_score():
    """BusyBox ntpd: an unsynchronised clock would cost 1 point BOB cannot see."""
    from bob.visibility import is_visibility_key
    assert is_visibility_key("ntp.sync_unknown")
