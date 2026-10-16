"""
NTP / time synchronisation audit check for BOB (CHECK 28).

Checks whether the system clock is synchronised via NTP.
Unsynchronised or disabled NTP is a WARN finding (-1 pt): time drift
can indicate tampering, breaks TLS certificate validation, corrupts logs,
and causes authentication failures (Kerberos, TOTP, etc.).

Supported NTP services: systemd-timesyncd, chronyd, ntpd, openntpd.

Split into:
  1. NtpSnapshot.from_system() — collects state via timedatectl / systemctl.
  2. check_ntp(snapshot, t)    — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from pathlib import Path

from bob.checks._run import (
    TranslationFunc, _C_LOCALE_ENV, _command_exists, _identity_t, _run, is_unit_active,  # noqa: F401
    openrc_available, path_exists, run_result, service_enable_cmd, unit_active_state,
)
from bob.scoring import CheckResult

# Known NTP service unit names (checked in order)
#: ``chronyc tracking``: "Normal", "Insert second", "Delete second" or
#: "Not synchronised" (chrony's own wording, under LC_ALL=C).
_CHRONY_LEAP = re.compile(r"^Leap status\s*:\s*(.+?)\s*$", re.MULTILINE)
_NTP_SERVICES = ("systemd-timesyncd", "chronyd", "ntpd", "openntpd", "ntp")
#: v0.24.4 — the NTP clients an OpenRC host may ship an init script for, most
#: common first. Alpine's default is BusyBox ``ntpd``.
_OPENRC_NTP = ("chronyd", "ntpd", "openntpd")


@dataclass
class NtpSnapshot:
    """
    State collected from the system about NTP synchronisation.

    Args:
        ntp_enabled:      True if an NTP service is configured and running.
        ntp_synchronized: True if the clock is currently synchronised.
        ntp_service:      Name of the detected NTP service ("systemd-timesyncd", …).
        timedatectl_ok:   True if timedatectl was available and parseable.
    """
    ntp_enabled:      bool = False
    #: None when the client runs but no tool can say whether it is in sync
    #: (BusyBox ntpd has none) — v0.24.4: no longer assumed True.
    ntp_synchronized: "bool | None" = False
    ntp_service:      str  = ""
    timedatectl_ok:   bool = False
    #: v0.24.4 — on an OpenRC host, the NTP client that has an init script
    #: ("" when none, or not OpenRC): what the "not enabled" fix starts.
    openrc_client:    str  = ""

    @classmethod
    def from_system(cls) -> "NtpSnapshot":
        """Collect NTP state from the live system. Never raises."""
        snap = cls()

        # Primary source: timedatectl show (systemd systems)
        if _command_exists("timedatectl"):
            out = _run("timedatectl", "show")
            if out:
                snap.timedatectl_ok = True
                kv: dict[str, str] = {}
                for line in out.splitlines():
                    if "=" in line:
                        k, _, v = line.partition("=")
                        kv[k.strip()] = v.strip()

                snap.ntp_enabled      = kv.get("NTP", "").lower() == "yes"
                snap.ntp_synchronized = kv.get("NTPSynchronized", "").lower() == "yes"

                # Identify which service is active
                if snap.ntp_enabled:
                    snap.ntp_service = _detect_active_service()

                return snap

        # Fallback: check individual service units
        if openrc_available() and not _command_exists("systemctl"):
            snap.openrc_client = next(
                (s for s in _OPENRC_NTP if path_exists(Path(f"/etc/init.d/{s}"))), "")
        svc = _detect_active_service()
        if svc:
            snap.ntp_enabled = True
            snap.ntp_service = svc
            snap.ntp_synchronized = _check_sync_fallback(svc)

        return snap


def _detect_active_service() -> str:
    """Return the name of the first active NTP service, or empty string.

    v0.24.4 — asked through whichever init system answers. Gated on systemctl,
    an Alpine host running BusyBox ntpd (OpenRC "started") was reported "NTP
    time synchronisation is not enabled", WARN -1, with a systemctl fix."""
    systemd = _command_exists("systemctl")
    for svc in _NTP_SERVICES:
        if is_unit_active(svc) if systemd else unit_active_state(svc) == "active":
            return svc
    return ""


def _check_sync_fallback(service: str) -> "bool | None":
    """
    Best-effort sync check when timedatectl is unavailable.

    - chronyc tracking: its "Leap status" line — "Not synchronised" is not in
      sync (v0.25.0: any output used to count as synced; measured on Alpine
      3.22, chrony pointed at an unreachable server printed "Not synchronised"
      and BOB said "NTP time synchronisation active")
    - ntpstat: exit-0 → synced
    - systemd-timesyncd: assume synced if active (timedatectl not available)
    """
    if service in ("chronyd",) and _command_exists("chronyc"):
        res = run_result("chronyc", "tracking")
        leap = _CHRONY_LEAP.search(res.stdout) if res.ok else None
        if leap is None:
            return None                         # no answer we can read
        return leap.group(1) != "Not synchronised"
    if service == "ntpd" and _command_exists("ntpstat"):
        try:
            result = subprocess.run(
                ["ntpstat"], capture_output=True, timeout=5,
                env=_C_LOCALE_ENV,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    # v0.24.4: no tool to ask (BusyBox ntpd, timesyncd without timedatectl).
    # This used to return True — an assumption reported as "synchronised".
    return None


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_ntp(snapshot: NtpSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse NTP snapshot and return findings.

    Findings:
      - Enabled and synchronised:     OK
      - Enabled but not synchronised: WARN −1 pt
      - Not enabled / not detected:   WARN −1 pt
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if snapshot.ntp_enabled and snapshot.ntp_synchronized:
        svc = snapshot.ntp_service or "ntp"
        result.ok(
            message=_t("ntp.synchronized", service=svc),
            key="ntp.synchronized",
        )
        return result

    if snapshot.ntp_enabled and snapshot.ntp_synchronized is None:
        svc = snapshot.ntp_service or "ntp"
        result.info(
            message=_t("ntp.sync_unknown", service=svc),
            key="ntp.sync_unknown",
        )
        return result

    if snapshot.ntp_enabled and not snapshot.ntp_synchronized:
        result.warn_with_deduction(
            key="ntp.not_synchronized",
            message=_t("ntp.not_synchronized"),
            reason=_t("ntp.not_synchronized_reason"),
            points=1,
            detail=_t("ntp.not_synchronized_detail"),
            # timedatectl only where it answered: an OpenRC host has none.
            cmd="sudo timedatectl set-ntp true" if snapshot.timedatectl_ok else None,
            nature="improvement",
        )
        return result

    # Not enabled
    result.warn_with_deduction(
        key="ntp.not_enabled",
        message=_t("ntp.not_enabled"),
        reason=_t("ntp.not_enabled_reason"),
        points=1,
        detail=_t("ntp.not_enabled_detail"),
        cmd=_ntp_enable_cmd(snapshot),
        nature="improvement",
    )
    return result


def _ntp_enable_cmd(snapshot: NtpSnapshot) -> "str | None":
    """Start an NTP client in this host's own init system (v0.24.4): the one
    OpenRC has a script for, or systemd-timesyncd on systemd. An OpenRC host
    with no NTP client script gets no command — install one first."""
    if snapshot.openrc_client:
        return service_enable_cmd(snapshot.openrc_client)
    if openrc_available() and not _command_exists("systemctl"):
        return None
    return "sudo systemctl enable --now systemd-timesyncd"
