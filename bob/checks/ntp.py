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

import subprocess
from dataclasses import dataclass

from bob.checks._run import _command_exists, _identity_t, _run
from bob.scoring import CheckResult

# Known NTP service unit names (checked in order)
_NTP_SERVICES = ("systemd-timesyncd", "chronyd", "ntpd", "openntpd", "ntp")


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
    ntp_synchronized: bool = False
    ntp_service:      str  = ""
    timedatectl_ok:   bool = False

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
        svc = _detect_active_service()
        if svc:
            snap.ntp_enabled = True
            snap.ntp_service = svc
            snap.ntp_synchronized = _check_sync_fallback(svc)

        return snap


def _detect_active_service() -> str:
    """Return the name of the first active NTP service unit, or empty string."""
    if not _command_exists("systemctl"):
        return ""
    for svc in _NTP_SERVICES:
        out = _run("systemctl", "is-active", svc)
        if out.strip() == "active":
            return svc
    return ""


def _check_sync_fallback(service: str) -> bool:
    """
    Best-effort sync check when timedatectl is unavailable.

    - chronyc tracking: exit-0 + non-empty output → synced
    - ntpstat: exit-0 → synced
    - systemd-timesyncd: assume synced if active (timedatectl not available)
    """
    if service in ("chronyd",) and _command_exists("chronyc"):
        out = _run("chronyc", "tracking")
        return bool(out.strip())
    if service == "ntpd" and _command_exists("ntpstat"):
        try:
            result = subprocess.run(
                ["ntpstat"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    # systemd-timesyncd active without timedatectl → assume synced
    return True


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_ntp(snapshot: NtpSnapshot, t=None) -> CheckResult:
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

    if snapshot.ntp_enabled and not snapshot.ntp_synchronized:
        result.warn(
            message=_t("ntp.not_synchronized"),
            detail=_t("ntp.not_synchronized_detail"),
            cmd="sudo timedatectl set-ntp true",
            nature="improvement",
            key="ntp.not_synchronized",
        )
        result.add_deduction(
            reason=_t("ntp.not_synchronized_reason"),
            points=1,
            context="local",
            key="ntp.not_synchronized",
        )
        return result

    # Not enabled
    result.warn(
        message=_t("ntp.not_enabled"),
        detail=_t("ntp.not_enabled_detail"),
        cmd="sudo systemctl enable --now systemd-timesyncd",
        nature="improvement",
        key="ntp.not_enabled",
    )
    result.add_deduction(
        reason=_t("ntp.not_enabled_reason"),
        points=1,
        context="local",
        key="ntp.not_enabled",
    )
    return result
