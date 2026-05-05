"""
Desktop application detection for BOB (CHECK 19).

Detects known desktop/GUI applications running on the system via the
process list. Findings are INFO-only (no score deduction) — the check
provides visibility, not a security penalty.

Useful on servers where desktop apps (Steam, Discord, Zoom…) would be
unexpected, and on workstations for a complete activity picture.

Split into:
  1. DesktopAppsSnapshot.from_system() — collects data via ps.
  2. check_desktop_apps(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Known desktop applications
# Mapping: process_name (comm, max 15 chars on Linux) → display_name
# Multiple process names can map to the same display_name — deduplicated
# in from_system().
# ---------------------------------------------------------------------------

_KNOWN_APPS: dict[str, str] = {
    # Gaming
    "steam":           "Steam",
    "steamwebhelper":  "Steam",
    # Browsers
    "firefox":         "Firefox",
    "firefox-bin":     "Firefox",        # snap / Ubuntu packaging
    "firefox-esr":     "Firefox",
    "brave-browser":   "Brave Browser",
    "brave":           "Brave Browser",
    "chromium":        "Chromium",
    "chromium-browse": "Chromium",   # "chromium-browser" truncated to 15 chars
    # Communication
    "discord":         "Discord",
    "zoom":            "Zoom",
    "zoom_linux":      "Zoom",
    "teams":           "Microsoft Teams",
    "teams-for-linux": "Microsoft Teams",
    "slack":           "Slack",
    "skypeforlinux":   "Skype",
    "skype":           "Skype",
    "telegram-deskto": "Telegram",   # "telegram-desktop" truncated to 15 chars
    "signal-desktop":  "Signal",
    "element-desktop": "Element (Matrix)",
    "nheko":           "Nheko (Matrix)",
    "fractal":         "Fractal (Matrix)",
    "whatsie":         "Whatsie (WhatsApp)",
    "whatsapp-for-li": "WhatsApp for Linux",  # "whatsapp-for-linux" truncated to 15 chars
    "zapzap":          "ZapZap (WhatsApp)",
    "betterbird":      "Betterbird",
    "betterbird-bin":  "Betterbird",
    "thunderbird":     "Thunderbird",
    # VPN clients
    "expressvpn-daem": "ExpressVPN",   # "expressvpn-daemon" truncated to 15 chars
    "expressvpn-clie": "ExpressVPN",   # "expressvpn-client" truncated to 15 chars
    "expressvpn-ligh": "ExpressVPN",   # "expressvpn-lightway" truncated to 15 chars
    "nordvpnd":        "NordVPN",
    "nordvpn":         "NordVPN",
    "protonvpn-app":   "ProtonVPN",
    "protonvpn":       "ProtonVPN",
    "mullvad-gui":     "Mullvad VPN",
    "mullvad-daemon":  "Mullvad VPN",
    # Development
    "code":            "Visual Studio Code",
    "code-oss":        "VS Code (OSS)",
    "codium":          "VSCodium",
    # Remote access
    "rustdesk":        "RustDesk",
    # Network analysis
    "wireshark":       "Wireshark",
    # Virtualisation
    "virt-manager":    "Virtual Machine Manager",
    # File sync / storage
    "kdrive_client":   "kDrive",
    # Downloads
    "transmission-gt": "Transmission",   # "transmission-gtk" truncated to 15 chars
    # Media / creation
    "obs":             "OBS Studio",
    "obs-studio":      "OBS Studio",
}


@dataclass
class DesktopAppsSnapshot:
    """
    State collected from the system about running desktop applications.

    Args:
        detected: list of (display_name, process_name) for each unique
                  desktop app found in the process list.
    """
    detected: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def from_system(cls) -> "DesktopAppsSnapshot":
        """Scan the process list for known desktop apps. Never raises."""
        snap = cls()
        seen_apps: set[str] = set()

        try:
            out = subprocess.check_output(
                ["ps", "-eo", "comm"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return snap

        for line in out.splitlines():
            proc = line.strip()
            display = _KNOWN_APPS.get(proc.lower())
            if display and display not in seen_apps:
                seen_apps.add(display)
                snap.detected.append((display, proc))

        return snap


# ---------------------------------------------------------------------------
# Pure check logic
# ---------------------------------------------------------------------------

def check_desktop_apps(snapshot: DesktopAppsSnapshot, t: TranslationFunc | None = None) -> CheckResult:
    """
    Analyse desktop apps snapshot and return findings.

    One INFO finding per detected application — no deduction.
    Returns an empty CheckResult (no findings) when nothing is detected,
    so the caller can skip displaying the section entirely.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    for display_name, proc_name in snapshot.detected:
        result.info(
            message=_t("desktop_apps.detected", app=display_name, proc=proc_name),
            key="desktop_apps.detected",
        )

    return result
