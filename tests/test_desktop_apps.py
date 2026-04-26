"""Tests for CHECK 19 — Desktop application audit."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from bob.checks.desktop_apps import (
    DesktopAppsSnapshot,
    check_desktop_apps,
    _KNOWN_APPS,
)
from bob.scoring import FindingLevel


_LOCALE = {
    "desktop_apps.detected": "{app} detected (process: {proc})",
}


def _t(key: str, **kwargs) -> str:
    """Minimal translate stub using the EN locale template."""
    template = _LOCALE.get(key, key)
    return template.format(**kwargs) if kwargs else template


# ---------------------------------------------------------------------------
# DesktopAppsSnapshot dataclass
# ---------------------------------------------------------------------------

class TestDesktopAppsSnapshotDefaults:
    def test_detected_default_empty(self):
        snap = DesktopAppsSnapshot()
        assert snap.detected == []


# ---------------------------------------------------------------------------
# DesktopAppsSnapshot.from_system()
# ---------------------------------------------------------------------------

def _ps_output(*proc_names: str) -> str:
    return "COMMAND\n" + "\n".join(proc_names) + "\n"


class TestDesktopAppsFromSystem:
    def test_no_apps_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("bash", "sshd", "cron")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected == []

    def test_steam_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("steam")):
            snap = DesktopAppsSnapshot.from_system()
        assert len(snap.detected) == 1
        assert snap.detected[0][0] == "Steam"
        assert snap.detected[0][1] == "steam"

    def test_discord_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("Discord")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected[0][0] == "Discord"

    def test_discord_lowercase_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("discord")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected[0][0] == "Discord"

    def test_zoom_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("zoom")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected[0][0] == "Zoom"

    def test_slack_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("slack")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected[0][0] == "Slack"


    def test_obs_detected(self):
        with patch("subprocess.check_output", return_value=_ps_output("obs")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected[0][0] == "OBS Studio"

    def test_telegram_truncated_comm_detected(self):
        # Linux comm field truncates to 15 chars: "telegram-desktop" → "telegram-deskto"
        with patch("subprocess.check_output", return_value=_ps_output("telegram-deskto")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected[0][0] == "Telegram"

    def test_deduplication_steam(self):
        # both "steam" and "steamwebhelper" map to "Steam" → only one finding
        with patch("subprocess.check_output", return_value=_ps_output("steam", "steamwebhelper")):
            snap = DesktopAppsSnapshot.from_system()
        names = [d[0] for d in snap.detected]
        assert names.count("Steam") == 1

    def test_multiple_different_apps(self):
        with patch("subprocess.check_output", return_value=_ps_output("steam", "discord", "zoom")):
            snap = DesktopAppsSnapshot.from_system()
        names = {d[0] for d in snap.detected}
        assert names == {"Steam", "Discord", "Zoom"}

    def test_subprocess_error_returns_empty(self):
        with patch("subprocess.check_output", side_effect=OSError):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected == []

    def test_subprocess_called_error_returns_empty(self):
        with patch("subprocess.check_output", side_effect=subprocess.SubprocessError):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected == []

    def test_unknown_process_ignored(self):
        with patch("subprocess.check_output", return_value=_ps_output("my-custom-app", "nginx")):
            snap = DesktopAppsSnapshot.from_system()
        assert snap.detected == []


# ---------------------------------------------------------------------------
# check_desktop_apps()
# ---------------------------------------------------------------------------

class TestCheckDesktopAppsNoApps:
    def test_empty_snapshot_no_findings(self):
        snap = DesktopAppsSnapshot(detected=[])
        result = check_desktop_apps(snap)
        assert result.findings == []

    def test_empty_snapshot_no_deductions(self):
        snap = DesktopAppsSnapshot(detected=[])
        result = check_desktop_apps(snap)
        assert result.deductions == []


class TestCheckDesktopAppsDetected:
    def test_one_app_one_info_finding(self):
        snap = DesktopAppsSnapshot(detected=[("Steam", "steam")])
        result = check_desktop_apps(snap)
        assert len(result.findings) == 1
        assert result.findings[0].level == FindingLevel.INFO

    def test_finding_key(self):
        snap = DesktopAppsSnapshot(detected=[("Discord", "Discord")])
        result = check_desktop_apps(snap)
        assert result.findings[0].key == "desktop_apps.detected"

    def test_no_deduction(self):
        snap = DesktopAppsSnapshot(detected=[("Zoom", "zoom")])
        result = check_desktop_apps(snap)
        assert result.deductions == []

    def test_multiple_apps_multiple_findings(self):
        snap = DesktopAppsSnapshot(detected=[
            ("Steam", "steam"),
            ("Discord", "Discord"),
            ("OBS Studio", "obs"),
        ])
        result = check_desktop_apps(snap)
        assert len(result.findings) == 3
        assert all(f.level == FindingLevel.INFO for f in result.findings)

    def test_app_name_in_message(self):
        snap = DesktopAppsSnapshot(detected=[("Slack", "slack")])
        result = check_desktop_apps(snap, t=_t)
        assert "Slack" in result.findings[0].message

    def test_proc_name_in_message(self):
        snap = DesktopAppsSnapshot(detected=[("Slack", "slack")])
        result = check_desktop_apps(snap, t=_t)
        assert "slack" in result.findings[0].message


# ---------------------------------------------------------------------------
# _KNOWN_APPS registry sanity
# ---------------------------------------------------------------------------

class TestKnownAppsRegistry:
    def test_steam_present(self):
        assert "steam" in _KNOWN_APPS

    def test_discord_present(self):
        assert "Discord" in _KNOWN_APPS or "discord" in _KNOWN_APPS

    def test_zoom_present(self):
        assert "zoom" in _KNOWN_APPS

    def test_slack_present(self):
        assert "slack" in _KNOWN_APPS

    def test_all_values_non_empty(self):
        assert all(v for v in _KNOWN_APPS.values())

    def test_no_proc_name_longer_than_15_chars(self):
        # Linux comm field is limited to 15 chars — keys must match what ps returns.
        # "telegram-desktop" (16 chars) must be stored as "telegram-deskto" (15 chars).
        for proc in _KNOWN_APPS:
            assert len(proc) <= 15, (
                f"Process name {proc!r} exceeds 15 chars — use truncated comm form"
            )
