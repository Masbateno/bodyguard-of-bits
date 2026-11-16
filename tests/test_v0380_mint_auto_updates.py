"""v0.38.0 — Linux Mint's Update Manager automation counts as automatic updates.

0.37.0 read only unattended-upgrades: on a Mint whose Update Manager applies
updates by itself, it said "security patches require manual intervention" and,
under the server profile with security updates pending, took a point.

Measured (16 November 2026): Linux Mint 22.3, mintupdate 7.1.4 (read-only on
the developer's Mint) and its container image (linuxmintd/mint22.3-amd64):
`mintupdate-automation upgrade enable` writes the marker
/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled AND the timer's link
under /etc/systemd/system/timers.target.wants/; `disable` removes both. The
service exits at once without the marker and runs `mintupdate-cli upgrade
--refresh-cache --yes` daily, nothing on battery.

Decided with the user (16 November 2026): both present → automatic updates in
place, an OK finding names them, no point; one alone → not counted.
"""

from __future__ import annotations

import pytest

from bob.checks import updates as up
from bob.checks.updates import check_updates
from tests.test_updates import base_snapshot


@pytest.mark.parametrize("marker, timer, on", [(True, True, True), (True, False, False),
                                                (False, True, False), (False, False, False)])
def test_both_files_or_nothing(tmp_path, monkeypatch, marker, timer, on):
    m, t = tmp_path / "marker", tmp_path / "wants" / "mintupdate-automation-upgrade.timer"
    if marker:
        m.write_text("")
    if timer:
        t.parent.mkdir()
        (tmp_path / "unit.timer").write_text("")
        t.symlink_to(tmp_path / "unit.timer")
    monkeypatch.setattr(up, "_MINT_AUTO_MARKER", m)
    monkeypatch.setattr(up, "_MINT_AUTO_TIMER", t)
    assert up._mint_auto_upgrades() is on


def test_mint_automation_takes_no_point_under_server():
    snap = base_snapshot(pending_security=["libssl3"], unattended_installed=False,
                         unattended_enabled=False, mint_auto_upgrades=True)
    result = check_updates(snap)
    keys = {f.key for f in result.findings}
    assert "updates.mint_automation_on" in keys and "updates.unattended_not_configured" not in keys
    assert not any(d.key == "updates.unattended_not_configured" for d in result.deductions)


def test_without_it_the_point_stays():
    snap = base_snapshot(pending_security=["libssl3"], unattended_installed=False, unattended_enabled=False)
    result = check_updates(snap)
    assert [d.points for d in result.deductions if d.key == "updates.unattended_not_configured"] == [1]


def test_the_snapshot_reads_it(monkeypatch):
    monkeypatch.setattr(up, "_command_exists", lambda c: c == "apt-get")
    monkeypatch.setattr(up, "_scan_dist_upgrade", lambda: ([], [], [], []))
    monkeypatch.setattr(up, "_check_unattended", lambda: (False, False))
    monkeypatch.setattr(up, "_apt_cache_age_days", lambda: 0)
    monkeypatch.setattr(up, "_count_upgradable", lambda: 0)
    monkeypatch.setattr(up, "_mint_auto_upgrades", lambda: True)
    assert up.UpdatesSnapshot.from_system().mint_auto_upgrades is True
