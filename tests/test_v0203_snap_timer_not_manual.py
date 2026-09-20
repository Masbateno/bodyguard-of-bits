"""A snap-managed timer is not a "manually created" root timer.

snapd writes its timers into /etc/systemd/system/ (snap.<pkg>.<name>.timer),
the same directory a hand-added unit uses — unlike deb packages, which install
under /lib/systemd/system/ and are already excluded. Measured on a real Ubuntu
26.04: snap.nextcloud.logrotate.timer was listed as "manually created, running
as root" (INFO). It belongs to an installed snap, so the snap.* namespace is
excluded from that listing; the pipe-to-shell / world-writable ExecStart checks
still apply to every timer.
"""

from __future__ import annotations

from bob.checks.systemd_timers import _is_manually_created_root_timer as f


def test_snap_timer_is_not_manual():
    assert f("snap.nextcloud.logrotate.timer",
             is_user_created=True, has_user=False, has_exec=True) is False


def test_hand_added_root_timer_is_still_flagged():
    assert f("custom.timer",
             is_user_created=True, has_user=False, has_exec=True) is True


def test_timer_with_user_directive_is_not_flagged():
    assert f("custom.timer",
             is_user_created=True, has_user=True, has_exec=True) is False


def test_package_dir_timer_is_not_flagged():
    # is_user_created False = the unit lives under /lib/systemd/system (deb).
    assert f("logrotate.timer",
             is_user_created=False, has_user=False, has_exec=True) is False
