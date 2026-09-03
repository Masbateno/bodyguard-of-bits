"""
v0.15.5 — BOB audits the file, an attacker meets the process.

A third axis, and a different question from the two before it. Those asked
whether the evidence supported the verdict; this one asks **what the verdict is
about**. The SSH findings are phrased in the present indicative — "Root login
via SSH *is* permitted", "Password authentication *is* enabled" — but they are
read from ``/etc/ssh/sshd_config``, and sshd loads that file at start and on
reload. An edit that was never applied makes them a statement of intent.

Both directions are wrong, and they are not equally dangerous. A file still
showing a bad directive on a daemon already fixed produces a finding that is
merely stale. A file **just hardened** on a daemon still running the old
settings produces a clean section — and there is no finding for a caveat to
hang off, which is why the note is about the section rather than attached to a
result. Twenty-four of the tool's points ride on sshd_config, three more on
journald.conf.

**The reload semantics were established against systemd, not assumed**, on a
disposable user unit, because the whole angle turns on them. After
``systemctl reload`` with the main PID unchanged:

    ExecMainStartTimestamp   15:10:06 -> 15:10:06   (unchanged)
    ActiveEnterTimestamp     15:10:06 -> 15:10:06   (unchanged)
    StateChangeTimestamp     15:10:06 -> 15:10:18   (moved)

Only StateChangeTimestamp follows a reload. Comparing against either of the
other two would have flagged every administrator who edited and reloaded
correctly — a guard that fires on people doing the right thing gets switched
off, which is the defect this release just removed from the log analyser.

**Two modules were examined and excluded, from their own documentation.** smbd
"automatically reload[s] the configuration file every three minutes, if they
change" (smbd(8)), so smb.conf is effectively live and the divergence window is
three minutes. PAM, pwquality and login.defs are read per authentication, so
the file *is* the effective state. sysctl is read by BOB from /proc/sys, which
is the runtime. Eight further modules already query the live tool — auditd via
auditctl, fail2ban via fail2ban-client, firewall via ufw status. The pattern
was already right in most of the tool; the file-reading set is the exposed one.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

import bob.checks._run as run_mod
import bob.checks.log_rotation as lr_mod
import bob.checks.ssh._snapshot as snap_mod
from bob.checks._run import CommandResult, unit_config_applied_at
from bob.checks.ssh import SSHSnapshot
from bob.checks.ssh._subchecks import _check_sshd_config
from bob.scoring import CheckResult


def _keys(result):
    return {f.key for f in result.findings}


class TestTheTimestampHelperReadsWhatSystemdSays:

    def test_unix_form_is_used_when_available(self, monkeypatch):
        monkeypatch.setattr(run_mod, "run_result",
                            lambda *a, **k: CommandResult("@1788437049\n", True, ""))
        assert unit_config_applied_at("ssh") == 1788437049.0

    def test_the_text_form_is_the_fallback(self, monkeypatch):
        """systemd < 248 has no --timestamp=unix."""
        calls = []

        def _run(*args, **kwargs):
            calls.append(args)
            if "--timestamp=unix" in args:
                return CommandResult("", False, "unknown option")
            return CommandResult("Thu 2026-09-03 15:10:43 CEST\n", True, "")

        monkeypatch.setattr(run_mod, "run_result", _run)
        value = unit_config_applied_at("ssh")
        assert value == datetime(2026, 9, 3, 15, 10, 43).timestamp()
        assert len(calls) == 2

    def test_it_asks_for_the_property_that_follows_a_reload(self, monkeypatch):
        """
        The single decision the whole angle rests on, and it was established
        empirically: on a disposable user unit, `systemctl reload` moved
        StateChangeTimestamp while ExecMainStartTimestamp and
        ActiveEnterTimestamp both stayed at the original start, main PID
        unchanged. Asking for either of those would flag every administrator
        who edited a config and reloaded it correctly.
        """
        asked = []

        def _run(*args, **kwargs):
            asked.append(args)
            return CommandResult("@1788437049\n", True, "")

        monkeypatch.setattr(run_mod, "run_result", _run)
        unit_config_applied_at("ssh")
        flat = [a for call in asked for a in call]
        assert "StateChangeTimestamp" in flat
        assert "ActiveEnterTimestamp" not in flat
        assert "ExecMainStartTimestamp" not in flat

    def test_no_answer_is_none_not_zero(self, monkeypatch):
        """Zero would read as 'applied at the epoch' — every file newer."""
        monkeypatch.setattr(run_mod, "run_result",
                            lambda *a, **k: CommandResult("", False, ""))
        assert unit_config_applied_at("ssh") is None


class TestDriftIsOnlyClaimedWhenEstablished:

    def _snap(self, tmp_path, mtime_offset_s, applied_answer):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PermitRootLogin no\n")
        applied = datetime.now() - timedelta(hours=1)
        import os
        stamp = (applied + timedelta(seconds=mtime_offset_s)).timestamp()
        os.utime(cfg, (stamp, stamp))
        snap = SSHSnapshot()
        snap_mod._apply_config_drift.__globals__["unit_config_applied_at"] = (
            lambda unit: applied.timestamp() if applied_answer else None
        )
        snap_mod._apply_config_drift(snap, {str(cfg)}, "ssh")
        return snap

    def test_a_file_newer_than_the_applied_config_is_drift(self, tmp_path):
        snap = self._snap(tmp_path, +600, True)
        assert snap.sshd_config_drifted is True
        assert snap.sshd_config_changed_at and snap.sshd_config_applied_at

    def test_a_file_older_than_the_applied_config_is_not(self, tmp_path):
        """The polarity twin — the ordinary host must stay silent."""
        snap = self._snap(tmp_path, -600, True)
        assert snap.sshd_config_drifted is False

    def test_no_systemd_answer_leaves_it_unknown(self, tmp_path):
        """Unknown, not 'no drift'. The check then says nothing at all."""
        snap = self._snap(tmp_path, +600, False)
        assert snap.sshd_config_drifted is None

    def test_an_unreadable_file_is_not_drift(self, tmp_path, monkeypatch):
        snap = SSHSnapshot()
        snap_mod._apply_config_drift.__globals__["unit_config_applied_at"] = (
            lambda unit: datetime.now().timestamp()
        )
        snap_mod._apply_config_drift(snap, {str(tmp_path / "gone")}, "ssh")
        assert snap.sshd_config_drifted is None


class TestTheSectionSaysWhatItIsAbout:

    def _check(self, drifted):
        snap = SSHSnapshot(
            sshd_config_readable=True,
            sshd_config={"permitrootlogin": "no"},
            sshd_config_drifted=drifted,
            sshd_config_drift_path="/etc/ssh/sshd_config",
            sshd_config_changed_at="2026-09-03 15:13",
            sshd_config_applied_at="2026-09-03 14:04",
        )
        result = CheckResult()
        _check_sshd_config(snap, result, lambda key, **kw: key)
        return result

    def test_drift_is_stated(self):
        assert "ssh.config_newer_than_service" in _keys(self._check(True))

    def test_no_drift_stays_quiet(self):
        assert "ssh.config_newer_than_service" not in _keys(self._check(False))

    def test_unknown_stays_quiet(self):
        """None must not be read as drift — `if snapshot.x` would do that."""
        assert "ssh.config_newer_than_service" not in _keys(self._check(None))

    def test_it_costs_nothing(self):
        """
        It names a limit on the section; it is not a finding about the host.
        The directive findings themselves are unchanged — the note explains
        what they describe, it does not withdraw them, because the file really
        does say what it says and really will take effect on the next reload.
        """
        with_drift = [(d.key, d.points) for d in self._check(True).deductions]
        without    = [(d.key, d.points) for d in self._check(False).deductions]
        assert with_drift == without


class TestJournaldCarriesTheSameNote:

    def test_no_systemd_answer_is_unknown(self, monkeypatch):
        monkeypatch.setattr(lr_mod, "unit_config_applied_at", lambda unit: None)
        assert lr_mod._journald_conf_drift() == (None, "", "")

    def test_a_newer_conf_is_drift(self, monkeypatch, tmp_path):
        conf = tmp_path / "journald.conf"
        conf.write_text("[Journal]\nStorage=persistent\n")
        applied = datetime.now() - timedelta(hours=1)
        monkeypatch.setattr(lr_mod, "unit_config_applied_at",
                            lambda unit: applied.timestamp())
        monkeypatch.setattr(lr_mod, "_JOURNALD_CONF", conf)
        monkeypatch.setattr(lr_mod, "_JOURNALD_CONF_D", tmp_path / "none.d")
        drifted, changed, used = lr_mod._journald_conf_drift()
        assert drifted is True and changed and used
