"""
v0.15.5 — "No backup solution installed or configured", from a name on PATH.

The over-interpretation angle: BOB *has* an observation, but the verdict claims
more than the observation carries. Every one of the nine backup branches opened
with ``_command_exists``, so the deduction rested entirely on whether a binary
was on PATH.

**Reproduced on the bench before anything was changed.** With a mirrored PATH
minus the nine known binaries, the audit reported ``backup.no_backup``, −1,
reason "No backup solution installed or configured". Adding a genuine backup —
``/etc/cron.d/rsnapshot`` on two schedules, plus a ``nas-backup.timer`` running
duplicity to a NAS — did not change the verdict. Querying the cron snapshot in
the same namespace returned::

    ['/etc/cron.d/rsnapshot: 15 5 * * * root curl ... | sh']

so BOB opens that file, parses its lines and keeps the source path, in the same
run where it states no backup is configured.

**The tighter case needs no unknown tool at all.** This host carries
``/etc/timeshift/timeshift.json`` — a path this module already holds as a
constant — and ``/etc/cron.d/timeshift-hourly``. With the binary off PATH the
artefact was never consulted, because it sits *behind* the binary gate. That
inverts the evidence hierarchy: a configuration file is a stronger statement
that backups are configured than a name on PATH. A tool in /opt, installed by
snap or flatpak, or a PATH without /usr/sbin reaches the same place for real.

**B1, the chosen shape.** The deduction is the part that asserts, so the
deduction is what goes when the evidence is ambiguous. The finding does not
claim backups are fine — it withdraws the claim that none is configured and
names what it saw. Keeping the WARN and adding a second finding beside it was
the alternative; it preserves a statement already known to be false.

The dangerous half is the opposite error: a stale ``/etc/rsnapshot.conf`` left
by ``apt remove`` must not read as "backups are happening". Hence a list of
binary names rather than a fuzzy match, comments skipped, and an INFO that says
outright it is not a confirmation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bob.checks.backup as backup_mod
from bob.checks.backup import BackupSnapshot, check_backup


def _keys(result) -> set[str]:
    return {f.key for f in result.findings}


def _deducted(result) -> set[str]:
    return {d.key for d in getattr(result, "deductions", [])}


class TestEvidenceWithdrawsTheDeduction:

    def test_nothing_at_all_still_deducts_on_a_server(self):
        """The polarity twin. A host with no backup must still be told."""
        result = check_backup(BackupSnapshot(), profile_name="server")
        assert "backup.no_backup" in _deducted(result)

    def test_evidence_without_a_tool_costs_nothing(self):
        snap = BackupSnapshot(
            evidence_without_tool=["rsnapshot: /etc/cron.d/rsnapshot"]
        )
        result = check_backup(snap, profile_name="server")
        assert "backup.no_backup" not in _deducted(result)
        assert "backup.evidence_without_tool" in _keys(result)

    def test_the_finding_names_what_it_saw(self):
        snap = BackupSnapshot(
            evidence_without_tool=["duplicity: /etc/systemd/system/nas-backup.service"]
        )
        result = check_backup(snap, profile_name="server")
        detail = " ".join(f.detail or "" for f in result.findings)
        assert "nas-backup.service" in detail

    def test_evidence_never_upgrades_the_verdict(self):
        """It withdraws a claim; it must not manufacture an OK."""
        snap = BackupSnapshot(evidence_without_tool=["borg: /root/.config/borg/keys"])
        result = check_backup(snap, profile_name="server")
        assert "backup.active" not in _keys(result)

    def test_a_real_tool_still_wins(self):
        """Evidence is only collected when nothing was found the ordinary way."""
        snap = BackupSnapshot(active_tools=["borgmatic"])
        result = check_backup(snap, profile_name="server")
        assert "backup.active" in _keys(result)
        assert "backup.evidence_without_tool" not in _keys(result)


class TestArtefactsAreReadWithoutTheBinaryGate:

    def test_a_known_config_is_evidence_on_its_own(self, monkeypatch, tmp_path):
        """The reproduced case: timeshift.json present, binary off PATH."""
        cfg = tmp_path / "timeshift.json"
        cfg.write_text("{}")
        monkeypatch.setattr(backup_mod, "_ARTEFACTS_WITHOUT_BINARY",
                            (("timeshift", (cfg,)),))
        found = backup_mod._artefact_evidence()
        assert found == [f"timeshift: {cfg}"]

    def test_an_unreadable_artefact_is_not_evidence(self, monkeypatch):
        """Unreadable is not absent — and it is not proof either."""
        def _raise(self):
            raise PermissionError(13, "Permission denied", str(self))
        monkeypatch.setattr(Path, "is_file", _raise)
        monkeypatch.setattr(Path, "is_dir", _raise)
        assert backup_mod._artefact_evidence() == []


class TestTheSchedulerScanStaysNarrow:
    """The dangerous half: a false clean bill of health."""

    @pytest.mark.parametrize("line,expected", [
        ("30 3 * * * root /usr/bin/rsnapshot daily", "rsnapshot"),
        ("ExecStart=/usr/local/bin/duplicity / rsync://nas//b", "duplicity"),
        ("0 2 * * * root /usr/bin/btrbk run", "btrbk"),
        # A commented-out backup job is the opposite of evidence.
        ("# 30 3 * * * root /usr/bin/rsnapshot daily", None),
        # Bare rsync is a mirror as often as a backup — deliberately excluded.
        ("0 5 * * * root /usr/bin/rsync -a / /mnt/mirror", None),
        # Word boundaries: no substring hits.
        ("echo cyborg-restic-old.bak", None),
        ("", None),
    ])
    def test_only_a_named_tool_counts(self, line, expected):
        assert backup_mod._names_a_backup_tool(line) == expected

    def test_a_scheduled_job_is_found_with_its_source(self, monkeypatch, tmp_path):
        job = tmp_path / "rsnapshot"
        job.write_text("30 3 * * * root /usr/bin/rsnapshot daily\n")
        monkeypatch.setattr(backup_mod, "_SCHEDULE_DIRS", (tmp_path,))
        monkeypatch.setattr(backup_mod, "_SCHEDULE_FILES", ())
        assert backup_mod._scheduled_evidence() == [f"rsnapshot: {job}"]

    def test_an_unreadable_schedule_dir_is_not_evidence(self, monkeypatch, tmp_path):
        monkeypatch.setattr(backup_mod, "_SCHEDULE_DIRS", (tmp_path / "gone",))
        monkeypatch.setattr(backup_mod, "_SCHEDULE_FILES", ())
        assert backup_mod._scheduled_evidence() == []
