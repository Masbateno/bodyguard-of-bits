"""On a host without systemd, "not measured" was reported as "not running".

Alpine Linux 3.22, v0.17.1 development. OpenRC says::

    sshd                                        [  started  ]
    2351 sshd: /usr/sbin/sshd [listener]

BOB said::

    ⚠ SSH server is installed but not running

It had asked nothing. `systemctl` does not exist on Alpine, and the three-state
logic that exists for exactly this case — *installed, state undetermined* — was
unreachable: `sshd_active_known` defaulted to ``True``, and only the branch
guarded by ``_command_exists("systemctl")`` ever set it to ``False``. A host
with no systemd never entered that branch, so the flag stayed at "I know" while
``sshd_active`` stayed at "it is not running".

The services panorama on the same run got it right — *Service installed, state
undetermined* — which is what made the contradiction visible: two parts of one
audit describing the same daemon, one honest and one not.

This is the class the AppArmor fix closed earlier in this release, in the same
shape: the absence of a probe treated as a negative answer.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from bob.checks.ssh._snapshot import SSHSnapshot
from bob.scoring import FindingLevel

_SRC = Path(__file__).resolve().parent.parent / "bob"


class TestTheFieldDefaultsToNotKnowing:
    def test_a_fresh_snapshot_claims_nothing(self):
        assert SSHSnapshot().sshd_active_known is False, (
            "defaulting to True makes 'nothing answered' and 'it is stopped' "
            "the same value on any host without systemd"
        )

    def test_a_host_where_nothing_answers_stays_unknown(self):
        """Drives the collector, rather than reading the dataclass default.

        The assignment before the probe loop is what protects a host neither
        init system could answer for. A guard on `SSHSnapshot()` alone cannot
        see it: the default and the assignment are two different lines, and
        only the second one runs during an audit.
        """
        from bob.checks.ssh import _snapshot as mod
        with patch.object(mod, "_command_exists", return_value=True), \
             patch.object(mod, "unit_active_state", return_value=None), \
             patch.object(mod, "path_exists", return_value=False):
            snap = mod.SSHSnapshot.from_system()
        assert snap.sshd_active_known is False, (
            "nothing answered about this daemon, and the flag says BOB knows"
        )

    def test_nothing_gates_the_probe_on_one_init_system(self):
        """v0.17.1 moved the assignment out of the systemd branch.

        v0.18.0 removed the branch: `unit_active_state` asks systemd and then
        OpenRC, and answers None when neither could say — which is exactly what
        the flag encodes. Testing for systemctl first made the OpenRC answer
        unreachable, and on Alpine the panorama reported the daemon ACTIVE
        while this check still called its state undetermined.
        """
        src = (_SRC / "checks" / "ssh" / "_snapshot.py").read_text(encoding="utf-8")
        code = "\n".join(ln for ln in src.splitlines()
                         if not ln.strip().startswith("#"))
        assert '_command_exists("systemctl")' not in code, (
            "the SSH snapshot decides for itself which init system exists, so "
            "an OpenRC host cannot be measured no matter what the shared layer "
            "learns to do"
        )
        assert "snap.sshd_active_known = False" in code


class TestWhatTheCheckSays:
    """Three states, and the middle one has to be reachable."""

    def _check(self, **kw):
        from bob.checks.ssh._subchecks import check_ssh
        from tests.test_ssh import base_snapshot
        return check_ssh(base_snapshot(**kw))

    def _keys(self, result):
        return {f.key for f in result.findings}

    def test_no_systemd_withholds_the_verdict(self):
        keys = self._keys(self._check(sshd_active_known=False, sshd_active=False,
                                      ssh_dir_exists=False))
        assert "ssh.active_unknown" in keys
        assert "ssh.not_active" not in keys, (
            "Alpine runs sshd under OpenRC; calling it stopped is a claim about "
            "something BOB never looked at"
        )

    def test_a_measured_stop_still_warns(self):
        result = self._check(sshd_active_known=True, sshd_active=False,
                             ssh_dir_exists=False)
        assert "ssh.not_active" in self._keys(result)
        assert any(f.key == "ssh.not_active" and f.level is FindingLevel.WARN
                   for f in result.findings)

    def test_a_measured_run_is_ok(self):
        assert "ssh.active" in self._keys(
            self._check(sshd_active_known=True, sshd_active=True))

    def test_the_unknown_state_is_only_information(self):
        result = self._check(sshd_active_known=False, sshd_active=False,
                             ssh_dir_exists=False)
        unknown = [f for f in result.findings if f.key == "ssh.active_unknown"]
        assert unknown and unknown[0].level is FindingLevel.INFO, (
            "not knowing is not a finding against the host"
        )


class TestTheTwoHalvesOfTheAuditAgree:
    """The panorama was honest while the SSH check was not."""

    def test_neither_asserts_a_state_without_a_source(self):
        snap_src = (_SRC / "checks" / "ssh" / "_snapshot.py").read_text(encoding="utf-8")
        assert "sshd_active_known:       bool = False" in snap_src
        services_src = (_SRC / "checks" / "services.py").read_text(encoding="utf-8")
        assert "UNKNOWN" in services_src or "unknown" in services_src, (
            "the services panorama lost its undetermined state, which is the "
            "half that was right"
        )
