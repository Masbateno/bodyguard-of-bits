"""
v0.15.0 — an unreadable seccomp status was indistinguishable from an active one.

The rest of this module was checked against podman and agreed on every
configuration it could be asked for — `--privileged`, `--cap-add SYS_ADMIN`,
`--cap-drop=ALL`, `--read-only`, `--security-opt no-new-privileges`,
`--userns=keep-id`, and detection in an image with no `systemd-detect-virt`.
The v0.14.1 pass on this file did its job.

One gap survived it. `snapshot.seccomp` is -1 when `/proc/self/status` had no
`Seccomp` line, and the check only ever tested `== 0`, so -1 fell through in
silence — the container section simply said nothing about seccomp, which reads
as "seccomp is in place".

The kernel emits that line only under `CONFIG_SECCOMP`. It is therefore missing
exactly on a kernel with no seccomp support at all: the case where the remark
matters most is the case that produced no remark.

Unknown is now its own answer, and says so rather than guessing in either
direction.
"""

from __future__ import annotations

import pytest

import bob.checks.container_security as cs
from bob.checks.container_security import (
    ContainerSecuritySnapshot,
    check_container_security,
)


def _keys(seccomp: int) -> set[str]:
    snap = ContainerSecuritySnapshot(
        in_container=True, runtime="docker", seccomp=seccomp,
        cap_bnd=2147747323, cap_last_cap=40)
    return {f.key for f in check_container_security(snap).findings}


class TestSeccompStates:
    def test_unknown_is_reported_as_unknown(self):
        keys = _keys(-1)
        assert "container_security.seccomp_unknown" in keys
        assert "container_security.no_seccomp" not in keys, \
            "unknown must not be reported as disabled either — it is unknown"

    def test_disabled_is_still_reported_as_disabled(self):
        keys = _keys(0)
        assert "container_security.no_seccomp" in keys
        assert "container_security.seccomp_unknown" not in keys

    @pytest.mark.parametrize("mode", [1, 2])
    def test_an_active_mode_says_nothing(self, mode):
        """Strict (1) and filter (2) are both protections; silence is correct
        here, and is exactly what -1 used to borrow."""
        keys = _keys(mode)
        assert "container_security.no_seccomp" not in keys
        assert "container_security.seccomp_unknown" not in keys

    def test_the_three_outcomes_are_distinguishable(self):
        """The defect was that two of them were the same."""
        unknown, disabled, active = _keys(-1), _keys(0), _keys(2)
        assert unknown != active
        assert disabled != active
        assert unknown != disabled


class TestParsingProducesTheUnknownState:
    def test_a_status_without_a_seccomp_line_yields_minus_one(self, monkeypatch):
        """What a CONFIG_SECCOMP=n kernel actually gives."""
        monkeypatch.setattr(cs, "_read_proc_status",
                            lambda: {"CapBnd": "0000000000000000", "Uid": "0 0 0 0"})
        monkeypatch.setattr(cs, "_detect_container", lambda: "docker")
        assert ContainerSecuritySnapshot.from_system().seccomp == -1

    def test_an_unreadable_status_yields_minus_one(self, monkeypatch):
        monkeypatch.setattr(cs, "_read_proc_status", dict)
        monkeypatch.setattr(cs, "_detect_container", lambda: "docker")
        assert ContainerSecuritySnapshot.from_system().seccomp == -1

    def test_a_real_value_is_read(self, monkeypatch):
        monkeypatch.setattr(cs, "_read_proc_status",
                            lambda: {"Seccomp": "2", "CapBnd": "0", "Uid": "0 0 0 0"})
        monkeypatch.setattr(cs, "_detect_container", lambda: "docker")
        assert ContainerSecuritySnapshot.from_system().seccomp == 2


class TestOutsideAContainerNothingIsRead:
    def test_the_snapshot_short_circuits(self, monkeypatch):
        """Every field keeps its default, including seccomp=-1, and the check
        is never reached — pinned so the new branch cannot start firing on
        ordinary hosts."""
        monkeypatch.setattr(cs, "_detect_container", lambda: "")
        snap = ContainerSecuritySnapshot.from_system()
        assert snap.in_container is False
        assert check_container_security(snap).findings == []
