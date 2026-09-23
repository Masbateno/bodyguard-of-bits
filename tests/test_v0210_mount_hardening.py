"""v0.21.0 — filesystem mount-hardening check (CIS §1.1).

/tmp, /var/tmp, /dev/shm are world-writable. When they are their own mount but
lack nodev/nosuid, a dropped file can become a device node or a set-uid binary.
BOB reads *effective* options from /proc/self/mounts and, crucially, does NOT
penalise a /tmp that is simply not a separate mount (a topology choice, not a
fault) — that is reported INFO. Missing nodev/nosuid on a real mount is WARN;
missing only noexec is INFO (it breaks legitimate use); unreadable is unknown.
"""

from __future__ import annotations

import bob.checks.mount_hardening as mh
from bob.checks.mount_hardening import (
    MountHardeningSnapshot, _MountInfo, check_mount_hardening,
)
from bob.scoring import FindingLevel
from tests.helpers import _keys, _get_finding


def _levels_of(result, key):
    return [f.level for f in result.findings if f.key == key]


# ---------------------------------------------------------------------------
# check logic
# ---------------------------------------------------------------------------

def test_unreadable_is_info_unknown():
    result = check_mount_hardening(MountHardeningSnapshot(readable=False))
    assert _keys(result) == ["mount_hardening.unreadable"]


def test_not_a_separate_mount_is_info_not_penalised():
    snap = MountHardeningSnapshot(readable=True, mounts=[
        _MountInfo(path="/tmp", is_mount=False),
    ])
    result = check_mount_hardening(snap)
    assert "mount_hardening.not_separate" in _keys(result)
    assert not result.deductions


class TestOptions:
    def test_missing_nodev_nosuid_warns_and_deducts(self):
        """The mutation guard: a separate mount missing nodev/nosuid must WARN."""
        snap = MountHardeningSnapshot(readable=True, mounts=[
            _MountInfo(path="/tmp", is_mount=True,
                       options=frozenset({"rw", "noexec"})),
        ])
        result = check_mount_hardening(snap)
        assert FindingLevel.WARN in _levels_of(result, "mount_hardening.options_missing")
        assert sum(d.points for d in result.deductions) >= 1
        f = _get_finding(result, "mount_hardening.options_missing")
        assert "nodev" in f.message and "nosuid" in f.message

    def test_only_noexec_missing_is_info(self):
        snap = MountHardeningSnapshot(readable=True, mounts=[
            _MountInfo(path="/dev/shm", is_mount=True,
                       options=frozenset({"rw", "nodev", "nosuid"})),
        ])
        result = check_mount_hardening(snap)
        f = _get_finding(result, "mount_hardening.noexec_missing")
        assert f is not None and f.level == FindingLevel.INFO
        assert not result.deductions

    def test_all_three_is_ok(self):
        snap = MountHardeningSnapshot(readable=True, mounts=[
            _MountInfo(path="/dev/shm", is_mount=True,
                       options=frozenset({"rw", "nodev", "nosuid", "noexec"})),
        ])
        assert "mount_hardening.hardened" in _keys(check_mount_hardening(snap))

    def test_missing_only_nosuid_still_warns(self):
        snap = MountHardeningSnapshot(readable=True, mounts=[
            _MountInfo(path="/var/tmp", is_mount=True,
                       options=frozenset({"rw", "nodev", "noexec"})),
        ])
        result = check_mount_hardening(snap)
        f = _get_finding(result, "mount_hardening.options_missing")
        assert f is not None and "nosuid" in f.message and "nodev" not in f.message


# ---------------------------------------------------------------------------
# from_system parsing
# ---------------------------------------------------------------------------

class TestFromSystemParsing:
    _CONF = (
        "proc /proc proc rw,nosuid,nodev,noexec 0 0\n"
        "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
        "/dev/sda2 /tmp ext4 rw,relatime 0 0\n"
    )

    def _snap(self, monkeypatch, conf):
        monkeypatch.setattr(mh, "read_text_capped", lambda p, **kw: conf)
        return MountHardeningSnapshot.from_system()

    def test_effective_options_parsed(self, monkeypatch):
        snap = self._snap(monkeypatch, self._CONF)
        by = {m.path: m for m in snap.mounts}
        assert by["/dev/shm"].is_mount and "nodev" in by["/dev/shm"].options
        assert by["/tmp"].is_mount and "nodev" not in by["/tmp"].options
        assert by["/var/tmp"].is_mount is False  # not in the fake mounts

    def test_unreadable_mounts(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("nope")
        monkeypatch.setattr(mh, "read_text_capped", boom)
        assert MountHardeningSnapshot.from_system().readable is False
