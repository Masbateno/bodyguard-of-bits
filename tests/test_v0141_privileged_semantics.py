"""v0.14.1 — "privileged" must mean the full capability set, not CAP_SYS_ADMIN.

Until v0.14.1 the snapshot computed:

    snap.privileged = bool(snap.cap_bnd & (1 << _CAP_SYS_ADMIN_BIT))

so a container started with ``--cap-add SYS_ADMIN`` — one targeted grant,
seccomp still enforcing — was reported as PRIVILEGED under the headline
*"full Linux capability set available"*. Measured on real podman containers:

    default rootless      cap_bnd 2147747323     seccomp 2
    --privileged          cap_bnd 2199023255551  seccomp 0
    --cap-add SYS_ADMIN   cap_bnd 2149844475     seccomp 2   <- reported privileged

2199023255551 is (1 << 41) - 1, every capability the kernel knows
(cap_last_cap = 40). 2149844475 is demonstrably not that.

The existing tests could not catch it: they set ``privileged=True/False``
directly on the snapshot and never derived it from a realistic ``cap_bnd``.
These do the opposite — they start from the measured bitmasks.
"""

from __future__ import annotations

import pytest

from bob.checks._run import _identity_t
from bob.checks.container_security import (
    _CAP_LAST_CAP_FALLBACK,
    ContainerSecuritySnapshot,
    _read_cap_last_cap,
    check_container_security,
)

# Bounding sets captured from real podman containers on Linux 6.x
# (cap_last_cap = 40).
CAP_DEFAULT_ROOTLESS = 2147747323
CAP_FULL_PRIVILEGED = 2199023255551
CAP_SYS_ADMIN_ADDED = 2149844475

FULL_MASK = (1 << 41) - 1


def _snapshot_for(cap_bnd: int, monkeypatch) -> ContainerSecuritySnapshot:
    """Drive the REAL ContainerSecuritySnapshot.from_system() with a chosen
    bounding set.

    The point is to exercise the production classification, not to restate it
    in the test. An earlier version of this file reimplemented the mask logic
    locally; it passed happily when the old buggy line was restored, which is
    exactly the weakness that let the defect ship in the first place.
    """
    import bob.checks.container_security as m
    monkeypatch.setattr(m, "_detect_container", lambda: "podman")
    monkeypatch.setattr(m, "_read_proc_status", lambda: {
        "CapBnd": f"{cap_bnd:016x}",
        "Seccomp": "2",
        "NoNewPrivs": "1",
        "Uid": "0\t0\t0\t0",
    })
    monkeypatch.setattr(m, "_has_user_namespace", lambda: True)
    monkeypatch.setattr(m, "_rootfs_writable", lambda: False)
    monkeypatch.setattr(m, "_read_cap_last_cap", lambda: 40)
    return m.ContainerSecuritySnapshot.from_system()


class TestClassificationFromRealBitmasks:
    """Every case goes through from_system(), never a reimplementation."""

    def test_full_set_is_privileged(self, monkeypatch):
        snap = _snapshot_for(CAP_FULL_PRIVILEGED, monkeypatch)
        assert snap.privileged is True
        assert snap.cap_sys_admin is True

    def test_sys_admin_alone_is_not_privileged(self, monkeypatch):
        """The regression this release exists for."""
        snap = _snapshot_for(CAP_SYS_ADMIN_ADDED, monkeypatch)
        assert snap.privileged is False, (
            "a container granted one capability is not a privileged container"
        )
        assert snap.cap_sys_admin is True

    def test_default_container_is_neither(self, monkeypatch):
        snap = _snapshot_for(CAP_DEFAULT_ROOTLESS, monkeypatch)
        assert snap.privileged is False
        assert snap.cap_sys_admin is False

    def test_the_measured_masks_are_actually_different(self):
        """Guards the fixtures themselves: if these ever collapse to the same
        value the tests above would pass vacuously."""
        assert CAP_SYS_ADMIN_ADDED != CAP_FULL_PRIVILEGED
        assert CAP_FULL_PRIVILEGED == FULL_MASK

    def test_end_to_end_emission_for_a_targeted_grant(self, monkeypatch):
        """from_system() -> check_container_security(), no field set by hand."""
        snap = _snapshot_for(CAP_SYS_ADMIN_ADDED, monkeypatch)
        keys = {f.key for f in check_container_security(snap, t=_identity_t).findings}
        assert "container_security.cap_sys_admin" in keys
        assert "container_security.privileged" not in keys

    def test_end_to_end_emission_for_a_privileged_container(self, monkeypatch):
        snap = _snapshot_for(CAP_FULL_PRIVILEGED, monkeypatch)
        keys = {f.key for f in check_container_security(snap, t=_identity_t).findings}
        assert "container_security.privileged" in keys
        assert "container_security.cap_sys_admin" not in keys


class TestFindingEmission:

    @staticmethod
    def _keys(**kwargs) -> set[str]:
        snap = ContainerSecuritySnapshot(in_container=True, runtime="podman", **kwargs)
        return {f.key for f in check_container_security(snap, t=_identity_t).findings}

    def test_full_set_emits_privileged(self):
        keys = self._keys(cap_bnd=CAP_FULL_PRIVILEGED, privileged=True,
                          cap_sys_admin=True, dangerous_caps=["CAP_SYS_ADMIN"])
        assert "container_security.privileged" in keys
        assert "container_security.cap_sys_admin" not in keys

    def test_sys_admin_alone_emits_its_own_finding(self):
        keys = self._keys(cap_bnd=CAP_SYS_ADMIN_ADDED, privileged=False,
                          cap_sys_admin=True, dangerous_caps=["CAP_SYS_ADMIN"])
        assert "container_security.cap_sys_admin" in keys
        assert "container_security.privileged" not in keys, (
            "reporting a targeted grant as PRIVILEGED is the defect"
        )

    def test_other_dangerous_caps_still_use_the_generic_finding(self):
        keys = self._keys(cap_bnd=0, privileged=False, cap_sys_admin=False,
                          dangerous_caps=["CAP_NET_ADMIN"])
        assert "container_security.dangerous_caps" in keys
        assert "container_security.cap_sys_admin" not in keys

    def test_clean_container_emits_neither(self):
        keys = self._keys(cap_bnd=CAP_DEFAULT_ROOTLESS, privileged=False,
                          cap_sys_admin=False, dangerous_caps=[])
        assert "container_security.privileged" not in keys
        assert "container_security.cap_sys_admin" not in keys


class TestCapLastCap:

    def test_reads_the_kernel_value(self):
        value = _read_cap_last_cap()
        assert 0 < value < 64, f"implausible cap_last_cap: {value}"

    def test_falls_back_when_unreadable(self, monkeypatch):
        import bob.checks.container_security as m

        class _Boom:
            def read_text(self, *a, **k):
                raise OSError("no such file")
        monkeypatch.setattr(m, "Path", lambda *_: _Boom())
        assert m._read_cap_last_cap() == _CAP_LAST_CAP_FALLBACK

    def test_rejects_a_nonsense_value(self, monkeypatch):
        """A bogus cap_last_cap would shift the mask into absurdity and make
        every container look unprivileged."""
        import bob.checks.container_security as m

        class _Weird:
            def read_text(self, *a, **k):
                return "9999\n"
        monkeypatch.setattr(m, "Path", lambda *_: _Weird())
        assert m._read_cap_last_cap() == _CAP_LAST_CAP_FALLBACK


class TestMessagesAreAccurate:

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_only_the_privileged_headline_claims_the_full_set(self, locale):
        """The old headline claimed "full capability set" for both cases."""
        import json
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        cs = json.loads((root / "bob" / "locales" / f"{locale}.json")
                        .read_text(encoding="utf-8"))["container_security"]
        full_claim = "full Linux capability set" if locale == "en" \
            else "jeu complet de capabilities"
        assert full_claim in cs["privileged"]
        assert full_claim not in cs["cap_sys_admin"], (
            "the CAP_SYS_ADMIN headline must not claim the full set — that "
            "claim is false for a targeted grant"
        )

    @pytest.mark.parametrize("locale", ["en", "fr"])
    def test_sys_admin_message_says_it_is_not_privileged(self, locale):
        import json
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        cs = json.loads((root / "bob" / "locales" / f"{locale}.json")
                        .read_text(encoding="utf-8"))["container_security"]
        needle = "not a privileged" if locale == "en" else "pas un conteneur privilégié"
        assert needle in cs["cap_sys_admin"]
