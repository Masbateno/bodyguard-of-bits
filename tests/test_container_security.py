"""v0.13.0 — container self-hardening posture check (INFO-only)."""

from __future__ import annotations

from bob.checks.container_security import (
    ContainerSecuritySnapshot,
    check_container_security,
    _parse_hex,
    _CAP_SYS_ADMIN_BIT,
    _DANGEROUS_CAPS,
)
from bob.scoring import FindingLevel


def _keys(result):
    return {f.key for f in result.findings}


class TestCheckLogic:
    def test_not_in_container_emits_nothing(self):
        r = check_container_security(ContainerSecuritySnapshot(in_container=False))
        assert r.findings == []
        assert not r.deductions

    def test_only_operator_choices_deduct(self):
        """v0.15.4 "teeth" replaced the INFO-only contract with a narrower one.

        Three findings deduct — privileged, CAP_SYS_ADMIN, seccomp switched
        off — because each is typed by a human on the command line, the way
        PermitRootLogin=yes is. Everything else the section reports is a
        runtime default the operator did not choose (podman leaves the root
        filesystem writable out of the box; docker runs as root without a user
        namespace), and defaults stay INFO with no deduction.

        Field-tested with podman: a container started with no flags at all
        scores zero, which is the property that matters most here.
        """
        snap = ContainerSecuritySnapshot(
            in_container=True, runtime="docker", privileged=True,
            dangerous_caps=["CAP_SYS_ADMIN"], seccomp=0, is_root=True,
            userns=False, rootfs_writable=True,
        )
        r = check_container_security(snap)
        deducting = {d.key for d in r.deductions} if hasattr(next(iter(r.deductions), None), "key") \
            else {f.key for f in r.findings if f.level is not FindingLevel.INFO}
        assert deducting == {
            "container_security.privileged",
            "container_security.no_seccomp",
        }
        # the defaults in the same snapshot stay INFO
        levels = {f.key: f.level for f in r.findings}
        assert levels["container_security.rootfs_writable"] is FindingLevel.INFO
        assert levels["container_security.root_no_userns"] is FindingLevel.INFO

    def test_a_default_container_costs_nothing(self):
        """The rule the teeth rest on: editor defaults are not penalised."""
        snap = ContainerSecuritySnapshot(
            in_container=True, runtime="podman", privileged=False,
            dangerous_caps=[], seccomp=2, is_root=True, userns=True,
            rootfs_writable=True,
        )
        r = check_container_security(snap)
        assert not r.deductions
        assert all(f.level is FindingLevel.INFO for f in r.findings)

    def test_cap_sys_admin_alone_deducts_less_than_privileged(self):
        """A targeted grant is not a privileged container, and the ladder says so."""
        def points(**kw):
            snap = ContainerSecuritySnapshot(in_container=True, runtime="docker",
                                             seccomp=2, **kw)
            return sum(d.points for d in check_container_security(snap).deductions)
        assert points(cap_sys_admin=True, dangerous_caps=["CAP_SYS_ADMIN"]) == 2
        assert points(privileged=True, dangerous_caps=["CAP_SYS_ADMIN"]) == 3

    def test_privileged_surfaced(self):
        snap = ContainerSecuritySnapshot(in_container=True, runtime="docker",
                                         privileged=True, dangerous_caps=["CAP_SYS_ADMIN"])
        keys = _keys(check_container_security(snap))
        assert "container_security.detected" in keys
        assert "container_security.privileged" in keys
        assert "container_security.dangerous_caps" not in keys   # privileged supersedes

    def test_dangerous_caps_without_sys_admin(self):
        snap = ContainerSecuritySnapshot(in_container=True, runtime="podman",
                                         privileged=False, dangerous_caps=["CAP_NET_ADMIN"])
        keys = _keys(check_container_security(snap))
        assert "container_security.dangerous_caps" in keys
        assert "container_security.privileged" not in keys

    def test_restricted_caps(self):
        snap = ContainerSecuritySnapshot(in_container=True, runtime="docker",
                                         privileged=False, dangerous_caps=[],
                                         seccomp=2, is_root=False, userns=True,
                                         rootfs_writable=False)
        keys = _keys(check_container_security(snap))
        assert "container_security.caps_restricted" in keys
        assert "container_security.no_seccomp" not in keys        # seccomp active
        assert "container_security.root_no_userns" not in keys    # not root / userns on
        assert "container_security.rootfs_writable" not in keys   # ro rootfs

    def test_seccomp_and_root_and_rootfs_conditions(self):
        snap = ContainerSecuritySnapshot(in_container=True, runtime="docker",
                                         seccomp=0, is_root=True, userns=False,
                                         rootfs_writable=True)
        keys = _keys(check_container_security(snap))
        assert {"container_security.no_seccomp",
                "container_security.root_no_userns",
                "container_security.rootfs_writable"} <= keys


class TestCapParsing:
    def test_parse_hex(self):
        assert _parse_hex("000001ffffffffff") == 0x1ffffffffff
        assert _parse_hex("garbage") == 0
        assert _parse_hex("") == 0

    def test_privileged_bit_detection(self):
        full = _parse_hex("000001ffffffffff")
        assert bool(full & (1 << _CAP_SYS_ADMIN_BIT))             # privileged
        docker_default = _parse_hex("00000000a80425fb")          # real docker default
        assert not (docker_default & (1 << _CAP_SYS_ADMIN_BIT))  # SYS_ADMIN dropped

    def test_dangerous_cap_map_bits(self):
        # sanity: the well-known cap numbers
        assert _DANGEROUS_CAPS[21] == "CAP_SYS_ADMIN"
        assert _DANGEROUS_CAPS[19] == "CAP_SYS_PTRACE"


class TestDetection:
    def test_detect_via_systemd(self, monkeypatch):
        import bob.checks.container_security as m
        monkeypatch.setattr(m, "_command_exists", lambda n: True)
        monkeypatch.setattr(m, "_run", lambda *a, **k: "docker\n")
        assert m._detect_container() == "docker"

    def test_detect_none_on_host(self, monkeypatch):
        import bob.checks.container_security as m
        monkeypatch.setattr(m, "_command_exists", lambda n: True)
        monkeypatch.setattr(m, "_run", lambda *a, **k: "none\n")
        monkeypatch.setattr(m.Path, "exists", lambda self: False)
        # cgroup read returns host-ish content
        monkeypatch.setattr(m.Path, "read_text",
                            lambda self, **k: "0::/user.slice\n")
        assert m._detect_container() == ""

    def test_from_system_not_container(self, monkeypatch):
        import bob.checks.container_security as m
        monkeypatch.setattr(m, "_detect_container", lambda: "")
        snap = ContainerSecuritySnapshot.from_system()
        assert snap.in_container is False
