"""Kernel attack surface — unprivileged eBPF, perf events, user namespaces.

INFO-only by the v0.24.0 framing: each knob opens a large kernel interface to
unprivileged users, and the right setting depends on the workload. The guard
pins:

  1. nothing here ever deducts;
  2. the restricted values are OK and the permissive ones INFO — bpf ≥1,
     perf ≥2 (Debian/Ubuntu's 3 and 4 included);
  3. user namespaces are reported as a state with no fix to run — restricting
     them breaks browser sandboxes, flatpak and rootless containers;
  4. the Debian-only kernel.unprivileged_userns_clone and the Ubuntu-only
     kernel.apparmor_restrict_unprivileged_userns being absent is normal — it
     must not land in "parameters not exposed"; only user.max_user_namespaces
     absent means the kernel has no user namespaces to report on;
  5. from_system reads each field from the sysctl it claims to.
"""

from __future__ import annotations

import pytest

import bob.checks.kernel_hardening as kh
from bob.checks.kernel_hardening import KernelHardeningSnapshot, check_kernel_hardening
from tests.helpers import _t

_BASE = dict(aslr=2, ptrace_scope=1, suid_dumpable=0, kptr_restrict=1,
             dmesg_restrict=1, bpf_unpriv_disabled=2, perf_paranoid=2, max_userns=0)


def _run(**kw):
    return check_kernel_hardening(KernelHardeningSnapshot(**{**_BASE, **kw}), t=_t)


def _find(result, key):
    return next((f for f in result.findings if f.key == key), None)


def _keys(result):
    return [f.key for f in result.findings]


@pytest.mark.parametrize("val", [1, 2])
def test_bpf_disabled_is_ok(val):
    assert "kernel_hardening.bpf_unpriv_ok" in _keys(_run(bpf_unpriv_disabled=val))


def test_bpf_allowed_is_info_with_fix():
    r = _run(bpf_unpriv_disabled=0)
    f = _find(r, "kernel_hardening.bpf_unpriv_enabled")
    assert f is not None and f.level.value == "info"
    assert "kernel.unprivileged_bpf_disabled=2" in f.cmd
    assert r.deductions == []


@pytest.mark.parametrize("val", [2, 3, 4])
def test_perf_restricted_is_ok(val):
    assert "kernel_hardening.perf_ok" in _keys(_run(perf_paranoid=val))


@pytest.mark.parametrize("val", [-1, 0, 1])
def test_perf_permissive_is_info(val):
    r = _run(perf_paranoid=val)
    assert "kernel_hardening.perf_permissive" in _keys(r)
    assert r.deductions == []


@pytest.mark.parametrize("kw", [dict(max_userns=0),
                                dict(max_userns=1000, userns_clone=0),
                                dict(max_userns=1000, userns_apparmor=1)])
def test_userns_restricted_forms_are_ok(kw):
    assert "kernel_hardening.userns_restricted" in _keys(_run(**kw))


def test_userns_allowed_is_info_without_a_fix():
    r = _run(max_userns=1000, userns_clone=1, userns_apparmor=0)
    f = _find(r, "kernel_hardening.userns_allowed")
    assert f is not None and f.level.value == "info"
    assert not f.cmd, "turning user namespaces off breaks sandboxes — no fix to run"
    assert r.deductions == []


def test_distro_specific_userns_knobs_absent_is_not_unavailable():
    """Fedora / Arch have neither patch: that is not an unreadable kernel."""
    r = _run(max_userns=1000, userns_clone=None, userns_apparmor=None)
    assert "kernel_hardening.userns_allowed" in _keys(r)
    assert "kernel_hardening.params_unavailable" not in _keys(r)


@pytest.mark.parametrize("field,sysctl", [
    ("bpf_unpriv_disabled", "kernel.unprivileged_bpf_disabled"),
    ("perf_paranoid", "kernel.perf_event_paranoid"),
    ("max_userns", "user.max_user_namespaces"),
])
def test_absent_core_knob_is_reported_unavailable(field, sysctl):
    r = check_kernel_hardening(KernelHardeningSnapshot(**{**_BASE, field: None}),
                               t=lambda key, **kw: f"{key} {kw}")
    f = _find(r, "kernel_hardening.params_unavailable")
    assert f is not None and sysctl in f.message


def test_everything_permissive_still_never_deducts():
    r = _run(bpf_unpriv_disabled=0, perf_paranoid=-1, max_userns=1000,
             userns_clone=1, userns_apparmor=0)
    assert r.deductions == []


def test_from_system_reads_each_field_from_its_sysctl(monkeypatch):
    values = {"kernel.unprivileged_bpf_disabled": 11, "kernel.perf_event_paranoid": 12,
              "user.max_user_namespaces": 13, "kernel.unprivileged_userns_clone": 14,
              "kernel.apparmor_restrict_unprivileged_userns": 15}
    monkeypatch.setattr(kh, "_sysctl_int", lambda key: values.get(key))
    s = KernelHardeningSnapshot.from_system()
    assert (s.bpf_unpriv_disabled, s.perf_paranoid, s.max_userns,
            s.userns_clone, s.userns_apparmor) == (11, 12, 13, 14, 15)
