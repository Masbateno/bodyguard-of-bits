"""/proc hidepid — process visibility between users, folded into mount_hardening.

INFO-only by doctrine: whether hiding other users' processes matters depends on
how many people log in, so it is reported, never scored. The guard pins:

  1. both syntaxes the kernel accepts (0/1/2/4 and, since 5.8, the names) map to
     the same verdict;
  2. no hidepid option means "off" — never read as restricted;
  3. a value BOB does not recognise, or a /proc missing from the mount table, is
     "unknown", not a verdict;
  4. nothing here ever deducts.
"""

from __future__ import annotations

import pytest

from bob.checks import mount_hardening
from bob.checks.mount_hardening import (
    MountHardeningSnapshot,
    check_mount_hardening,
)
from tests.helpers import _t


def _keys(result):
    return [f.key for f in result.findings]


def _snap(proc_options):
    return MountHardeningSnapshot(readable=True, mounts=[], proc_options=proc_options)


@pytest.mark.parametrize("opt", ["hidepid=2", "hidepid=invisible",
                                 "hidepid=4", "hidepid=ptraceable"])
def test_restricted_levels_are_ok(opt):
    r = check_mount_hardening(_snap(frozenset({"rw", opt})), t=_t)
    assert "mount_hardening.proc_hidepid_restricted" in _keys(r)


@pytest.mark.parametrize("opt", ["hidepid=1", "hidepid=noaccess"])
def test_noaccess_is_partial(opt):
    r = check_mount_hardening(_snap(frozenset({"rw", opt})), t=_t)
    assert "mount_hardening.proc_hidepid_partial" in _keys(r)


@pytest.mark.parametrize("opts", [frozenset({"rw", "nosuid"}),
                                  frozenset({"rw", "hidepid=0"}),
                                  frozenset({"rw", "hidepid=off"})])
def test_absent_or_zero_is_off_not_restricted(opts):
    r = check_mount_hardening(_snap(opts), t=_t)
    assert "mount_hardening.proc_hidepid_off" in _keys(r)
    assert "mount_hardening.proc_hidepid_restricted" not in _keys(r)


@pytest.mark.parametrize("opts", [None, frozenset({"rw", "hidepid=7"})])
def test_unknown_is_not_a_verdict(opts):
    r = check_mount_hardening(_snap(opts), t=_t)
    assert "mount_hardening.proc_hidepid_unknown" in _keys(r)


@pytest.mark.parametrize("opts", [None, frozenset(), frozenset({"hidepid=2"})])
def test_never_deducts(opts):
    r = check_mount_hardening(_snap(opts), t=_t)
    assert not [d for d in r.deductions if "hidepid" in d.key]


def test_from_system_reads_the_proc_line(monkeypatch):
    text = ("proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0\n"
            "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n")
    monkeypatch.setattr(mount_hardening, "read_text_capped", lambda *a, **k: text)
    snap = MountHardeningSnapshot.from_system()
    assert snap.proc_options is not None and "hidepid=invisible" in snap.proc_options
    assert "mount_hardening.proc_hidepid_restricted" in _keys(check_mount_hardening(snap, t=_t))
