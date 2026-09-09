"""An empty profile set is an answer, not a failure to look.

Kali 2026.2, running as root, v0.17.1 development::

    ℹ AppArmor is active, but its profile set could not be read

It could be read. ``/sys/kernel/security/apparmor/profiles`` opened cleanly and
returned nothing: AppArmor was loaded and enforcing **zero** profiles — a
framework running with nothing to enforce, which is a finding, reported as an
absence of information.

The cause is that ``aa-status`` cannot tell the two apart. Without the
privilege to read the policy it prints ``apparmor module is loaded.`` and then
fails; with nothing loaded on Kali it prints the same line and *"Failed to get
profiles: 2"*. Either way there is no count line, and v0.15.5 chose to call
that unreadable — correctly, for the case it was measured on: an unprivileged
run on a host carrying 120 enforcing profiles, which had been reported as
having none, with a WARN and a point attached.

The kernel separates them, because its failure modes differ where it matters:

* unprivileged — ``PermissionError``. Measured on the maintainer's Mint host
  and again on Kali as ``nobody``: mode 444, and still denied.
* nothing loaded — succeeds, empty. Measured on Kali as root.
* profiles loaded — succeeds, one ``name (mode)`` per line. Measured on
  Debian 13 as root: 116 lines parsing to 15 enforce and 25 complain, agreeing
  exactly with ``aa-status`` (116 loaded, 15 in enforce mode).

This is the class v0.15.2 closed at its root — "unreadable is not empty" — met
here from the other side: empty treated as unreadable.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bob.checks import mac_policy
from bob.checks.mac_policy import _apparmor_profiles_from_kernel

#: Verbatim from Debian 13, root. Three modes appear in a real set.
_REAL = """wpcom (unconfined)
wike (unconfined)
1password (enforce)
libreoffice-oosplash (complain)
lsb_release (enforce)
"""


class _FakeProfiles:
    """Stands in for the securityfs path.

    `Path` instances refuse attribute assignment, so the module-level constant
    is replaced rather than its method patched.
    """

    def __init__(self, text=None, exc=None):
        self._text, self._exc = text, exc

    def read_text(self, *args, **kwargs):
        if self._exc is not None:
            raise self._exc
        return self._text


class TestTheKernelIsAsked:
    def test_an_empty_set_is_zero_not_unknown(self):
        with patch.object(mac_policy, "_KERNEL_PROFILES", _FakeProfiles(text="")):
            assert _apparmor_profiles_from_kernel() == (0, 0, 0)

    def test_whitespace_only_is_still_zero(self):
        with patch.object(mac_policy, "_KERNEL_PROFILES", _FakeProfiles(text="\n\n  \n")):
            assert _apparmor_profiles_from_kernel() == (0, 0, 0)

    def test_a_real_set_parses_by_mode(self):
        with patch.object(mac_policy, "_KERNEL_PROFILES", _FakeProfiles(text=_REAL)):
            assert _apparmor_profiles_from_kernel() == (5, 2, 1)

    @pytest.mark.parametrize("exc", [PermissionError, FileNotFoundError, OSError])
    def test_only_an_unreadable_file_is_unknown(self, exc):
        with patch.object(mac_policy, "_KERNEL_PROFILES",
                          _FakeProfiles(exc=exc("denied"))):
            assert _apparmor_profiles_from_kernel() is None

    def test_a_line_without_a_mode_still_counts_as_loaded(self):
        with patch.object(mac_policy, "_KERNEL_PROFILES", _FakeProfiles(text="weird-profile\n")):
            assert _apparmor_profiles_from_kernel() == (1, 0, 0)


class TestTheSnapshotUsesIt:
    """What the check concludes, not what the helper returns."""

    def _snapshot(self, aa_out, kernel):
        with patch.object(mac_policy, "_command_exists",
                          side_effect=lambda c: c == "aa-status"), \
             patch.object(mac_policy, "_run", return_value=aa_out), \
             patch.object(mac_policy, "_apparmor_profiles_from_kernel",
                          return_value=kernel):
            return mac_policy.MacPolicySnapshot.from_system()

    def test_kali_root_reports_zero_rather_than_unknown(self):
        """aa-status failed, the kernel answered: that is a verdict."""
        snap = self._snapshot("apparmor module is loaded.\n", (0, 0, 0))
        assert snap.apparmor_active is True
        assert snap.apparmor_profiles_readable is True, (
            "an empty profile set read cleanly is an answer — reporting it as "
            "unreadable hides a framework enforcing nothing"
        )
        assert snap.apparmor_enforcing == 0

    def test_unprivileged_still_says_it_does_not_know(self):
        """The v0.15.5 defect must not reopen: no privilege is not zero."""
        snap = self._snapshot("apparmor module is loaded.\n", None)
        assert snap.apparmor_active is True
        assert snap.apparmor_profiles_readable is False, (
            "a host with 120 enforcing profiles, run without privilege, was "
            "once told it had none — with a WARN and a point attached"
        )

    def test_aa_status_keeps_precedence_when_it_answers(self):
        aa_out = ("apparmor module is loaded.\n"
                  "116 profiles are loaded.\n"
                  "15 profiles are in enforce mode.\n"
                  "25 profiles are in complain mode.\n")
        snap = self._snapshot(aa_out, None)
        assert snap.apparmor_profiles_readable is True
        assert snap.apparmor_enforcing == 15
        assert snap.apparmor_complain == 25


class TestEveryBranchConsultsTheKernel:
    """Three places used to give up; a helper is no use in only one of them."""

    def test_no_branch_hardcodes_unreadable_any_more(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "bob" / "checks"
               / "mac_policy.py").read_text(encoding="utf-8")
        assert "apparmor_profiles_readable = False" not in src, (
            "a branch still declares the profile set unreadable without "
            "asking the kernel first"
        )
        assert src.count("_apparmor_profiles_from_kernel()") >= 4
