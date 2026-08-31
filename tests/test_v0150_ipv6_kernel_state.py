"""
v0.15.0 — an absent IPv6 stack was read as an enabled one, and reported OK.

This one was examined earlier in the cycle and waved through on the reasoning
that an optimistic default errs toward alarming: "assume IPv6 is on, then the
check looks for missing IPv6 firewall rules and warns". Running it instead of
reasoning about it showed the opposite. With both reads failing and no IPv6
listeners, the output is:

    [OK] ipv6.config_ok    IPv6 configuration is consistent

— an explicit statement that the IPv6 configuration is fine, about a stack BOB
could not read at all.

`/proc/sys/net/ipv6` is created when the IPv6 stack registers its sysctls, so
booting with `ipv6.disable=1`, or a kernel built without IPv6, leaves the whole
tree missing. The file was absent *because* IPv6 was off, and
`except OSError: return True  # assume enabled if unreadable` concluded it was
on.

The absent tree is now treated as what it is — an answer, not an unknown —
verified under a mount namespace with `/proc/sys/net` replaced by an empty
tmpfs. A read that fails for any other reason stays unknown and says so.
"""

from __future__ import annotations

import pytest

import bob.checks.ipv6 as m
from bob.checks.ipv6 import IPv6Snapshot, _read_kernel_ipv6, check_ipv6


def _keys(**kw) -> list[str]:
    return [f.key for f in check_ipv6(IPv6Snapshot(**kw), ufw_active=True).findings]


class TestAnAbsentStackIsNotAnEnabledOne:
    def test_a_missing_file_means_ipv6_is_off(self, monkeypatch, tmp_path):
        monkeypatch.setattr(m, "_IPV6_DISABLE_ALL", tmp_path / "absent")
        monkeypatch.setattr(m, "_IPV6_SYSCTL_DIR", tmp_path / "absent")
        assert _read_kernel_ipv6() == (False, True), \
            "an absent /proc/sys/net/ipv6 is the kernel saying IPv6 is off"

    def test_it_no_longer_reports_the_configuration_as_fine(self):
        assert "ipv6.config_ok" not in _keys(
            kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)

    def test_ufw_managing_ipv6_on_a_kernel_without_it_is_surfaced(self):
        assert "ipv6.ufw_enabled_kernel_disabled" in _keys(
            kernel_ipv6_enabled=False, ufw_ipv6_enabled=True)


class TestTheReader:
    def test_disable_ipv6_set_to_one_reads_as_off(self, monkeypatch, tmp_path):
        f = tmp_path / "disable_ipv6"; f.write_text("1\n")
        monkeypatch.setattr(m, "_IPV6_DISABLE_ALL", f)
        monkeypatch.setattr(m, "_IPV6_SYSCTL_DIR", tmp_path)
        assert _read_kernel_ipv6() == (False, True)

    def test_disable_ipv6_set_to_zero_reads_as_on(self, monkeypatch, tmp_path):
        f = tmp_path / "disable_ipv6"; f.write_text("0\n")
        monkeypatch.setattr(m, "_IPV6_DISABLE_ALL", f)
        monkeypatch.setattr(m, "_IPV6_SYSCTL_DIR", tmp_path)
        assert _read_kernel_ipv6() == (True, True)

    def test_an_unreadable_file_in_a_present_tree_is_unknown(self, monkeypatch, tmp_path):
        """Distinct from an absent tree: here IPv6 may well be running."""
        class Boom:
            def read_text(self, **kw): raise PermissionError("nope")
        monkeypatch.setattr(m, "_IPV6_DISABLE_ALL", Boom())
        monkeypatch.setattr(m, "_IPV6_SYSCTL_DIR", tmp_path)   # exists
        assert _read_kernel_ipv6() == (True, False)

    def test_another_oserror_with_no_tree_is_still_off(self, monkeypatch, tmp_path):
        """A read can fail with something other than FileNotFoundError —
        NotADirectoryError, say — while the tree is nonetheless absent. The
        conclusion is the same and must not degrade to "unknown": found by a
        mutation that removed this branch and survived the first version of
        this file."""
        class Boom:
            def read_text(self, **kw): raise NotADirectoryError("not a dir")
        monkeypatch.setattr(m, "_IPV6_DISABLE_ALL", Boom())
        monkeypatch.setattr(m, "_IPV6_SYSCTL_DIR", tmp_path / "absent")
        assert _read_kernel_ipv6() == (False, True)

    def test_the_real_host_is_readable(self):
        enabled, readable = _read_kernel_ipv6()
        assert readable is True
        assert isinstance(enabled, bool)


class TestUnknownIsSaidOutLoud:
    def test_an_unknown_state_produces_its_own_finding(self):
        keys = _keys(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True,
                     kernel_ipv6_readable=False)
        assert "ipv6.kernel_state_unknown" in keys

    def test_a_known_state_does_not(self):
        keys = _keys(kernel_ipv6_enabled=True, ufw_ipv6_enabled=True)
        assert "ipv6.kernel_state_unknown" not in keys

    @pytest.mark.parametrize("enabled", [True, False])
    def test_the_matrix_still_runs_when_the_state_is_unknown(self, enabled):
        """The unknown notice is added to the verdict, it does not replace it —
        the cautious reading still has to be computed."""
        keys = _keys(kernel_ipv6_enabled=enabled, ufw_ipv6_enabled=True,
                     kernel_ipv6_readable=False)
        assert len(keys) >= 2
