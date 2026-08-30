"""
v0.15.0 — the SYSTEM HARDENING section reported ten passes for ten parameters
it had not read.

`_read_sysctl_int(key, default)` and `_read_sysctl_bool(key, default)` returned
the default on any read failure, and every one of the ten call sites passed the
*hardened* value:

    rp_filter                    default=1
    accept_redirects             default=False
    log_martians                 default=True
    icmp_echo_ignore_broadcasts  default=True
    tcp_syncookies               default=1
    accept_source_route          default=False
    accept_redirects_v6          default=False
    send_redirects               default=False
    protected_hardlinks          default=True
    protected_symlinks           default=True

So an unreadable /proc/sys produced a perfectly hardened network stack. The
realistic trigger is not exotic: boot with `ipv6.disable=1` and
`/proc/sys/net/ipv6` does not exist at all, so `net.ipv6.conf.all.accept_redirects`
was answered from the default alone — and BOB's own IPv6 check already treats a
disabled IPv6 stack as an ordinary state.

Same defect as kernel_hardening, ten knobs wide instead of five. The JSON
`hardening` block now mirrors an unread parameter as `null` rather than
asserting a value it never saw.
"""

from __future__ import annotations

import pytest

import bob.checks.hardening as h
from bob.checks.hardening import HardeningSnapshot, check_hardening

_ALL_FIELDS = (
    "rp_filter", "accept_redirects", "log_martians",
    "icmp_echo_ignore_broadcasts", "tcp_syncookies", "accept_source_route",
    "accept_redirects_v6", "send_redirects", "protected_hardlinks",
    "protected_symlinks",
)

_HARDENED = dict(
    rp_filter=1, accept_redirects=False, log_martians=True,
    icmp_echo_ignore_broadcasts=True, tcp_syncookies=1,
    accept_source_route=False, accept_redirects_v6=False,
    send_redirects=False, protected_hardlinks=True, protected_symlinks=True,
)


def _keys(**overrides) -> list[str]:
    return [f.key for f in
            check_hardening(HardeningSnapshot(**{**_HARDENED, **overrides})).findings]


class TestNothingIsAssumedBeforeARead:
    def test_the_bare_snapshot_carries_no_opinion(self):
        snap = HardeningSnapshot()
        assert all(getattr(snap, f) is None for f in _ALL_FIELDS)

    def test_an_unread_parameter_produces_no_pass(self):
        keys = _keys(accept_redirects_v6=None)
        assert "hardening.accept_redirects_v6_ok" not in keys
        assert "hardening.params_unavailable" in keys

    def test_an_unread_parameter_produces_no_deduction(self):
        """An absent parameter is not set to a weak value; it is absent."""
        result = check_hardening(HardeningSnapshot())
        assert result.deductions == []

    def test_everything_unread_gives_one_finding_not_ten(self):
        assert _keys(**dict.fromkeys(_ALL_FIELDS)) == ["hardening.params_unavailable"]

    def test_the_message_names_the_missing_sysctls(self):
        result = check_hardening(HardeningSnapshot(**{**_HARDENED,
                                                     "accept_redirects_v6": None,
                                                     "tcp_syncookies": None}))
        msg = next(f.message for f in result.findings
                   if f.key == "hardening.params_unavailable")
        assert "net.ipv6.conf.all.accept_redirects" in msg
        assert "net.ipv4.tcp_syncookies" in msg

    @pytest.mark.parametrize("field", _ALL_FIELDS)
    def test_every_field_is_guarded_not_just_the_ipv6_one(self, field):
        """The defect was uniform across all ten, so the guard must be too."""
        keys = _keys(**{field: None})
        assert "hardening.params_unavailable" in keys, \
            f"{field} unread did not surface as unavailable"


class TestTheOrdinaryPathIsUnchanged:
    def test_a_fully_hardened_host_still_passes_everything(self):
        keys = _keys()
        assert "hardening.params_unavailable" not in keys
        assert len(keys) == 10

    def test_real_weaknesses_are_still_scored(self):
        result = check_hardening(HardeningSnapshot(
            rp_filter=0, accept_redirects=True, log_martians=False,
            icmp_echo_ignore_broadcasts=False, tcp_syncookies=0,
            accept_source_route=True, accept_redirects_v6=True,
            send_redirects=True, protected_hardlinks=False,
            protected_symlinks=False))
        assert sum(d.points for d in result.deductions) > 0
        assert "hardening.params_unavailable" not in [f.key for f in result.findings]


class TestReaders:
    def test_a_missing_path_reads_as_none(self, monkeypatch):
        class FakePath:
            def __init__(self, p): self.p = str(p)
            def __truediv__(self, o): return FakePath(self.p + "/" + str(o))
            def read_text(self, **kw): raise FileNotFoundError(self.p)
        monkeypatch.setattr(h, "Path", FakePath)
        assert h._read_sysctl_bool("net.ipv6.conf.all.accept_redirects") is None
        assert h._read_sysctl_int("net.ipv4.tcp_syncookies") is None

    def test_a_real_key_still_reads_a_value(self):
        """net.ipv4.conf.all.rp_filter exists on every Linux BOB supports."""
        assert isinstance(h._read_sysctl_int("net.ipv4.conf.all.rp_filter"), int)
