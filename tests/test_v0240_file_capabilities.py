"""File capabilities — the privilege the SUID audit cannot see.

The guard pins:

  1. the raw ``security.capability`` value decodes to the right names, for the
     three on-disk revisions, from bytes measured on real binaries;
  2. a root-equivalent capability on a binary not known to need it is a WARN
     with a deduction — including a *known* name that carries more than its
     known set (ping with cap_setuid is not iputils);
  3. any other capability on an unknown binary is INFO, never scored;
  4. a partial walk never says "no unexpected capability", and no root at all
     is "unknown", not clean;
  5. ``from_system`` walks each tree once, reports a listing failure or an
     attribute it could not read as partial, treats ENODATA as "none", and
     stops at the time budget instead of hanging the audit.
"""

from __future__ import annotations

import errno
import os

import pytest

import bob.checks.file_capabilities as fc
from bob.checks.file_capabilities import (
    FileCapabilitiesSnapshot,
    check_file_capabilities,
    decode_capabilities,
)
from tests.helpers import _t

# Read back from real binaries (Ubuntu 24.04 / Fedora 44 hosts).
_PING_RAW = bytes.fromhex("0100000200200000000000000000000000000000")      # net_raw
_PTP_RAW = bytes.fromhex("0100000200148000000000000000000000000000")       # 3 caps


def _keys(result):
    return [f.key for f in result.findings]


def _points(result):
    return sum(d.points for d in result.deductions)


def _snap(*entries, partial=False):
    return FileCapabilitiesSnapshot(
        entries=[(p, frozenset(c)) for p, c in entries],
        files_seen=1000, scan_partial=partial)


# ---- decoding -----------------------------------------------------------------

class TestDecode:
    def test_measured_ping_value(self):
        assert decode_capabilities(_PING_RAW) == {"net_raw"}

    def test_measured_gst_ptp_helper_value(self):
        assert decode_capabilities(_PTP_RAW) == {"net_bind_service", "net_admin", "sys_nice"}

    def test_revision_one_single_word(self):
        raw = (0x01000000).to_bytes(4, "little") + (1 << 7).to_bytes(4, "little") + bytes(4)
        assert decode_capabilities(raw) == {"setuid"}

    def test_revision_three_reads_the_high_word(self):
        # mac_override is bit 32 — it lives in the second permitted word.
        raw = ((0x03000000).to_bytes(4, "little") + bytes(4) + bytes(4)
               + (1).to_bytes(4, "little") + bytes(4) + bytes(4))
        assert decode_capabilities(raw) == {"mac_override"}

    @pytest.mark.parametrize("raw", [b"", b"\x01\x00", bytes(20),
                                     (0x04000000).to_bytes(4, "little") + bytes(16),
                                     (0x02000000).to_bytes(4, "little") + bytes(4)])
    def test_unparseable_is_none_not_empty(self, raw):
        assert decode_capabilities(raw) is None


# ---- classification ----------------------------------------------------------

class TestClassify:
    def test_distribution_grants_are_ok(self):
        r = check_file_capabilities(_snap(
            ("/usr/bin/ping", {"net_raw"}),
            ("/usr/bin/mtr-packet", {"net_raw", "net_bind_service"}),
            ("/usr/bin/newuidmap", {"setuid"}),
            ("/usr/bin/dumpcap", {"dac_override", "net_admin", "net_raw"}),
            # Fedora 44 Server, full install (measured): sssd, httpd, KDE.
            ("/usr/libexec/sssd/krb5_child", {"dac_read_search", "setgid", "setuid"}),
            ("/usr/libexec/sssd/ldap_child", {"dac_read_search"}),
            ("/usr/libexec/sssd/selinux_child", {"setgid", "setuid"}),
            ("/usr/libexec/sssd/sssd_pam", {"dac_read_search"}),
            ("/usr/bin/suexec", {"setgid", "setuid"}),
            ("/usr/bin/kwin_wayland", {"sys_nice"}),
            ("/usr/libexec/ksystemstats_intel_helper", {"perfmon"}),
            # Ubuntu Server 26.04, snapd 2.77.1 (measured).
            ("/usr/lib/snapd/snap-confine", {"chown", "dac_override", "dac_read_search",
                                             "fowner", "setgid", "setuid", "sys_admin",
                                             "sys_chroot", "sys_ptrace", "sys_resource"}),
        ), t=_t)
        assert _keys(r) == ["file_capabilities.ok"]
        assert _points(r) == 0

    def test_setuid_on_an_interpreter_deducts(self):
        r = check_file_capabilities(_snap(("/usr/bin/python3.12", {"setuid"})), t=_t)
        assert "file_capabilities.root_equivalent" in _keys(r)
        assert _points(r) == 1
        assert "file_capabilities.ok" not in _keys(r)

    def test_known_name_with_more_than_its_set_is_not_known(self):
        r = check_file_capabilities(_snap(("/usr/bin/ping", {"net_raw", "setuid"})), t=_t)
        assert "file_capabilities.root_equivalent" in _keys(r)

    def test_harmless_capability_on_unknown_binary_is_info_only(self):
        r = check_file_capabilities(
            _snap(("/opt/expressvpn/bin/expressvpn-unbound", {"net_bind_service"})), t=_t)
        assert "file_capabilities.unexpected" in _keys(r)
        assert _points(r) == 0
        assert "file_capabilities.ok" not in _keys(r)

    def test_partial_walk_never_claims_clean(self):
        r = check_file_capabilities(_snap(("/usr/bin/ping", {"net_raw"}), partial=True), t=_t)
        assert "file_capabilities.partial" in _keys(r)
        assert "file_capabilities.ok" not in _keys(r)

    def test_partial_walk_still_reports_what_it_saw(self):
        r = check_file_capabilities(_snap(("/tmp/x", {"sys_admin"}), partial=True), t=_t)
        assert {"file_capabilities.root_equivalent", "file_capabilities.partial"} <= set(_keys(r))

    def test_no_root_is_unknown(self):
        r = check_file_capabilities(FileCapabilitiesSnapshot(scan_skipped=True), t=_t)
        assert _keys(r) == ["file_capabilities.unknown"]


# ---- from_system -------------------------------------------------------------

@pytest.fixture
def fake_xattr(monkeypatch):
    """Map basename -> raw value (bytes) or errno (int); default ENODATA."""
    table: "dict[str, bytes | int]" = {}

    def _getxattr(path, name, *, follow_symlinks=True):
        assert name == "security.capability"
        assert follow_symlinks is False
        v = table.get(os.path.basename(path), errno.ENODATA)
        if isinstance(v, int):
            raise OSError(v, os.strerror(v), path)
        return v
    monkeypatch.setattr(fc.os, "getxattr", _getxattr)
    return table


def _tree(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("ping", "ls", "python3"):
        (bindir / name).write_text("")
    return bindir


def test_from_system_reads_and_decodes(tmp_path, fake_xattr):
    bindir = _tree(tmp_path)
    fake_xattr["ping"] = _PING_RAW
    snap = FileCapabilitiesSnapshot.from_system(_roots=(str(bindir),))
    assert snap.entries == [(str(bindir / "ping"), frozenset({"net_raw"}))]
    assert snap.files_seen == 3
    assert not snap.scan_partial


def test_from_system_walks_a_symlinked_root_once(tmp_path, fake_xattr):
    bindir = _tree(tmp_path)
    (tmp_path / "alias").symlink_to(bindir)
    fake_xattr["ping"] = _PING_RAW
    snap = FileCapabilitiesSnapshot.from_system(_roots=(str(tmp_path / "alias"), str(bindir)))
    assert snap.files_seen == 3
    assert len(snap.entries) == 1


def test_from_system_unreadable_attribute_is_partial(tmp_path, fake_xattr):
    bindir = _tree(tmp_path)
    fake_xattr["python3"] = errno.EACCES
    snap = FileCapabilitiesSnapshot.from_system(_roots=(str(bindir),))
    assert snap.scan_partial


def test_from_system_no_xattr_support_is_not_partial(tmp_path, fake_xattr):
    bindir = _tree(tmp_path)
    fake_xattr["ls"] = errno.ENOTSUP
    snap = FileCapabilitiesSnapshot.from_system(_roots=(str(bindir),))
    assert not snap.scan_partial


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists a 0000 directory anyway")
def test_from_system_unlistable_directory_is_partial(tmp_path, fake_xattr):
    bindir = _tree(tmp_path)
    locked = bindir / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        snap = FileCapabilitiesSnapshot.from_system(_roots=(str(bindir),))
    finally:
        locked.chmod(0o755)
    assert snap.scan_partial


def test_from_system_stops_at_the_time_budget(tmp_path, fake_xattr, monkeypatch):
    bindir = _tree(tmp_path)
    monkeypatch.setattr(fc, "_BUDGET_EVERY", 1)
    snap = FileCapabilitiesSnapshot.from_system(_roots=(str(bindir),), _budget=-1)
    assert snap.scan_partial
    assert snap.files_seen == 1


def test_from_system_no_root_is_skipped(tmp_path, fake_xattr):
    snap = FileCapabilitiesSnapshot.from_system(_roots=(str(tmp_path / "absent"),))
    assert snap.scan_skipped
