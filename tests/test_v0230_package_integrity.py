"""Package-integrity check — the first consumer of ``--exhaustive``.

INFO-only by design: a file that differs from its package's recorded digest is a
signal, not a verdict (a local recompile looks identical to tampering). The guard
pins the three doctrine properties:

  1. unknown != clean — a missing verifier or a timeout reports "not verified",
     never "clean", and those states count as reduced visibility.
  2. configuration files are excluded — they are expected to be edited.
  3. the digest change is the signal — an mtime-only difference is not reported.

The parser samples below are the documented output shapes of each verifier;
``tests/`` has no package manager to run, so the real-output round-trip lives in
the field-test protocol (podman debian/fedora/alpine/arch).
"""

from __future__ import annotations

from bob.checks.package_integrity import (
    PackageIntegritySnapshot,
    _parse_apk,
    _parse_debsums,
    _parse_pacman,
    _parse_rpm,
    check_package_integrity,
)
from tests.helpers import _keys, _levels, _t


# ---------------------------------------------------------------------------
# Parsers — config filtered, digest change is the signal
# ---------------------------------------------------------------------------

class TestRpmParser:
    _OUT = (
        "S.5....T.  c /etc/sudoers\n"          # config — excluded
        "S.5....T.  c /usr/lib/foo/foo.conf\n"  # config OUTSIDE /etc — excluded by the 'c' flag alone
        "..5....T.    /usr/bin/sudo\n"         # digest change — reported
        ".......T.    /usr/bin/mtime-only\n"   # mtime only, no digest — not reported
        "S.5....T.  d /usr/share/doc/x/README\n"  # doc — excluded
        "missing      /usr/lib/gone.so\n"      # missing, no digest flag — not reported
    )

    def test_only_digest_changed_regular_files(self):
        assert _parse_rpm(self._OUT) == ["/usr/bin/sudo"]

    def test_config_marked_c_is_excluded(self):
        # The non-/etc config file isolates the 'c'-flag exclusion from the
        # path-based /etc filter: only the flag check keeps it out.
        assert "/usr/lib/foo/foo.conf" not in _parse_rpm(self._OUT)
        assert "/etc/sudoers" not in _parse_rpm(self._OUT)


class TestDebsumsParser:
    _OUT = "/usr/bin/sudo\n/etc/sudoers\n/usr/lib/x.so\n"

    def test_lists_changed_non_config_paths(self):
        assert _parse_debsums(self._OUT) == ["/usr/bin/sudo", "/usr/lib/x.so"]

    def test_etc_is_excluded(self):
        assert "/etc/sudoers" not in _parse_debsums(self._OUT)


class TestApkParser:
    _OUT = "U usr/bin/foo\nA etc/newfile\nU etc/edited.conf\nD usr/lib/gone\n"

    def test_only_updated_non_config(self):
        assert _parse_apk(self._OUT) == ["/usr/bin/foo"]


class TestPacmanParser:
    # Real `pacman -Qkk` shape: several lines per file, one per attribute.
    _OUT = (
        "warning: coreutils: /usr/bin/foo (Modification time mismatch)\n"
        "warning: coreutils: /usr/bin/foo (Size mismatch)\n"
        "warning: coreutils: /usr/bin/foo (SHA256 checksum mismatch)\n"
        "warning: pkg: /etc/foo.conf (SHA256 checksum mismatch)\n"
        "bar: 0 altered files\n"
    )

    def test_one_finding_per_file_size_or_checksum_only(self):
        # de-duplicated across the three lines; /etc excluded
        assert _parse_pacman(self._OUT) == ["/usr/bin/foo"]

    def test_mtime_only_mismatch_is_not_reported(self):
        assert _parse_pacman(
            "warning: p: /usr/bin/x (Modification time mismatch)\n") == []


# ---------------------------------------------------------------------------
# Check logic — INFO-only, unknown != clean
# ---------------------------------------------------------------------------

class TestCheckLogic:
    def test_tool_missing_is_not_clean(self):
        snap = PackageIntegritySnapshot(manager="apt", tool="debsums",
                                        tool_available=False)
        result = check_package_integrity(snap, t=_t)
        assert "package_integrity.tool_missing" in _keys(result)
        # never a deduction, never an "ok/clean"
        assert result.deductions == []
        assert "package_integrity.clean" not in _keys(result)

    def test_timeout_is_not_clean(self):
        snap = PackageIntegritySnapshot(manager="dnf", tool="rpm",
                                        tool_available=True, timed_out=True)
        result = check_package_integrity(snap, t=_t)
        assert "package_integrity.timed_out" in _keys(result)
        assert "package_integrity.clean" not in _keys(result)

    def test_changed_files_report_is_info_not_a_deduction(self):
        snap = PackageIntegritySnapshot(
            manager="dnf", tool="rpm", tool_available=True, ran=True,
            changed_files=["/usr/bin/sudo", "/usr/lib/x.so"],
        )
        result = check_package_integrity(snap, t=_t)
        assert "package_integrity.changed" in _keys(result)
        assert "info" in _levels(result)
        assert result.deductions == []

    def test_clean_when_verified_and_nothing_changed(self):
        snap = PackageIntegritySnapshot(
            manager="dnf", tool="rpm", tool_available=True, ran=True,
            changed_files=[],
        )
        result = check_package_integrity(snap, t=_t)
        assert "package_integrity.clean" in _keys(result)

    def test_unknown_manager_is_unsupported_not_clean(self):
        snap = PackageIntegritySnapshot(manager="", tool="")
        result = check_package_integrity(snap, t=_t)
        assert "package_integrity.unsupported" in _keys(result)
        assert "package_integrity.clean" not in _keys(result)
