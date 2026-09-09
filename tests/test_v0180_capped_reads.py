"""A reader written to prevent an OOM could not read a sysctl, and BOB read
`/etc/shadow` without a cap at all.

Stress pass 2 — a fabricated `/etc` bind-mounted over the real one inside a
mount namespace. Every hostile element passed *functionally*, and the peak
resident set gave it away:

    /etc healthy                        113 MB
    /etc hostile (full)                2683 MB
    /etc/shadow -> /dev/zero alone     2621 MB

`user_accounts` read `/etc/shadow` with a bare `Path.read_text()`, which is
unbounded. Pointed at a character device it reads NUL bytes for as long as it
is allowed to: on the maintainer's host, under memory pressure, the kernel
OOM-killed python3 at 7.3 GB RSS.

`bob/_atomic.read_text_capped` exists for exactly this, and its docstring says
so — v0.14.1 measured the same failure on state files. The lesson was applied
to that one family and never generalised: 42 bare reads remained in the checks.

Converting them exposed a second defect, latent since v0.14.1. The capped
reader asked for its whole cap in one `read(8388609)`, and procfs allocates a
buffer the size of the request::

    read(8388609) -> OSError errno 12
    read(1048576) -> "2\\n"

So the reader written to keep BOB from reading a device until it died could not
read a single `/proc/sys` knob. It reads in chunks now.

Scope, deliberately: the checks that read `/proc` and `/sys` keep the bare
reader. Those paths are kernel-generated, bounded by the kernel, and cannot be
a symlink to a device — the risk measured here is on real filesystem paths.
"""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from bob._atomic import _DEFAULT_READ_CAP, _READ_CHUNK, read_text_capped


class TestItReadsPseudoFilesystems:
    """The latent v0.14.1 defect: one big read(2) that procfs refuses."""

    def test_no_single_read_asks_for_the_whole_cap(self):
        assert _READ_CHUNK < _DEFAULT_READ_CAP, (
            "the reader asks for its whole cap in one read(2); procfs "
            "allocates a buffer that size and refuses it with ENOMEM"
        )
        assert _READ_CHUNK <= 1024 * 1024, (
            "1 MiB is the largest request measured to succeed on procfs"
        )

    def test_a_file_that_refuses_a_large_read_is_still_read(self, tmp_path,
                                                            monkeypatch):
        """Deterministic twin of the live /proc case.

        A live-system test alone would pass here and fail on a CI box with a
        different procfs, so the behaviour is pinned against a stand-in that
        raises ENOMEM above the threshold, exactly as procfs does.
        """
        target = tmp_path / "knob"
        target.write_text("2\n")
        real_open = Path.open

        class _ProcfsLike:
            def __init__(self, fh): self._fh = fh
            def read(self, n=-1):
                if n > 1024 * 1024:
                    raise OSError(errno.ENOMEM, "Cannot allocate memory")
                return self._fh.read(n)
            def __enter__(self): return self
            def __exit__(self, *a): self._fh.close(); return False

        def fake_open(self, *a, **k):
            return _ProcfsLike(real_open(self, *a, **k))

        monkeypatch.setattr(Path, "open", fake_open)
        assert read_text_capped(target) == "2\n"

    @pytest.mark.skipif(not Path("/proc/sys/net/ipv4/ip_forward").exists(),
                        reason="no procfs on this host")
    def test_a_real_sysctl_reads(self):
        """The live case, kept beside the deterministic one rather than alone."""
        value = read_text_capped(Path("/proc/sys/net/ipv4/ip_forward"))
        assert value.strip() in ("0", "1")


class TestItStillRefusesWhatItWasWrittenFor:
    def test_a_character_device_is_refused(self):
        with pytest.raises(OSError):
            read_text_capped(Path("/dev/zero"))

    def test_a_directory_is_refused(self, tmp_path):
        with pytest.raises(OSError):
            read_text_capped(tmp_path)

    def test_a_missing_file_is_refused(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            read_text_capped(tmp_path / "nope")

    def test_a_file_over_the_cap_is_refused(self, tmp_path):
        big = tmp_path / "big"
        big.write_text("x" * 128)
        with pytest.raises(OSError):
            read_text_capped(big, max_bytes=64)

    def test_a_file_exactly_at_the_cap_is_read(self, tmp_path):
        exact = tmp_path / "exact"
        exact.write_text("x" * 64)
        assert len(read_text_capped(exact, max_bytes=64)) == 64

    def test_a_file_spanning_several_chunks_is_whole(self, tmp_path):
        many = tmp_path / "many"
        content = "y" * (_READ_CHUNK * 2 + 7)
        many.write_text(content)
        assert read_text_capped(many) == content, (
            "chunked reading must reassemble the file, not truncate at a chunk"
        )


class TestTheChecksThatReadRealPathsAreCapped:
    """`/etc/shadow -> /dev/zero` cost 2.6 GB before this."""

    _SRC = Path(__file__).resolve().parent.parent / "bob" / "checks"

    @pytest.mark.parametrize("module", [
        "user_accounts", "cron_audit", "password_policy", "ssl_certs",
        "file_perms", "auth_log", "ddns", "systemd_timers",
    ])
    def test_it_uses_the_capped_reader(self, module):
        src = (self._SRC / f"{module}.py").read_text(encoding="utf-8")
        code = "\n".join(ln for ln in src.splitlines()
                         if not ln.strip().startswith("#"))
        assert "read_text_capped" in code, f"{module} reads without a cap"
        assert ".read_text(" not in code, (
            f"{module} still has a bare read_text(); pointed at a device it "
            "reads until the process dies"
        )

    def test_shadow_and_passwd_are_among_them(self):
        src = (self._SRC / "user_accounts.py").read_text(encoding="utf-8")
        assert src.count("read_text_capped") >= 2, (
            "both /etc/passwd and /etc/shadow are read; measured at 2.6 GB "
            "peak RSS with shadow symlinked to /dev/zero"
        )


class TestThePseudoFilesystemReadersAreLeftAlone:
    """A decision, so it is asserted rather than assumed.

    /proc and /sys are kernel-generated, bounded, and cannot be a symlink to a
    device. Capping them bought nothing and broke every sysctl probe.
    """

    _SRC = Path(__file__).resolve().parent.parent / "bob" / "checks"

    @pytest.mark.parametrize("module", [
        "hardening", "kernel_hardening", "ipv6", "mac_policy", "memory",
    ])
    def test_they_keep_the_bare_reader(self, module):
        src = (self._SRC / f"{module}.py").read_text(encoding="utf-8")
        assert ".read_text(" in src, (
            f"{module} was converted; it reads /proc or /sys, where the cap "
            "buys nothing and the conversion broke every probe"
        )
