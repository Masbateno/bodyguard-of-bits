"""v0.24.1 — a refused FUSE mount point is not an incomplete sweep.

The Mint desktop audit ended "world-writable sweep incomplete — some directories
could not be read", which capped the score (≤ 9/10). find exits non-zero for
any path it cannot look at, and BOB read the exit status alone. The desktop had
a FUSE mount owned by the user (``/tmp/.mount_kDrive…``, an AppImage) — without
``allow_other`` the kernel refuses even root on it, while FUSE filesystems are
excluded from the sweep by design. Errors at or under an excluded mount point
are no longer blindness; any other error still is.
"""

from __future__ import annotations

import bob.checks.world_writable as ww
from bob.checks.world_writable import WorldWritableSnapshot, _unexplained_errors

_FUSE = "/tmp/.mount_kDriveMKHmFl"


def test_gnu_error_on_skipped_mount_point_is_explained():
    err = f"find: '{_FUSE}': Permission denied\n".encode()
    assert not _unexplained_errors(err, [_FUSE])


def test_real_gnu_line_with_absolute_argv0_is_understood():
    # Verbatim from the real Mint 22.3 run: BOB runs find by absolute path, so
    # find names itself "/usr/bin/find". A "find: " prefix test missed it and
    # the field run stayed "incomplete".
    err = b"/usr/bin/find: '/home/so6/fusemnt': Permission denied\n"
    assert not _unexplained_errors(err, ["/home/so6/fusemnt"])


def test_busybox_error_format_is_understood():
    err = f"find: {_FUSE}: Permission denied\n".encode()
    assert not _unexplained_errors(err, [_FUSE])


def test_error_under_a_skipped_mount_is_explained():
    err = b"find: '/run/user/1000/doc/by-app': Permission denied\n"
    assert not _unexplained_errors(err, ["/run/user/1000/doc"])


def test_error_on_a_swept_path_is_blindness():
    err = f"find: '{_FUSE}': Permission denied\nfind: '/var/lib/secret': Permission denied\n".encode()
    assert _unexplained_errors(err, [_FUSE])


def test_a_name_prefix_is_not_containment():
    err = b"find: '/tmp/.mount_ab': Permission denied\n"
    assert _unexplained_errors(err, ["/tmp/.mount_a"])


def test_failure_without_a_named_error_is_blindness():
    assert _unexplained_errors(b"", [_FUSE])


def _sweep(monkeypatch, script: str) -> WorldWritableSnapshot:
    monkeypatch.setattr(ww, "build_command", lambda *a: ["sh", "-c", script])
    monkeypatch.setattr(ww, "_is_gnu_find", lambda f: True)
    monkeypatch.setattr(ww, "_skipped_mount_points", lambda: [_FUSE])
    return WorldWritableSnapshot.from_system()


def test_sweep_with_only_a_fuse_refusal_is_complete(monkeypatch):
    snap = _sweep(monkeypatch, f"echo \"find: '{_FUSE}': Permission denied\" >&2; exit 1")
    assert snap.partial is False


def test_sweep_with_another_refusal_stays_partial(monkeypatch):
    snap = _sweep(monkeypatch, "echo \"find: '/srv/x': Permission denied\" >&2; exit 1")
    assert snap.partial is True
