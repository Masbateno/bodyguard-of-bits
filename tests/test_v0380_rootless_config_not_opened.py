"""v0.38.0 — a user's config.json is looked at before root opens it.

BOB reads a rootless container's configuration as root through the user's own
mount namespace (``/proc/<shim>/cwd``, ``/proc/<dockerd>/root``,
``/proc/<conmon>/root``), where an unprivileged user can bind-mount a device
node over the file. 0.36.0-0.37.0 opened it ``O_RDONLY|O_NONBLOCK`` and refused
it after ``fstat``: the open() had already reached the device.

Measured (16 November 2026) on the test Linux Mint 22.3
(kernel.apparmor_restrict_unprivileged_userns = 0), a10380/c2-device-open-*:
a plain account, no Docker installed, `unshare -Urm`, `/dev/null` bound over
~/bundle/config.json, then `exec -a containerd-shim-runc-v2 … -namespace moby
-id <64 hex>` from that directory. strace of BOB as root:
- 0.37.0: openat("/proc/<pid>/cwd/config.json", O_RDONLY|O_NONBLOCK|O_NOFOLLOW) = 3
- 0.38.0: openat(…, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH) = 3, nothing else;
  with a regular config.json: O_PATH, then /proc/self/fd/3 O_RDONLY, read.
"""

from __future__ import annotations

import json
import os

from bob.checks import _rootless_oci as R


def _spy(monkeypatch):
    calls = []
    real = os.open

    def spy(path, flags, *a, **k):
        calls.append((str(path), flags))
        return real(path, flags, *a, **k)
    monkeypatch.setattr(R.os, "open", spy)
    return calls


def test_a_device_is_never_opened(monkeypatch):
    calls = _spy(monkeypatch)
    assert R.read_config(R.Path("/dev/null"), os.stat("/dev/null").st_uid) is None
    on_dev = [f for p, f in calls if p == "/dev/null"]
    assert on_dev and all(f & os.O_PATH for f in on_dev), calls
    assert not any(p.startswith("/proc/self/fd/") for p, _ in calls), "a device must not be reopened"


def test_a_fifo_is_never_opened(tmp_path, monkeypatch):
    fifo = tmp_path / "config.json"
    os.mkfifo(fifo)
    calls = _spy(monkeypatch)
    assert R.read_config(fifo, os.getuid()) is None
    assert all(f & os.O_PATH for p, f in calls if p == str(fifo))
    assert not any(p.startswith("/proc/self/fd/") for p, _ in calls)


def test_a_regular_file_of_the_user_is_still_read(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"ociVersion": "1.0.2"}))
    calls = _spy(monkeypatch)
    assert R.read_config(cfg, os.getuid()) == {"ociVersion": "1.0.2"}
    assert [f & os.O_PATH for p, f in calls if p == str(cfg)] == [os.O_PATH]
    assert any(p.startswith("/proc/self/fd/") for p, _ in calls)


def test_a_final_symlink_is_not_followed(tmp_path):
    target = tmp_path / "real.json"
    target.write_text("{}")
    link = tmp_path / "config.json"
    link.symlink_to(target)
    assert R.read_config(link, os.getuid()) is None


def test_the_reopened_file_must_be_the_inspected_one(tmp_path, monkeypatch):
    cfg, other = tmp_path / "config.json", tmp_path / "other.json"
    cfg.write_text("{}")
    other.write_text(json.dumps({"planted": True}))
    real = os.open

    def swap(path, flags, *a, **k):
        if str(path).startswith("/proc/self/fd/"):
            return real(other, os.O_RDONLY)
        return real(path, flags, *a, **k)
    monkeypatch.setattr(R.os, "open", swap)
    assert R.read_config(cfg, os.getuid()) is None


def test_no_proc_self_fd_means_not_read(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    real = os.open

    def deny(path, flags, *a, **k):
        if str(path).startswith("/proc/self/fd/"):
            raise PermissionError(13, "denied")
        return real(path, flags, *a, **k)
    monkeypatch.setattr(R.os, "open", deny)
    assert R.read_config(cfg, os.getuid()) is None
