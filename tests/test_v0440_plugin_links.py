"""v0.44.0 — a plugin is never opened through a link, nor outside the caller's home.

Found after the external review of the 0.44.0 changelog (27 November 2026):
BOB, root under sudo, read each plugin of the calling user's checks.d by its
name, following links — in the parent (the syntax check) and in the child
(before giving up root). A link there to a root-only file was read by root:
the family of the 0.26.1 fix. Now the parent refuses a link and a plugin that
resolves outside the calling user's home; the child opens without following
the last component, accepts a regular file only, and only the one the parent
resolved, inside that home.

The child's refusals come before it strips anything, so they run here in the
test's own process.
"""

from __future__ import annotations

import os
import queue

import pytest

from bob import _sandbox as sb
from bob import plugin_checks as pc
from bob import sysinfo

_PLUGIN = "CHECK_NAME = 'x'\n\ndef run_check():\n    return None\n"


def _key(q):
    status, payload = q.get_nowait()
    assert status == "error"
    return payload["key"]


@pytest.fixture
def plugin(tmp_path):
    p = tmp_path / "real.py"
    p.write_text(_PLUGIN)
    return p


def test_the_parent_refuses_a_linked_plugin(tmp_path, plugin, caplog):
    link = tmp_path / "linked.py"
    link.symlink_to(plugin)
    assert pc._load_one(link) is None
    # Said by the check itself, not only by the O_PATH open behind it.
    assert "a symbolic link — skipped" in caplog.text
    assert pc._load_one(plugin) is not None                  # the file itself is fine


def test_the_parent_refuses_a_plugin_outside_the_callers_home(tmp_path, monkeypatch, caplog):
    home, elsewhere = tmp_path / "home", tmp_path / "root-only"
    (home / ".config" / "bob").mkdir(parents=True)
    elsewhere.mkdir()
    (elsewhere / "p.py").write_text(_PLUGIN)
    (home / ".config" / "bob" / "checks.d").symlink_to(elsewhere)   # the directory linked
    monkeypatch.setattr(sysinfo, "invoking_user_name", lambda: "alice")
    monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
    assert pc._load_one(home / ".config" / "bob" / "checks.d" / "p.py") is None
    assert "resolves outside the calling user's home" in caplog.text


def test_the_child_does_not_follow_a_link(tmp_path, plugin):
    link = tmp_path / "linked.py"
    link.symlink_to(plugin)
    q = queue.Queue()
    # A second refusal behind the one tested (expected elsewhere): were the
    # link followed, the plugin would still not run in this test's process.
    sb._worker_main(str(link), q, None, "/nonexistent/elsewhere.py")
    assert _key(q) == "plugin.sandbox.not_run_link"


def test_the_child_runs_only_the_file_the_parent_resolved(plugin, tmp_path):
    q = queue.Queue()
    sb._worker_main(str(plugin), q, None, str(tmp_path / "another.py"), "/nonexistent-home")
    assert _key(q) == "plugin.sandbox.not_run_replaced"


def test_the_child_refuses_a_plugin_outside_the_callers_home(plugin, tmp_path):
    q = queue.Queue()
    sb._worker_main(str(plugin), q, None, os.path.realpath(plugin), str(tmp_path / "home-of-alice"))
    assert _key(q) == "plugin.sandbox.not_run_outside_home"


def test_the_child_refuses_what_is_not_a_regular_file(tmp_path):
    fifo = tmp_path / "p.py"
    os.mkfifo(fifo)
    q = queue.Queue()
    sb._worker_main(str(fifo), q, None, "/nonexistent/elsewhere.py")
    assert _key(q) == "plugin.sandbox.not_run_not_regular"


def test_the_place_is_resolved_by_the_parent_and_the_home_only_for_another_user(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(sysinfo, "invoking_user_name", lambda: None)
    assert sb._plugin_place(plugin) == (os.path.realpath(plugin), None)
    monkeypatch.setattr(sysinfo, "invoking_user_name", lambda: "alice")
    monkeypatch.setattr(sysinfo, "get_user_home", lambda: tmp_path)
    assert sb._plugin_place(plugin)[1] == os.path.realpath(tmp_path)


@pytest.mark.parametrize("key", ["link", "not_regular", "replaced", "outside_home", "unopened"])
def test_each_refusal_is_said_in_both_languages(key):
    from bob import i18n
    for lang in ("en", "fr"):
        i18n.init(lang)
        text = i18n.t(f"plugin.sandbox.not_run_{key}", plugin="'p.py'", error="x")
        assert "p.py" in text and "plugin.sandbox" not in text
    i18n.init("en")


# --- Third external review (28 November 2026): looked at before it is opened ---
# The parent checked the plugin, then opened it again by its name following
# links; the child opened it as root before checking the descriptor. A plugin
# swapped between the check and the open was opened by root all the same.


def test_the_parent_does_not_open_a_plugin_swapped_after_its_checks(tmp_path, plugin, monkeypatch):
    secret = tmp_path / "root-only.py"
    secret.write_text("CHECK_NAME = 'secret'\n\ndef run_check():\n    return None\n")
    real_is_file = pc.strict_is_file

    def swap_after_check(path):
        ok = real_is_file(path)
        path.unlink()
        path.symlink_to(secret)                  # swapped once the checks have looked
        return ok

    monkeypatch.setattr(pc, "strict_is_file", swap_after_check)
    assert pc._load_one(plugin) is None


class _Recording:
    """The real ``os``, with every open()'s flags written down."""

    def __init__(self, other_inode=False):
        self.flags, self._other, self._fds = [], other_inode, set()

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *a):
        self.flags.append(flags)
        fd = os.open(path, flags, *a)
        if str(path).startswith("/proc/self/fd/"):
            self._fds.add(fd)
        return fd

    def fstat(self, fd):
        st = os.fstat(fd)
        if self._other and fd in self._fds:
            return os.stat_result((st.st_mode, st.st_ino + 1, *tuple(st)[2:]))
        return st


def test_root_never_opens_what_is_not_a_regular_file(tmp_path):
    fifo = tmp_path / "p.py"
    os.mkfifo(fifo)
    rec = _Recording()
    assert sb.open_plugin_checked(str(fifo), None, None, rec) == (None, "not_regular", None)
    assert rec.flags and all(f & os.O_PATH for f in rec.flags)


def test_the_file_reopened_must_be_the_one_checked(plugin):
    fd, why, _ = sb.open_plugin_checked(str(plugin), os.path.realpath(plugin), None, _Recording(other_inode=True))
    assert (fd, why) == (None, "replaced")


def test_the_checked_file_is_read_through_the_same_inode(plugin):
    rec = _Recording()
    fd, why, _ = sb.open_plugin_checked(str(plugin), os.path.realpath(plugin), None, rec)
    try:
        assert why is None and os.read(fd, 100).decode() == _PLUGIN
        assert len(rec.flags) == 2 and rec.flags[0] & os.O_PATH and not rec.flags[1] & os.O_PATH
    finally:
        os.close(fd)
