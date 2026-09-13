"""A trust-boundary path check must fail *closed* when it cannot look.

`_is_safe_config_path` / `_is_safe_user_path` gate whether BOB will read a path:
a symlink under `/etc/cron.d`, `/etc/sudoers.d`, `~/.ssh` etc. is suspect
(``authorized_keys → /etc/shadow``), so the answer "safe to read" is a security
assertion. Both used `Path.is_symlink()`, which up to Python 3.13 *raised*
PermissionError when the path could not be lstat'd — but from 3.14 answers
`False` instead (measured on 3.14.7). A symlink BOB is refused permission to
lstat would then read as "not a symlink, safe", following it to its target.

These guards now call `strict_is_symlink` (which keeps the ≤3.13 raise) and
treat an undeterminable answer as *unsafe*. The denial cases below build a
mode-000 parent so lstat raises on every interpreter version, so they hold the
fail-closed contract on 3.12 as well as 3.14.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bob.checks._run import _is_safe_config_path, _is_safe_user_path

_skip_as_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root traverses a mode-000 directory, so no denial is raised",
)


class TestSafeConfigPath:
    def test_plain_absolute_file_is_safe(self, tmp_path):
        f = tmp_path / "drop.conf"
        f.write_text("x\n")
        assert _is_safe_config_path(f) is True

    def test_relative_path_is_unsafe(self):
        assert _is_safe_config_path(Path("etc/passwd")) is False

    def test_a_symlink_is_unsafe(self, tmp_path):
        target = tmp_path / "real"
        target.write_text("x\n")
        link = tmp_path / "link.conf"
        link.symlink_to(target)
        assert _is_safe_config_path(link) is False

    @_skip_as_root
    def test_undeterminable_fails_closed(self, tmp_path):
        """lstat refused → not 'safe', but 'unsafe'."""
        vault = tmp_path / "vault"
        vault.mkdir()
        secret = vault / "evil.conf"
        secret.symlink_to("/etc/shadow")
        vault.chmod(0o000)
        try:
            assert _is_safe_config_path(secret) is False
        finally:
            vault.chmod(0o755)


class TestSafeUserPath:
    def test_plain_file_in_home_is_safe(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        f = home / ".bashrc"
        f.write_text("x\n")
        assert _is_safe_user_path(f, home) is True

    def test_symlink_inside_home_is_safe(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        target = home / "real"
        target.write_text("x\n")
        link = home / "link"
        link.symlink_to(target)
        assert _is_safe_user_path(link, home) is True

    def test_symlink_escaping_home_is_unsafe(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        outside = tmp_path / "outside"
        outside.write_text("secret\n")
        link = home / "escape"
        link.symlink_to(outside)
        assert _is_safe_user_path(link, home) is False

    @_skip_as_root
    def test_undeterminable_fails_closed(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        vault = home / "vault"
        vault.mkdir()
        link = vault / "escape"
        link.symlink_to("/etc/shadow")
        vault.chmod(0o000)
        try:
            assert _is_safe_user_path(link, home) is False
        finally:
            vault.chmod(0o755)
