"""`--install-completion` names the symlink's real state.

Field report (2026-10-03): on a second run, with ``/usr/local/bin/bob`` already
pointing at ``~/.local/bin/bob``, the command printed "bob not found in
~/.local/bin" — about a binary that was there and correctly linked. The
"already linked" case fell into the "not found" branch.

The guard pins the three states apart:
  1. not linked yet       → the symlink is created;
  2. already linked       → "already in place", and the link is left alone;
  3. genuinely not there  → "not found".
"""

from __future__ import annotations

import io
import types
from contextlib import redirect_stdout

import pytest

import bob.completion as completion
import bob.i18n as i18n


@pytest.fixture
def home(tmp_path, monkeypatch):
    i18n.init(lang="en")
    user_home = tmp_path / "home"
    (user_home / ".local" / "bin").mkdir(parents=True)
    comp_dir = tmp_path / "bash_completion.d"
    comp_dir.mkdir()
    dst_bin = tmp_path / "usr-local-bin-bob"
    monkeypatch.setattr(completion, "_DST_COMP", comp_dir / "bob")
    monkeypatch.setattr(completion, "_DST_BIN", dst_bin)
    monkeypatch.setenv("SUDO_USER", "alice")
    import pwd
    monkeypatch.setattr(pwd, "getpwnam",
                        lambda name: types.SimpleNamespace(pw_dir=str(user_home)))
    return types.SimpleNamespace(user_bin=user_home / ".local" / "bin" / "bob",
                                 dst_bin=dst_bin)


def _run():
    out = io.StringIO()
    with redirect_stdout(out):
        rc = completion.install_completion()
    return rc, out.getvalue()


def test_not_linked_yet_creates_the_symlink(home):
    home.user_bin.write_text("#!/bin/sh\n")
    rc, text = _run()
    assert rc == 0
    assert home.dst_bin.is_symlink() and home.dst_bin.resolve() == home.user_bin
    assert "Symlink created" in text


def test_already_linked_says_so_and_leaves_it(home):
    home.user_bin.write_text("#!/bin/sh\n")
    home.dst_bin.symlink_to(home.user_bin)
    ino = home.dst_bin.lstat().st_ino
    rc, text = _run()
    assert rc == 0
    assert "already in place" in text
    assert "not found" not in text
    assert home.dst_bin.lstat().st_ino == ino, "an up-to-date link was recreated"


def test_missing_binary_says_not_found(home):
    rc, text = _run()
    assert "not found in ~/.local/bin" in text
    assert not home.dst_bin.exists()
