"""v0.41.0 — the parents BOB creates in a user's home are the user's (B-029).

Measured on the test Mint (17 November 2026): after a first ``sudo bob -d`` on a
fresh account, ``~/.local/share/bob`` was root's while ``logs`` under it was
the user's — ``mkdir(parents=True)`` created every missing parent as root and
only the leaf was handed over. The user could create, rename or remove nothing
there without root. Each parent BOB creates is now handed over like the leaf,
when it lies in the invoking user's home; a parent that already existed is not
touched, and one created outside the home is never given away.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob import sysinfo


@pytest.fixture
def handed(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(sysinfo, "get_user_home", lambda: home)
    calls: "list[Path]" = []
    monkeypatch.setattr(sysinfo, "chown_to_sudo_user", lambda p: calls.append(Path(p)))
    return home, calls


def test_every_parent_created_in_the_home_is_handed_over(handed):
    home, calls = handed
    d = home / ".local" / "share" / "bob" / "logs"
    sysinfo.ensure_user_dir(d)
    assert d.is_dir()
    assert calls == [home / ".local", home / ".local" / "share", home / ".local" / "share" / "bob", d]


def test_a_parent_that_was_there_is_left_alone(handed):
    home, calls = handed
    (home / ".local").mkdir()
    sysinfo.ensure_user_dir(home / ".local" / "share" / "bob")
    assert home / ".local" not in calls
    assert calls == [home / ".local" / "share", home / ".local" / "share" / "bob"]


def test_a_parent_outside_the_home_is_never_given(handed, tmp_path):
    _home, calls = handed
    d = tmp_path / "srv" / "reports" / "bob"
    sysinfo.ensure_user_dir(d)
    assert tmp_path / "srv" not in calls and tmp_path / "srv" / "reports" not in calls


def test_nothing_handed_over_when_asked_not_to(handed):
    home, calls = handed
    d = home / ".local" / "share" / "bob"
    sysinfo.ensure_user_dir(d, hand_over=False)
    assert d.is_dir() and calls == []
