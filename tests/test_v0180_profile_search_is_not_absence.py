"""A profile BOB could not look for is not a profile that is absent.

Two ways a ``--profile NAME`` can fail to resolve, and they are different
claims:

* every profile directory was searched and no ``NAME.conf`` was there —
  the profile does not exist, and BOB may say so;
* a profile directory refused entry — BOB never got to look, and reporting
  "not found" would assert something it did not measure.

Before v0.18.0 both rendered the same "not found" sentence, and a third
case — a name the kernel rejects outright, such as one too long to be a
filename — escaped ``load_profile`` entirely and surfaced as a raw
``Fatal error: [Errno 36]``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bob.profiles import _DEFAULT_PROFILE, load_profile, lookup_profile_file


@pytest.fixture(autouse=True)
def _clear_cache():
    lookup_profile_file.cache_clear()
    yield
    lookup_profile_file.cache_clear()


def _profile_dirs(monkeypatch, user: Path, builtin: Path) -> None:
    monkeypatch.setattr("bob.profiles._USER_PROFILES_DIR", user)
    monkeypatch.setattr("bob.profiles._BUILTIN_PROFILES_DIR", builtin)


def test_absent_profile_reports_an_empty_search(tmp_path, monkeypatch):
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    _profile_dirs(monkeypatch, user, builtin)

    lookup = lookup_profile_file("ghost")

    assert lookup.path is None
    # BOB looked in both directories and neither refused it.
    assert lookup.unreadable == ()


def test_unreadable_directory_is_recorded_not_swallowed(tmp_path, monkeypatch):
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    (user / "ghost.conf").write_text("[profile]\nname = ghost\n", encoding="utf-8")
    user.chmod(0o000)
    _profile_dirs(monkeypatch, user, builtin)
    try:
        lookup = lookup_profile_file("ghost")
    finally:
        user.chmod(0o755)

    # The profile is right there. BOB was not allowed to see it, and the
    # lookup says which door was shut rather than claiming absence.
    assert lookup.path is None
    assert lookup.unreadable == (str(user),)


def test_a_name_the_kernel_refuses_is_a_genuine_absence(tmp_path, monkeypatch):
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    _profile_dirs(monkeypatch, user, builtin)

    # 300 bytes — longer than NAME_MAX, so the kernel rejects the stat with
    # ENAMETOOLONG instead of answering "no such file".
    lookup = lookup_profile_file("e" * 300)

    # No file of that name can exist, which is an answer, not a blocked door.
    assert lookup.path is None
    assert lookup.unreadable == ()


def test_load_profile_survives_a_name_the_kernel_refuses(tmp_path, monkeypatch):
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    _profile_dirs(monkeypatch, user, builtin)

    # Pre-v0.18.0 this raised OSError out of load_profile and reached the
    # operator as "Fatal error: [Errno 36] File name too long".
    assert load_profile("e" * 300) is _DEFAULT_PROFILE


def test_load_profile_names_the_blocked_directory_in_its_warning(
    tmp_path, monkeypatch, caplog
):
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    (user / "ghost.conf").write_text("[profile]\nname = ghost\n", encoding="utf-8")
    user.chmod(0o000)
    _profile_dirs(monkeypatch, user, builtin)
    try:
        with caplog.at_level("WARNING", logger="bob.profiles"):
            assert load_profile("ghost") is _DEFAULT_PROFILE
    finally:
        user.chmod(0o755)

    logged = caplog.text
    assert "not found" not in logged, "a blocked search must not be read as absence"
    assert str(user) in logged, "the operator is told which directory refused"


def test_both_outcomes_have_their_own_sentence_in_both_locales():
    """The render, not the helper: two distinct claims need two distinct texts."""
    for locale in ("en", "fr"):
        data = json.loads(
            Path(f"bob/locales/{locale}.json").read_text(encoding="utf-8")
        )
        audit = data["audit"]
        absent = audit["profile_not_found"]
        blocked = audit["profile_search_blocked"]

        assert absent != blocked, f"{locale}: both outcomes render the same sentence"
        assert "{profile}" in blocked
        # The blocked sentence must be able to name the door that was shut.
        assert "{dirs}" in blocked
        assert "{dirs}" not in absent


def test_a_resolved_profile_still_names_the_door_that_stayed_shut(
    tmp_path, monkeypatch, caplog
):
    """BOB found *a* profile. It does not pretend it found *the* profile.

    The user directory is searched first, so a same-named file there would
    have taken priority. When that directory refuses entry and the built-in
    answers instead, the operator is running under a profile that may not be
    the one they configured — and hearing nothing about it.
    """
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    (builtin / "desktop.conf").write_text(
        "[profile]\nname = desktop\n", encoding="utf-8"
    )
    user.chmod(0o000)
    _profile_dirs(monkeypatch, user, builtin)
    try:
        with caplog.at_level("WARNING", logger="bob.profiles"):
            resolved = load_profile("desktop")
    finally:
        user.chmod(0o755)

    assert resolved.name == "desktop"
    assert str(user) in caplog.text, "the unsearched directory is named"
    assert str(builtin / "desktop.conf") in caplog.text, "so is what BOB did read"


def test_a_clean_search_says_nothing_extra(tmp_path, monkeypatch, caplog):
    """The mirror: nothing was shut, so there is nothing to report."""
    user, builtin = tmp_path / "user", tmp_path / "builtin"
    user.mkdir()
    builtin.mkdir()
    (builtin / "desktop.conf").write_text(
        "[profile]\nname = desktop\n", encoding="utf-8"
    )
    _profile_dirs(monkeypatch, user, builtin)

    with caplog.at_level("WARNING", logger="bob.profiles"):
        assert load_profile("desktop").name == "desktop"

    assert caplog.text == "", "a search that met no closed door warns about none"


def test_the_shadow_sentence_exists_in_both_locales():
    for locale in ("en", "fr"):
        audit = json.loads(
            Path(f"bob/locales/{locale}.json").read_text(encoding="utf-8")
        )["audit"]
        shadow = audit["profile_shadow_unchecked"]
        assert shadow not in (
            audit["profile_not_found"],
            audit["profile_search_blocked"],
        ), f"{locale}: the third outcome reuses another outcome's sentence"
        for slot in ("{profile}", "{path}", "{dirs}"):
            assert slot in shadow, f"{locale}: {shadow!r} cannot name {slot}"
