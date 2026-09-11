"""Python 3.14 turned "not allowed to look" into "not there".

Up to 3.13, ``Path.is_file()``, ``is_dir()``, ``exists()`` and ``is_symlink()``
re-raised a ``PermissionError``; from 3.14 they answer ``False``. Measured on
3.14.7 against a file inside a mode-000 directory — ``is_file`` False, ``stat``
still raising. The CI's 3.14 job failed on one test of v0.18.0's profile lookup;
the same reliance on the raise sat in three more places where it changed
the answer.

These tests do not depend on the interpreter running them. The
``python314_predicates`` fixture gives ``pathlib`` the 3.14 behaviour on any
version, so the guards bite on the 3.12 the mutation bench runs on — a guard
that only fails on the one interpreter where the defect lives would pass the
bench while guarding nothing.
"""

from __future__ import annotations

import logging
import os
import pathlib

import pytest

from bob._fs import strict_is_file, strict_is_symlink

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="root bypasses the mode-000 directory these need"
)


@pytest.fixture
def python314_predicates(monkeypatch):
    """Make pathlib's predicates swallow every OSError, as 3.14 does."""
    for name in ("is_file", "is_dir", "exists", "is_symlink"):
        original = getattr(pathlib.Path, name)

        def swallowing(self, *args, _original=original, **kwargs):
            try:
                return _original(self, *args, **kwargs)
            except OSError:
                return False

        monkeypatch.setattr(pathlib.Path, name, swallowing)


@pytest.fixture
def shut(tmp_path):
    """A directory holding a regular file and a symlink, then closed."""
    d = tmp_path / "shut"
    d.mkdir()
    (d / "inside.conf").write_text("x", encoding="utf-8")
    (d / "link").symlink_to(d / "inside.conf")
    d.chmod(0o000)
    yield d
    d.chmod(0o755)


# ---------------------------------------------------------------------------
# The helpers keep the ≤3.13 contract, under 3.14's pathlib
# ---------------------------------------------------------------------------

def test_the_fixture_really_reproduces_314(shut, python314_predicates):
    """The mirror: without this, every test below could pass vacuously."""
    assert (shut / "inside.conf").is_file() is False


@pytest.mark.parametrize("helper,name", [
    (strict_is_file, "inside.conf"),
    (strict_is_symlink, "link"),
])
def test_a_denial_still_raises(helper, name, shut, python314_predicates):
    with pytest.raises(PermissionError):
        helper(shut / name)


def test_an_absence_is_still_false(tmp_path, python314_predicates):
    (tmp_path / "a-file").write_text("x", encoding="utf-8")
    for helper in (strict_is_file, strict_is_symlink):
        assert helper(tmp_path / "nothing-here") is False
        assert helper(tmp_path / "a-file" / "under-a-file") is False  # ENOTDIR


def test_the_answers_are_right_where_bob_may_look(tmp_path):
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    link = tmp_path / "l"
    link.symlink_to(f)
    assert strict_is_file(f) and not strict_is_symlink(f)
    assert not strict_is_file(tmp_path)
    assert strict_is_symlink(link) and strict_is_file(link)


# ---------------------------------------------------------------------------
# The four call sites, under 3.14's pathlib
# ---------------------------------------------------------------------------

def test_profile_in_a_shut_directory_is_not_reported_absent(
    shut, tmp_path, monkeypatch, python314_predicates
):
    """The one the CI's 3.14 job caught."""
    import bob.profiles as P

    builtin = tmp_path / "builtin"
    builtin.mkdir()
    monkeypatch.setattr(P, "_USER_PROFILES_DIR", shut)
    monkeypatch.setattr(P, "_BUILTIN_PROFILES_DIR", builtin)
    P.lookup_profile_file.cache_clear()
    try:
        lookup = P.lookup_profile_file("inside")
    finally:
        P.lookup_profile_file.cache_clear()
    assert lookup.path is None
    assert lookup.unreadable == (str(shut),)


def test_a_config_path_bob_cannot_inspect_is_not_safe(shut, python314_predicates):
    """``_is_safe_service_config``: "I could not tell" is not "safe"."""
    from bob.checks.services import _is_safe_service_config

    assert _is_safe_service_config(shut / "link", str(shut / "*")) is False


def test_logrotate_rules_it_could_not_inspect_are_not_a_count_of_zero(
    tmp_path, monkeypatch, python314_predicates
):
    """A directory that lists but will not let BOB stat its entries."""
    import bob.checks.log_rotation as L

    d = tmp_path / "logrotate.d"
    d.mkdir()
    (d / "rsyslog").write_text("x", encoding="utf-8")
    d.chmod(0o444)  # readable, not traversable: iterdir works, stat does not
    monkeypatch.setattr(L, "_LOGROTATE_D", d)
    try:
        count, readable = L._count_logrotate_rules()
    finally:
        d.chmod(0o755)
    assert (count, readable) == (0, False), (
        "BOB claimed to have read a directory whose entries it never inspected"
    )


def test_a_plugin_bob_cannot_stat_is_not_called_irregular(
    tmp_path, monkeypatch, caplog, python314_predicates
):
    from bob import plugin_checks

    d = tmp_path / "checks.d"
    d.mkdir()
    plugin = d / "mine.py"
    plugin.write_text("def run_check(ctx):\n    return None\n", encoding="utf-8")
    d.chmod(0o444)
    try:
        loader = plugin_checks._load_one
        with caplog.at_level(logging.WARNING):
            assert loader(plugin) is None
    finally:
        d.chmod(0o755)
    assert "not a regular file" not in caplog.text
    assert "cannot stat" in caplog.text
