"""
Version consistency guard (v0.7.0b2 release-engineering lesson).

BOB declares its version in TWO places:

  - ``pyproject.toml`` ``[project].version`` — what setuptools writes into
    the wheel metadata. ``pipx install`` reads this when reporting the
    installed package version, and PyPI uses it for the release identifier.
  - ``bob/__init__.py`` ``__version__`` — what the running BOB code reads
    via ``from bob import __version__``. The terminal banner, the ``bob
    --version`` output, the JSON ``"version"`` field, the webhook payload
    and the report header ALL come from this value.

A drift between the two means the wheel is labeled correctly on PyPI but
the running code reports the wrong version — exactly what happened on the
v0.7.0b1 ship: pyproject.toml was bumped to ``0.7.0b1`` but
``bob/__init__.py`` stayed at ``0.6.2``, so users running ``pipx install
--pre`` got a ``0.7.0b1`` wheel that reported ``BOB v0.6.2`` in every
output.

This test exists so the drift cannot happen silently again. Any future
version bump that updates only one of the two files fails this test in
CI.
"""

from __future__ import annotations

import re
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_pyproject_version() -> str:
    """Extract ``version = "..."`` from the ``[project]`` table of pyproject.toml.

    We use a regex rather than tomllib so the test runs on Python 3.10
    where ``tomllib`` is not in the stdlib (BOB still supports 3.10 — see
    ``DOCUMENTS/README_TECH.md`` Python support policy).
    """
    content = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # Find the [project] table, then version = "..." within it
    project_match = re.search(
        r"^\[project\][^\[]*?^version\s*=\s*[\"']([^\"']+)[\"']",
        content,
        re.MULTILINE | re.DOTALL,
    )
    assert project_match, (
        "Could not parse pyproject.toml [project].version — has the file format changed?"
    )
    return project_match.group(1)


def test_init_version_matches_pyproject_version():
    """The single most important invariant of the release pipeline.

    Hand-bumping just one of the two files used to produce a wheel that
    PyPI labeled correctly while the running code reported the prior
    version. Caught on the so6 Debian 13 VM during the v0.7.0b1 beta
    validation (2026-05-31) — the banner said ``BOB v0.6.2`` after a
    clean ``pipx install bodyguard-of-bits-beta``.

    This test runs on every CI invocation and on the local pre-ship suite.
    If you see it fail with both values printed: bump the value that is
    behind to match the other.
    """
    from bob import __version__ as runtime_version

    pyproject_version = _read_pyproject_version()
    assert runtime_version == pyproject_version, (
        f"Version drift between bob/__init__.py and pyproject.toml:\n"
        f"  bob.__version__       = {runtime_version!r}\n"
        f"  pyproject.toml version = {pyproject_version!r}\n"
        f"Both must match. Bump whichever one is behind."
    )


def test_pyproject_version_matches_pep440():
    """Sanity guard: the declared version must be a valid PEP 440 string
    so PyPI accepts it. The minimal regex covers stable (``X.Y.Z``) and
    pre-release suffixes (``X.Y.ZaN``, ``X.Y.ZbN``, ``X.Y.ZrcN``, ``X.Y.Z.devN``)
    — the same patterns publish.yml detects via its ``IS_PRERELEASE`` check."""
    v = _read_pyproject_version()
    assert re.match(
        r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|\.dev\d+|\.post\d+)?$",
        v,
    ), f"pyproject.toml version {v!r} is not a valid PEP 440 release identifier"
