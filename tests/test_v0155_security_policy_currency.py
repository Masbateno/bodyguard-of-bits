"""
v0.15.5 — the supported-version table had been stale for five releases.

SECURITY.md declares which release line receives security patches. It still
named **0.14.x** as current when the project was on 0.15.5, so the file had
been wrong since v0.15.0 shipped on 2026-08-31 — through five releases, two of
which carried behavioural changes an operator on 0.14.x would want to know
about before upgrading.

The doc-version-consistency guard added in v0.8.0 does not read this file. A
policy document that quietly names the wrong supported line is worse than an
absent one: a reader trusts it, and it tells them a dead branch is maintained.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bob import __version__

_ROOT = Path(__file__).resolve().parent.parent

# (file, the word marking the supported line, the words marking a dead one)
_POLICY_FILES = (
    ("SECURITY.md", "current", ("end of life",)),
    ("SECURITY_FR.md", "courante", ("fin de vie",)),
)

_ROW = re.compile(r"^\|\s*(?:≤ )?(\d+\.\d+)\.x[^|]*\|([^|]*)\|", re.M)


def _current_minor() -> str:
    major, minor, _ = __version__.split(".", 2)
    return f"{major}.{minor}"


@pytest.mark.parametrize("filename,supported_word,eol_words", _POLICY_FILES)
def test_only_the_current_minor_line_is_supported(filename, supported_word, eol_words):
    text = (_ROOT / filename).read_text(encoding="utf-8")
    rows = _ROW.findall(text)
    assert rows, f"{filename}: no version table found"

    current = _current_minor()
    supported = [v for v, status in rows if supported_word in status.lower()]
    assert supported == [current], (
        f"{filename} marks {supported} as supported; the project is on "
        f"{__version__}, so exactly ['{current}'] should be.\n"
        f"Every other line must be end-of-life — the policy is "
        f"'latest minor release line only'."
    )

    for version, status in rows:
        if version == current:
            continue
        assert any(w in status.lower() for w in eol_words), (
            f"{filename}: {version}.x is neither current nor marked end of life "
            f"(status: {status.strip()!r})"
        )


@pytest.mark.parametrize("filename,_supported,_eol", _POLICY_FILES)
def test_the_patch_and_bump_example_names_the_current_line(filename, _supported, _eol):
    """The sentence under the table gives a worked example of the next patch.

    It named `0.14.x+1` and `0.15.0` while the project was on 0.15.5 — the same
    drift as the table, one line below it and easy to fix separately, so it is
    checked separately.
    """
    text = (_ROOT / filename).read_text(encoding="utf-8")
    current = _current_minor()
    major, minor = current.split(".")
    next_minor = f"{major}.{int(minor) + 1}.0"

    assert f"`{current}.x+1`" in text, (
        f"{filename}: the patch example must name the current line "
        f"(`{current}.x+1`)"
    )
    assert f"`{next_minor}`" in text, (
        f"{filename}: the breaking-change example must name the next minor "
        f"(`{next_minor}`)"
    )
