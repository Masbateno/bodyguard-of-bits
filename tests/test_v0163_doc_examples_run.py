"""v0.16.3 — a command shown in the user documentation must actually work.

`DOCUMENTS/TUTORIAL.md` told a first-time reader to run
``bob --explain ssh.password_auth_enabled``. That key has never existed; the
command exits 3 with "no such key", on the page whose whole job is the first
half-hour with the tool. `README.md` showed a sample of BOB's own output whose
`? bob --explain hardening.send_redirects` hint named a key BOB does not emit
— the real one is `hardening.send_redirects_enabled`.

Neither is catchable by the numeric guards: both are plausible names, longer
and more specific than the truth, and both read as correct.

Scope is the **user-facing** documents. `TESTING.md` and the changelogs quote
keys as they were named at the time — `ssh.x11_forwarding` is accurate about
v0.10.1, which is the release that split it — and `SNAPSHOT.md` uses `foo.xxx`
as a placeholder in its "how to add a section" instructions. Excluding those
documents by their role is a rule; excluding `foo.xxx` by name would be a
whitelist, and a guard maintained by widening its whitelist stops being one.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Documents a user reads to learn what to type.
_USER_DOCS = [
    "README.md", "README_FR.md",
    "SECURITY.md", "SECURITY_FR.md",
    "DOCUMENTS/TUTORIAL.md", "DOCUMENTS/TUTORIAL_FR.md",
    "DOCUMENTS/AUTOMATION.md", "DOCUMENTS/AUTOMATION_FR.md",
    "DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md",
    "man/bob.1",
]

_EXPLAIN = re.compile(r"--explain[= ]`?([a-z][a-z0-9_]*\.[a-z0-9_.]+?)`?(?=[\s`,.)]|$)")
_SECTION = re.compile(r"--(?:check|skip)=`?([a-z0-9_,]+)`?")


@pytest.mark.parametrize("rel", _USER_DOCS)
def test_every_explain_key_shown_to_a_user_exists(rel):
    from bob.explain import EXPLAIN_KEYS
    text = (_ROOT / rel).read_text(encoding="utf-8")
    bad = sorted({
        k for k in (m.group(1).rstrip(".") for m in _EXPLAIN.finditer(text))
        if k not in EXPLAIN_KEYS
    })
    assert not bad, (
        f"{rel} tells the reader to run --explain on {bad}, which exits 3"
    )


@pytest.mark.parametrize("rel", _USER_DOCS)
def test_every_section_name_shown_to_a_user_exists(rel):
    from bob.runner import _SECTIONS
    names = {s.name for s in _SECTIONS}
    text = (_ROOT / rel).read_text(encoding="utf-8")
    bad = sorted({
        s for m in _SECTION.finditer(text) for s in m.group(1).split(",")
        if s and s != "list" and s not in names
    })
    assert not bad, f"{rel} names sections that do not exist: {bad}"


def test_the_scraper_would_notice_a_bad_key():
    """A scraper that matches nothing passes forever."""
    found = [m.group(1) for m in _EXPLAIN.finditer(
        "run `bob --explain ssh.password_auth_enabled` to see")]
    assert found == ["ssh.password_auth_enabled"], found


def test_the_scraper_finds_the_real_ones_too():
    from bob.explain import EXPLAIN_KEYS
    text = (_ROOT / "DOCUMENTS" / "TUTORIAL.md").read_text(encoding="utf-8")
    found = {m.group(1).rstrip(".") for m in _EXPLAIN.finditer(text)}
    assert found, "no --explain example found in the tutorial at all"
    assert found <= set(EXPLAIN_KEYS) | {"list"}
