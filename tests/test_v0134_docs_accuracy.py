"""Anti-drift guards for the v0.13.4 documentation accuracy pass.

Three guards, each closing a *class* of defect rather than the instances
found. Every one of them would have caught a real defect that shipped:

1. ``TestRelativeLinks`` — ``DOCUMENTS/CHANGELOG_FULL.md`` carried 17 links
   written ``](bob/…)`` instead of ``](../bob/…)``; they 404 on GitHub. The
   FR twin had zero, so this was never noticed by symmetry. Also catches
   links to the internal memory store (``](memory)``) that leaked into the
   public changelog.

2. ``TestLocaleSectionParity`` — ``SECURITY_FR.md``'s "Plugin checks"
   section had 83 words against 562 in English (15%), and worse: it still
   claimed plugins are **not** sandboxed and referred to "la ligne 0.6.x".
   The sandbox shipped in v0.7.0 — the French security policy had been
   telling readers the opposite of the truth for seven minor releases. A
   whole-file ratio would have missed it (the file was at 92% overall);
   only a *per-section* ratio surfaces it.

3. ``TestCliSurfaceDocumented`` — ``--json``, ``--json-full``, ``--html``,
   ``--output=FORMAT`` and ``--no-colour`` all parsed correctly but appeared
   nowhere in ``--help``: working, undiscoverable features. Same "silent
   feature gap" class the project hunted in v0.8.0.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


_FENCE_RE = re.compile(r"```.*?```", re.S)
_CODESPAN_RE = re.compile(r"`[^`\n]*`")


def _prose(text: str) -> str:
    """Strip fenced blocks and inline code spans.

    A doc that *documents* a link defect necessarily contains the defective
    pattern as an example (this project's own changelog quotes ``](bob/…)``
    and ``](memory)`` when describing the v0.13.4 fixes). Scanning raw text
    would make every such description a false positive, so the guards read
    prose only — which is also where real links live.
    """
    return _CODESPAN_RE.sub(" ", _FENCE_RE.sub(" ", text))


def _markdown_files() -> list[pathlib.Path]:
    skip = {".git", "build", ".pytest_cache", "node_modules"}
    return sorted(
        p for p in _REPO_ROOT.rglob("*.md")
        if not (skip & set(p.relative_to(_REPO_ROOT).parts))
    )


# ---------------------------------------------------------------------------
# 1 — relative links must resolve
# ---------------------------------------------------------------------------

# Markdown-syntax examples and regexes inside fenced code blocks that the
# link regex cannot tell apart from a real link. Keep this list SHORT and
# justified — every entry is a place the guard is deliberately blind.
_LINK_FALSE_POSITIVES = {
    "url",        # `[label](url)` — literal markdown-syntax example
    "[\\w.]+",    # a regex printed inside a code block
}

_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)#][^)]*)\)")


class TestRelativeLinks:

    def test_no_broken_relative_links(self):
        broken = []
        for md in _markdown_files():
            for m in _LINK_RE.finditer(_prose(md.read_text(encoding="utf-8"))):
                target = m.group(2).split("#")[0].strip()
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                if target in _LINK_FALSE_POSITIVES:
                    continue
                if not (md.parent / target).exists():
                    rel = md.relative_to(_REPO_ROOT)
                    broken.append(f"  {rel}: [{m.group(1)[:40]}] -> {target}")
        assert not broken, (
            "broken relative links (they 404 on GitHub):\n" + "\n".join(broken)
        )

    def test_documents_link_to_bob_with_parent_prefix(self):
        """A link from DOCUMENTS/ to the package must be ../bob/, not bob/."""
        offenders = []
        for md in sorted((_REPO_ROOT / "DOCUMENTS").glob("*.md")):
            n = len(re.findall(r"\]\(bob/", _prose(md.read_text(encoding="utf-8"))))
            if n:
                offenders.append(f"  {md.name}: {n} link(s) missing the '../' prefix")
        assert not offenders, "\n".join(offenders)

    def test_no_link_to_internal_memory_store(self):
        """`](memory)` is a reference to Claude's private memory store; it has
        no meaning for a reader and resolves to nothing in the repository."""
        offenders = []
        for md in _markdown_files():
            if re.search(r"\]\(memory[/)]", _prose(md.read_text(encoding="utf-8"))):
                offenders.append(str(md.relative_to(_REPO_ROOT)))
        assert not offenders, (
            "internal memory-store links leaked into public docs: " + ", ".join(offenders)
        )


# ---------------------------------------------------------------------------
# 2 — EN/FR parity, per section
# ---------------------------------------------------------------------------

_DOC_PAIRS = [
    ("SECURITY.md", "SECURITY_FR.md"),
    ("README.md", "README_FR.md"),
    ("DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md"),
    ("DOCUMENTS/README_DEV.md", "DOCUMENTS/README_DEV_FR.md"),
    ("DOCUMENTS/AUTOMATION.md", "DOCUMENTS/AUTOMATION_FR.md"),
    ("DOCUMENTS/TUTORIAL.md", "DOCUMENTS/TUTORIAL_FR.md"),
]

# French runs ~10-30% longer than English for the same content, so a healthy
# ratio sits above 1.0. A section under this floor is not a terser
# translation — it is missing content.
_MIN_RATIO = 0.55
_MIN_WORDS = 40  # ignore headers and one-liners, where the ratio is noise


def _sections(path: pathlib.Path) -> list[tuple[str, int]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    heads = [(i, l) for i, l in enumerate(lines) if re.match(r"^#{1,3} ", l)]
    out = []
    for n, (i, title) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        out.append((title.lstrip("# ").strip(),
                    sum(len(x.split()) for x in lines[i:end])))
    return out


class TestLocaleSectionParity:

    @pytest.mark.parametrize("en_path,fr_path", _DOC_PAIRS)
    def test_no_section_is_amputated_in_french(self, en_path: str, fr_path: str):
        en = _sections(_REPO_ROOT / en_path)
        fr = _sections(_REPO_ROOT / fr_path)
        assert len(en) == len(fr), (
            f"{en_path} has {len(en)} sections but {fr_path} has {len(fr)} — "
            "the two locales must keep the same structure"
        )
        thin = []
        for (t_en, w_en), (t_fr, w_fr) in zip(en, fr):
            if w_en < _MIN_WORDS:
                continue
            ratio = w_fr / w_en
            if ratio < _MIN_RATIO:
                thin.append(
                    f"  {t_en[:58]!r}: EN={w_en}w FR={w_fr}w ({ratio:.0%})"
                )
        assert not thin, (
            f"{fr_path} has section(s) far shorter than {en_path} — "
            f"missing content, not a terser translation:\n" + "\n".join(thin)
        )


# ---------------------------------------------------------------------------
# 3 — every accepted CLI flag appears in --help
# ---------------------------------------------------------------------------

# Flags that are accepted only to emit a helpful error. Documenting a retired
# flag in --help would advertise it as usable.
_INTENTIONALLY_UNDOCUMENTED = {
    "--json-v1",   # retired v0.9.0 F-3; parse_args raises CLIError on it
}


def _accepted_flags() -> set[str]:
    src = (_REPO_ROOT / "bob" / "cli.py").read_text(encoding="utf-8")
    body = src[src.index("def parse_args("):]
    # Both bare literals ("--quiet") and value-taking prefixes
    # ("--webhook-format=", matched via arg.startswith) must be captured —
    # the trailing '=' lives inside the quotes at those sites.
    return set(re.findall(r'["\'](--[a-z0-9][a-z0-9-]+)=?["\']', body))


def _help_text() -> str:
    return subprocess.run(
        [sys.executable, "-m", "bob", "--help"],
        capture_output=True, text=True, cwd=_REPO_ROOT,
    ).stdout


class TestCliSurfaceDocumented:

    def test_every_accepted_flag_is_in_help(self):
        help_text = _help_text()
        missing = sorted(
            f for f in _accepted_flags()
            if f not in _INTENTIONALLY_UNDOCUMENTED and f not in help_text
        )
        assert not missing, (
            "flags accepted by parse_args() but absent from --help — working "
            "features nobody can discover: " + ", ".join(missing)
        )

    def test_help_advertises_no_unknown_flag(self):
        """The reverse drift: --help must not promise a flag that was removed."""
        help_text = _help_text()
        accepted = _accepted_flags()
        # Only check long flags in the option column, not prose/examples.
        advertised = set(re.findall(r"^\s+(?:-\w[,/]\s+)?(--[a-z0-9][a-z0-9-]+)",
                                    help_text, re.M))
        ghosts = sorted(f for f in advertised - accepted if f != "--help")
        assert not ghosts, (
            "--help advertises flag(s) parse_args() does not accept: "
            + ", ".join(ghosts)
        )

    def test_long_form_format_aliases_work_and_are_documented(self):
        """Regression pin for the five v0.13.4 gaps."""
        from bob.cli import parse_args
        help_text = _help_text()
        for argv, attr in [
            (["--json"], "json_mode"),
            (["--json-full"], "json_full"),
            (["--html"], "html_mode"),
            (["--output=csv"], "csv_mode"),
            (["--no-colour"], "no_color"),
        ]:
            assert getattr(parse_args(argv), attr) is True, f"{argv} stopped working"
        for flag in ("--json", "--json-full", "--html", "--output", "--no-colour"):
            assert flag in help_text, f"{flag} vanished from --help"
