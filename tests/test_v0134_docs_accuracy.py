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

# DOCUMENTS/TESTING{,_FR}.md is deliberately NOT in the list. Its h1-h3
# skeleton is identical (1 / 8 / 60 headings both sides), but the two locales
# order some sections differently — FR places "Catégorie E — Ports loopback"
# after the observations block, EN places it before. This guard pairs sections
# by position, so on that file it would compare unrelated sections and report
# nonsense (measured: EN "Obs — DDNS false positives" 97w paired against FR
# "Catégorie E" 7w → a bogus 7%). Guarding it correctly needs content-based
# alignment, which is a different tool; until then the file is knowingly
# unguarded rather than guarded wrongly.

# French runs ~10-30% longer than English for the same content, so a healthy
# ratio sits above 1.0. A section under this floor is not a terser
# translation — it is missing content.
_MIN_RATIO = 0.55
_MIN_WORDS = 40  # ignore headers and one-liners, where the ratio is noise


def _strip_fences(lines: list[str]) -> list[str]:
    """Blank out fenced code blocks, keeping line numbering intact.

    A shell comment at the start of a line inside a ``` block (``# Cleanup:``,
    ``# Redis default: bind 127.0.0.1``) is indistinguishable from a level-1
    heading to a line-based regex. DOCUMENTS/TESTING.md contains 15 such
    comments and DOCUMENTS/TESTING_FR.md 13, which made the two files look
    like they had a 2-section structural divergence when their real heading
    structure is identical. Counting them would also make this guard fail
    spuriously the day someone adds a shell comment to one locale only.
    """
    out, in_fence = [], False
    for line in lines:
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else line)
    return out


def _sections(path: pathlib.Path, with_depth: bool = False) -> list[tuple]:
    """Return [(title, word_count)] or, with_depth, [(depth, title)]."""
    lines = _strip_fences(path.read_text(encoding="utf-8").splitlines())
    heads = [(i, l) for i, l in enumerate(lines) if re.match(r"^#{1,3} ", l)]
    out = []
    for n, (i, title) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        depth = len(title) - len(title.lstrip("#"))
        if with_depth:
            out.append((depth, title.lstrip("# ").strip()))
        else:
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
        # Sections are paired by position, which is only meaningful while both
        # locales keep the same skeleton. Pin the heading-depth sequence so a
        # structural divergence is reported as such instead of silently
        # producing word-ratio nonsense from mismatched pairs.
        depths_en = [d for d, _ in _sections(_REPO_ROOT / en_path, with_depth=True)]
        depths_fr = [d for d, _ in _sections(_REPO_ROOT / fr_path, with_depth=True)]
        assert depths_en == depths_fr, (
            f"{en_path} and {fr_path} have the same section count but a "
            "different heading-depth sequence — positional pairing is unsafe"
        )
        thin = []
        # strict=True: the equal-length assertion above already
        # guarantees it, and it keeps the pairing honest if that
        # assertion is ever relaxed.
        for (t_en, w_en), (_t_fr, w_fr) in zip(en, fr, strict=True):
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


# ---------------------------------------------------------------------------
# 4 — packaging changelog dates must name the right weekday
# ---------------------------------------------------------------------------

_MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}


class TestPackagingChangelogWeekdays:
    """Both packaging changelogs carry a written weekday next to the date.

    Nothing in the Python toolchain validates it, so a hand-written entry can
    name the wrong day indefinitely — 5 of the 46 debian entries and 3 of the
    46 rpm entries did (v0.13.3 and v0.13.4 each shipped one, on top of three
    pre-existing from 2026-05-22). ``lintian`` flags this as
    ``debian-changelog-has-wrong-day-of-week`` and it would surface at exactly
    the wrong moment: the first real Debian packaging review.
    """

    def test_debian_changelog_weekdays_match_dates(self):
        import datetime
        text = (_REPO_ROOT / "debian" / "changelog").read_text(encoding="utf-8")
        rows = re.findall(r"^ -- .+?>  (\w{3}), (\d{2}) (\w{3}) (\d{4})", text, re.M)
        assert rows, "no signature line found in debian/changelog"
        wrong = [
            f"  {wd}, {d} {mon} {y} — should be "
            f"{datetime.date(int(y), _MONTHS[mon], int(d)):%a}"
            for wd, d, mon, y in rows
            if f"{datetime.date(int(y), _MONTHS[mon], int(d)):%a}" != wd
        ]
        assert not wrong, "debian/changelog weekday mismatch:\n" + "\n".join(wrong)

    def test_rpm_spec_weekdays_match_dates(self):
        import datetime
        text = (_REPO_ROOT / "packaging" / "rpm" / "bob.spec").read_text(encoding="utf-8")
        rows = re.findall(r"^\* (\w{3}) (\w{3}) (\d{1,2}) (\d{4})", text, re.M)
        assert rows, "no %changelog entry found in bob.spec"
        wrong = [
            f"  {wd} {mon} {d} {y} — should be "
            f"{datetime.date(int(y), _MONTHS[mon], int(d)):%a}"
            for wd, mon, d, y in rows
            if f"{datetime.date(int(y), _MONTHS[mon], int(d)):%a}" != wd
        ]
        assert not wrong, "bob.spec weekday mismatch:\n" + "\n".join(wrong)


# ---------------------------------------------------------------------------
# 5 — the release documents must agree on the test count
# ---------------------------------------------------------------------------

class TestDocumentedTestCountIsConsistent:
    """SNAPSHOT and the four changelogs quote a test count for the release.

    Nothing recomputes it, and coupling it to the *live* count would make the
    guard fail on every commit that adds a test — the number describes a
    release, not the working tree. What is checkable with zero noise is that
    the documents agree with each other: during the v0.14.0 release the
    changelogs were written with 6591 (an arithmetic slip: 6547 + 29 = 6576)
    while SNAPSHOT, computed from an actual collection run, said 6576.
    """

    _SOURCES = [
        ("DOCUMENTS/SNAPSHOT.md", r"(\d{4,}) unit tests"),
        ("CHANGELOG.md", r"\*\*Tests\*\* [\d ]+→ \*\*(\d{4,})\*\*"),
        ("CHANGELOG_FR.md", r"\*\*Tests\*\* [\d ]+→ \*\*(\d{4,})\*\*"),
        ("DOCUMENTS/CHANGELOG_FULL.md", r"→ \*\*(\d{4,})\*\*"),
        ("DOCUMENTS/CHANGELOG_FULL_FR.md", r"→ \*\*(\d{4,})\*\*"),
    ]

    def test_all_release_documents_quote_the_same_count(self):
        found = {}
        for rel, pattern in self._SOURCES:
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            m = re.search(pattern, text)
            assert m, f"no test count found in {rel} (pattern {pattern!r})"
            found[rel] = int(m.group(1))
        counts = set(found.values())
        assert len(counts) == 1, (
            "the release documents disagree on the test count:\n"
            + "\n".join(f"  {k}: {v}" for k, v in found.items())
        )

    def test_documented_count_matches_a_real_collection(self):
        """Cheap sanity bound: the documented figure must be in the right
        ballpark of what pytest actually collects, so a stale release number
        cannot drift by hundreds unnoticed."""
        text = (_REPO_ROOT / "DOCUMENTS" / "SNAPSHOT.md").read_text(encoding="utf-8")
        documented = int(re.search(r"(\d{4,}) unit tests", text).group(1))
        # NOT -q: the quiet collector prints per-file counts and omits the
        # "N tests collected" summary line this guard reads.
        out = subprocess.run(
            [sys.executable, "-m", "pytest", "-p", "no:cacheprovider",
             "--collect-only"],
            capture_output=True, text=True, cwd=_REPO_ROOT,
        ).stdout
        m = re.search(r"(\d+) tests collected", out)
        if not m:
            pytest.skip("could not read the collected count")
        live = int(m.group(1))
        assert abs(live - documented) <= 50, (
            f"SNAPSHOT documents {documented} tests, pytest collects {live} — "
            "the release figure has drifted; refresh it at ship time"
        )



class TestDocumentedTestInventoryIsAccurate:
    """SNAPSHOT quotes the test inventory — file count, function count,
    collected count — in more than one place, and nothing kept them in step.

    Found during v0.15.0: the two lines had drifted apart *inside the same
    document* (one said 140 files / 4791 functions, the other still 139 /
    4785) while both agreed on the collected total, because only the total
    had a guard. A SNAPSHOT that contradicts itself is worse than one that is
    merely stale — a reader has no way to tell which half to trust.

    Calibration, deliberate: the file count is an inventory and is checked
    strictly; the function count is written with a `~` and gets a tolerance
    band. Measuring strict LoC-style equality on every figure was rejected —
    it fails on roughly half of all commits and trains people to ignore the
    guard.
    """

    _INVENTORY_RE = re.compile(r"(\d+) test files, ~(\d+) functions, \*{0,2}(\d{4,})")

    def _quotes(self) -> list[tuple[int, int, int]]:
        text = (_REPO_ROOT / "DOCUMENTS" / "SNAPSHOT.md").read_text(encoding="utf-8")
        found = [tuple(int(g) for g in m.groups())
                 for m in self._INVENTORY_RE.finditer(text)]
        assert found, "no test-inventory line found in SNAPSHOT.md"
        return found

    def test_snapshot_does_not_contradict_itself(self):
        quotes = self._quotes()
        assert len(set(quotes)) == 1, (
            "SNAPSHOT.md quotes the test inventory more than once and the "
            f"copies disagree: {quotes} — (files, functions, collected)"
        )

    def test_documented_file_count_is_exact(self):
        files, _, _ = self._quotes()[0]
        live = len(list((_REPO_ROOT / "tests").glob("test_*.py")))
        assert files == live, (
            f"SNAPSHOT.md documents {files} test files, the tree holds {live}"
        )

    def test_documented_function_count_is_close(self):
        _, functions, _ = self._quotes()[0]
        live = sum(
            len(re.findall(r"^\s*def test_", f.read_text(encoding="utf-8"), re.M))
            for f in (_REPO_ROOT / "tests").glob("test_*.py")
        )
        assert abs(live - functions) <= 50, (
            f"SNAPSHOT.md documents ~{functions} test functions, the tree "
            f"holds {live}"
        )



# ---------------------------------------------------------------------------
# 6 — the documented exit codes must match the real constants
# ---------------------------------------------------------------------------

class TestExitCodesAreDocumentedCorrectly:
    """The exit codes are a stable public API, and the root README had them
    wrong: it mapped each code to a *score band* (``0`` = score >= 7, ``3`` =
    score 0) when the codes are driven by finding counts and ``3`` is a
    technical error. Nothing caught it — the version guards pin versions, the
    counter guard pins counters, but nobody checked the contract itself.
    """

    _DOCS = ["README.md", "README_FR.md",
             "DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md"]
    _ROW = re.compile(r"\|\s*`(\d)`\s*\|\s*`(EXIT_[A-Z_]+)`\s*\|")

    @staticmethod
    def _constants() -> dict[str, int]:
        import bob.__main__ as m
        return {k: getattr(m, k) for k in dir(m) if k.startswith("EXIT_")}

    @pytest.mark.parametrize("rel_path", _DOCS)
    def test_documented_codes_match_the_real_constants(self, rel_path):
        text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
        rows = self._ROW.findall(text)
        assert rows, (
            f"{rel_path} documents no `N` | `EXIT_*` row — the exit-code "
            "table is missing or its shape changed"
        )
        consts = self._constants()
        errors = []
        for code, name in rows:
            if name not in consts:
                errors.append(f"  {rel_path}: unknown constant {name}")
            elif consts[name] != int(code):
                errors.append(f"  {rel_path}: documents {name} as {code}, "
                              f"real value is {consts[name]}")
        assert not errors, "exit-code drift:\n" + "\n".join(errors)

    @pytest.mark.parametrize("rel_path", _DOCS)
    def test_every_constant_is_documented(self, rel_path):
        text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
        documented = {name for _, name in self._ROW.findall(text)}
        missing = sorted(set(self._constants()) - documented)
        assert not missing, f"{rel_path} omits exit code(s): {missing}"

    @pytest.mark.parametrize("rel_path", _DOCS)
    def test_no_score_band_wording_in_the_exit_table(self, rel_path):
        """`3` is EXIT_ERROR, not "score 0". Score bands in that table are the
        exact defect this guard exists for."""
        text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
        bad = re.findall(r"\|\s*`\d`\s*\|\s*(?:Score|score)\s*[>=\u2265 0-9]", text)
        assert not bad, (
            f"{rel_path} maps an exit code to a score band; the codes are "
            f"driven by finding counts: {bad}"
        )
