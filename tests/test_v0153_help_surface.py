"""v0.15.3 — the --help surface: translated, accurate, and bounded.

Three defects closed here:

* ``--help`` was byte-identical English under ``--french``, ``--lang=fr`` and
  ``LANG=fr_FR`` — on the one screen that advertises ``--french``. The seam had
  existed since v0.1.0: ``print_help(t, version)`` took ``t`` behind a
  ``# noqa: ARG001 — t reserved for future i18n`` and never called it.
* The ``--install-completion`` example interpolated
  ``Path(sys.argv[0]).resolve()``, printing a command that fails from a source
  checkout and a venv-internal path under pipx.
* Eight short forms and two aliases were advertised in ``--help`` but absent
  from the man page.

The width contract at the bottom is new: it was informal (a de-facto ~100
ceiling that seven lines already broke, one by 50 characters). Both locales now
sit under it, so it is worth enforcing before it drifts again.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

from bob import i18n
from bob.cli import print_help

ROOT = Path(__file__).resolve().parent.parent
LOCALES = ("en", "fr")
MAX_WIDTH = 100


def render(lang: str) -> str:
    i18n.init(lang=lang)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_help(i18n.t, "0.15.3")
    return buf.getvalue()


def locale_help_keys(loc: str) -> set[str]:
    data = json.loads((ROOT / "bob" / "locales" / f"{loc}.json").read_text(encoding="utf-8"))
    flat: set[str] = set()

    def walk(node, prefix=""):
        for k, v in node.items():
            if isinstance(v, dict):
                walk(v, f"{prefix}{k}.")
            else:
                flat.add(f"{prefix}{k}")

    walk(data["help"], "help.")
    return flat


def referenced_help_keys() -> set[str]:
    """Keys cli.py actually asks for, including the f-string-built ones."""
    src = (ROOT / "bob" / "cli.py").read_text(encoding="utf-8")
    keys = set(re.findall(r"""['"](help\.[a-z0-9_.]+)['"]""", src))
    # section("audit") / ex(cmd, "standard") / t(f'help.exit.{n}') build keys
    keys |= {f"help.section.{n}" for n in re.findall(r'\bsection\("([a-z_]+)"\)', src)}
    keys |= {f"help.example.{n}" for n in re.findall(r'\bex\([^,]+,\s*"([a-z0-9]+)"\)', src)}
    keys |= {f"help.exit.{n}" for n in range(5)}
    return {k for k in keys if not k.endswith(".")}


class TestTranslated:
    def test_french_help_is_not_english(self):
        """The defect itself: the two renderings were byte-identical."""
        assert render("en") != render("fr")

    @pytest.mark.parametrize("lang", LOCALES)
    def test_no_bracketed_fallback(self, lang):
        """A missing key renders as [help.x] — the v0.9.1 failure mode."""
        assert not re.findall(r"\[help\.[a-z0-9_.]+\]", render(lang))

    def test_french_actually_reads_as_french(self):
        out = render("fr")
        assert "Utilisation :" in out
        assert "EXEMPLES" in out
        assert "CODES DE SORTIE" in out

    @pytest.mark.parametrize("lang", LOCALES)
    def test_flags_are_not_translated(self, lang):
        """Flags are CLI syntax, not prose — they must survive every locale."""
        out = render(lang)
        for flag in ("--profile=NAME", "--reconfigure", "--install-completion", "-j / -J"):
            assert flag in out

    @pytest.mark.parametrize("loc", LOCALES)
    def test_every_referenced_key_exists(self, loc):
        missing = sorted(referenced_help_keys() - locale_help_keys(loc))
        assert not missing, f"{loc}.json is missing: {missing}"

    @pytest.mark.parametrize("loc", LOCALES)
    def test_no_orphan_keys(self, loc):
        orphans = sorted(locale_help_keys(loc) - referenced_help_keys())
        assert not orphans, f"{loc}.json carries unused help keys: {orphans}"

    def test_locale_parity(self):
        assert locale_help_keys("en") == locale_help_keys("fr")


class TestInstallCompletionExample:
    """The advertised command must be one the reader can paste."""

    @staticmethod
    def _example(argv0: str) -> str:
        i18n.init(lang="en")
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", [argv0]), contextlib.redirect_stdout(buf):
            print_help(i18n.t, "0.15.3")
        return next(
            l.strip() for l in buf.getvalue().splitlines()
            if "--install-completion" in l and "sudo" in l
        )

    def test_source_checkout_suggests_the_module_form(self):
        """bob/__main__.py is mode 644 with no shebang: executing it fails."""
        line = self._example("/src/bodyguard-of-bits/bob/__main__.py")
        assert line.endswith("-m bob --install-completion")
        assert "__main__.py" not in line

    def test_entry_point_on_path_suggests_the_bare_name(self):
        """Not the pipx venv-internal real path .resolve() used to expose."""
        with mock.patch("shutil.which", return_value="/home/u/.local/bin/bob"):
            line = self._example("/home/u/.local/bin/bob")
        assert line == "sudo bob --install-completion"

    def test_off_path_binary_keeps_its_full_path(self):
        with mock.patch("shutil.which", return_value=None):
            line = self._example("/opt/odd/place/bobx")
        assert line == "sudo /opt/odd/place/bobx --install-completion"


class TestManPageDocumentsEveryOption:
    """--help and the man page are the two advertised surfaces; they must agree."""

    @staticmethod
    def _advertised() -> set[str]:
        out = render("en")
        adv: set[str] = set()
        for line in out.splitlines():
            m = re.match(r"^ {2,6}(-{1,2}[\w-]+.*?)(?:\s{2,}|$)", line)
            if m:
                adv.update(tok.rstrip("=") for tok in re.findall(r"-{1,2}[\w-]+", m.group(1)))
        adv |= set(re.findall(r"\(alias (--[\w-]+)\)", out))
        return adv

    def test_no_advertised_option_is_missing_from_the_man_page(self):
        page = (ROOT / "man" / "bob.1").read_text(encoding="utf-8")
        page = page.replace("\\-", "-").replace("\\&", "")
        missing = sorted(
            o for o in self._advertised()
            if not re.search(re.escape(o) + r"(?![\w-])", page)
        )
        assert not missing, f"advertised in --help, absent from man/bob.1: {missing}"

    def test_the_harness_finds_options_at_all(self):
        """A drift check that scrapes nothing would pass forever."""
        adv = self._advertised()
        assert len(adv) > 50, f"only {len(adv)} options scraped — the regex broke"


class TestWidthContract:
    @pytest.mark.parametrize("lang", LOCALES)
    def test_no_line_exceeds_the_ceiling(self, lang):
        """Measured in characters, not bytes: em dashes and ↑↓ are multi-byte."""
        long = [
            (len(l), l) for l in render(lang).splitlines() if len(l) > MAX_WIDTH
        ]
        assert not long, f"{lang}: {long}"

    @pytest.mark.parametrize("lang", LOCALES)
    def test_the_ceiling_is_not_trivially_satisfied(self, lang):
        """If the help were tiny or empty the contract would prove nothing."""
        lines = [l for l in render(lang).splitlines() if l.strip()]
        assert len(lines) > 70
        assert max(len(l) for l in lines) > 80
