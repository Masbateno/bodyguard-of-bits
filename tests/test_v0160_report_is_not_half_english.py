"""
v0.16.0 — a French audit's .log opened in English and closed in English.

Found in a real audit the maintainer ran on his own machine with v0.16.0, in
French. Between a header saying `[INFORMATIONS SYSTÈME]` and a summary saying
`[RÉSUMÉ DE L'AUDIT]`, two lines were English:

    2026-09-04 15:43:44 [INFO] Starting audit
    [NEXT STEPS]

Both are the class v0.7.3 M-5 closed for six field labels — "pre-v0.7.3 they
were hardcoded English so a French audit's .log carried mixed-language
content" — and both were missed by it.

The first is sharper than a missing translation: `bob/__main__.py` printed
``t("audit.starting")`` to the terminal and wrote the literal ``"Starting
audit"`` to the report, eight lines apart. The key existed, translated, in both
locales; the report call site simply did not use it. The same event, translated
on screen and English in the file.

The second was a heading whose three numbered steps were already translated.

`bob/report_markdown.py` is deliberately exempt, and that is recorded in its
own source: ``write_header`` receives ``labels`` and discards them with
``_ = labels  # intentionally unused for now``. That module is the cron email
report, English by decision rather than by oversight — a different question,
and not one a guard should silently answer.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_WORD = re.compile(r"[A-Za-z]{3,}")
_WRITERS = ("_writeln", "write_raw", "write_line")


def _literal_writes(path: Path) -> list[tuple[int, str]]:
    """Operator-visible strings written as literals rather than translated."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _WRITERS:
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if _WORD.search(arg.value):
                    found.append((node.lineno, arg.value))
    return found


class TestTheTextReportIsFullyTranslated:

    def test_no_english_literal_is_written_to_the_report(self):
        offenders = _literal_writes(_ROOT / "bob" / "report.py")
        assert not offenders, (
            "bob/report.py writes these as literals, so they stay English in a "
            "French audit's .log:\n"
            + "\n".join(f"  line {ln}: {v!r}" for ln, v in offenders)
            + "\nRoute them through the translator, as the six field labels "
              "were in v0.7.3 M-5."
        )

    def test_the_two_fixed_strings_come_from_locales(self):
        for locale in ("en", "fr"):
            import json

            data = json.loads(
                (_ROOT / "bob" / "locales" / f"{locale}.json").read_text(encoding="utf-8")
            )
            assert data["audit"]["starting"]
            assert data["report"]["next_steps_title"]

    def test_the_report_call_site_uses_the_key_the_terminal_uses(self):
        """
        The key existed and was translated; only the report call site ignored
        it. Both lines must resolve the same key, or the same event is
        reported in two languages eight lines apart.
        """
        source = (_ROOT / "bob" / "__main__.py").read_text(encoding="utf-8")
        assert 'report.write_finding("INFO", t("audit.starting"))' in source
        assert '"Starting audit"' not in source


class TestTheEmailReportIsExemptOnPurpose:

    def test_the_exemption_is_recorded_in_its_own_source(self):
        """
        Not an oversight: write_header takes `labels` and discards them with a
        comment saying so. A guard must not quietly overturn a decision its
        author wrote down — if that changes, this test is where to notice.
        """
        source = (_ROOT / "bob" / "report_markdown.py").read_text(encoding="utf-8")
        assert "_ = labels  # intentionally unused for now" in source, (
            "bob/report_markdown.py no longer records why it ignores labels — "
            "either it now honours them (drop this exemption and add it to the "
            "guard above) or the rationale was lost"
        )
