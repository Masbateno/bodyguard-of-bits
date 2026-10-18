"""v0.25.1 — `--help` says what -v adds.

It said "Show detailed port exposure for each service"; -v also prints, under
every finding, its detail, command, note and CIS reference (display.py
_emit_finding_body), plus the listening-port table and `ufw status verbose`.
"""

import json
from pathlib import Path

_LOC = Path(__file__).resolve().parent.parent / "bob" / "locales"


def test_the_help_names_the_per_finding_detail():
    for lang in ("en", "fr"):
        text = json.loads((_LOC / f"{lang}.json").read_text(encoding="utf-8"))["help"]["opt"]["verbose"]
        assert "CIS" in text and "port" in text, (lang, text)
