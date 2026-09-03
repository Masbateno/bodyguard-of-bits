"""CSV serialization of audit results.

Produces a flat CSV with one row per finding, suitable for spreadsheet
or dashboard integration.  Metadata columns (host, timestamp, score,
risk, alerts, warnings) are repeated on every row so that a single
import gives a self-contained dataset.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from bob.report import SystemInfo
from bob.scoring import ScoreEngine

_HEADERS = [
    "host",
    "timestamp",
    "score",
    "score_is_upper_bound",
    "risk",
    "alerts",
    "warnings",
    "level",
    # I-3 (v0.7.3): column renamed from "section" → "nature" to match the
    # actual data it carries (Finding.nature: "action" / "improvement" /
    # "structural" / ""). Pre-v0.7.3 the column was labelled "section"
    # because of a historic misalignment between the producer and the
    # _HEADERS list; external CSV consumers parsing "section" received
    # nature strings, not audit section names. **Breaking change** for
    # those consumers — see CHANGELOG.
    "nature",
    "message",
    # T11 (v0.8.1): ``detail`` joins the per-finding columns to reach parity
    # with terminal / text / Markdown / HTML / JSON which all surface
    # ``Finding.detail`` (the secondary explanation often shown after the
    # main message, e.g. "Restrict SUID dumps to root: …"). Pre-v0.8.1 CSV
    # dropped this field silently so monitoring pipelines lost the
    # explanatory context. Additive column — CSV has no schema_version
    # field but the new column appears AFTER ``message`` and BEFORE
    # ``fix_cmd`` so column-by-name consumers (DictReader) are unaffected;
    # column-by-index readers must re-index.
    "detail",
    "fix_cmd",
    "note",
]


# v0.14.1: characters that make a spreadsheet treat a cell as a formula.
# csv.DictWriter quotes correctly per RFC 4180, but Excel / LibreOffice still
# evaluate a quoted field that begins with one of these — so an audit report
# opened in a spreadsheet could execute content that merely passed *through*
# BOB (a cron command line, a container name, a SUID path). Neutralised by
# prefixing a single quote, the standard mitigation: the cell renders as text
# and the original value is preserved verbatim after it.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection in a free-text CSV field."""
    if value and value.startswith(_FORMULA_LEAD):
        return "'" + value
    return value


def build_csv_output(
    engine: ScoreEngine,
    sys_info: SystemInfo,
) -> str:
    """Return a CSV string with one row per finding.

    If the audit produced no findings (perfect score), a single summary row
    with empty level / nature / message is returned so that the file is
    always non-empty and importable.
    """
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # I-6 (v0.7.4): `risk` is the score-derived level (not posture-escalated),
    # matching JSON v1's `risk` field which was restored to `engine.level` by
    # v0.7.1 I-3 to preserve the v0.6.x wire-format. Pre-v0.7.4 CSV used
    # `engine.effective_level` (posture-escalated), causing CSV and JSON v1
    # to disagree on the same audit when posture escalation fires.
    # **Breaking change** for CSV consumers reading posture-escalated risk.
    meta = {
        "host":      sys_info.hostname,
        "timestamp": ts,
        "score":     engine.score,
        # Additive column rather than "≤ 7" in the score cell: a spreadsheet
        # consumes that column as a number, and prefixing it would break every
        # existing formula. The flag says what the number is worth.
        "score_is_upper_bound": int(engine.score_is_upper_bound),
        "risk":      engine.level.value,
        "alerts":    engine.alert_count,
        "warnings":  engine.warn_count,
    }

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_HEADERS, lineterminator="\n")
    writer.writeheader()

    if not engine.findings:
        writer.writerow({**meta, "level": "", "nature": "", "message": "",
                         "detail": "", "fix_cmd": "", "note": ""})
    else:
        for f in engine.findings:
            writer.writerow({
                **meta,
                "level":   f.level.value,
                "nature":  f.nature   or "",
                "message": _csv_safe(f.message or ""),
                "detail":  _csv_safe(f.detail  or ""),
                "fix_cmd": _csv_safe(f.cmd     or ""),
                "note":    _csv_safe(f.note    or ""),
            })

    return buf.getvalue()
