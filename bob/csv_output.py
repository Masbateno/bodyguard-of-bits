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
    "fix_cmd",
    "note",
]


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
        "risk":      engine.level.value,
        "alerts":    engine.alert_count,
        "warnings":  engine.warn_count,
    }

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_HEADERS, lineterminator="\n")
    writer.writeheader()

    if not engine.findings:
        writer.writerow({**meta, "level": "", "nature": "", "message": "", "fix_cmd": "", "note": ""})
    else:
        for f in engine.findings:
            writer.writerow({
                **meta,
                "level":   f.level.value,
                "nature":  f.nature   or "",
                "message": f.message  or "",
                "fix_cmd": f.cmd      or "",
                "note":    f.note     or "",
            })

    return buf.getvalue()
