"""The finding key is identity, and one sink out of six dropped it.

``message`` is translated prose. It changes with the locale and it changes
when a release rewords it. ``key`` is the stable identifier: it is what
``--explain`` and ``--ignore`` take as input, what a baseline is keyed on,
and what ``unverified`` lists.

Five sinks carried it. CSV did not, so a CSV row could not be tied back to
the finding it describes: no ``--explain``, no ``--ignore``, and no join
against a JSON baseline. Two CSVs of the same audit, one exported under
``--french`` and one under English, shared no column that meant the same
thing.

This is the third field CSV silently dropped — ``detail`` was the second,
closed as T11 in v0.8.1. So this guard checks every sink rather than the
one that was wrong today.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from bob import i18n
from bob.report import SystemInfo
from bob.scoring import Deduction, Finding, FindingLevel, ScoreEngine

_KEY = "hardening.rp_filter_disabled"
_KEY2 = "suid_audit.unowned_suid"


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


@pytest.fixture
def engine() -> ScoreEngine:
    e = ScoreEngine()
    e._apply_deduction(Deduction(reason=_KEY, points=1, key=_KEY))
    e._apply_deduction(Deduction(reason=_KEY2, points=2, key=_KEY2))
    e.findings += [
        Finding(
            level=FindingLevel.WARN,
            message="IPv4 rp_filter is disabled",
            key=_KEY, nature="action",
            cmd="sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
            # v0.18.0 carries the native instruction alongside the one-liner.
            # The marker is deliberately absent from cmd and message, so a
            # sink that leaks the action is caught by its content and not by
            # the field's name — `str(dict)` never contains "fix_action".
            fix_action={"kind": "sysctl",
                        "param": "net.ipv4.conf.all.rp_filter", "value": "1",
                        "marker": "NATIVE-ONLY-7f3a"},
        ),
        Finding(
            level=FindingLevel.ALERT,
            message="/usr/local/bin/oddbin is SUID root and belongs to no package",
            key=_KEY2, nature="action",
            cmd="sudo chmod u-s /usr/local/bin/oddbin",
        ),
    ]
    return e


@pytest.fixture
def sys_info() -> SystemInfo:
    return SystemInfo(
        hostname="bench", os_name="Alpine 3.22", kernel="6.12.0",
        ufw_version=None, iptables_version=None, nftables_version=None,
        user="root", config_path="", language="en", version="0.18.0",
    )


# ---------------------------------------------------------------------------
# The sink that was wrong
# ---------------------------------------------------------------------------

def test_csv_names_the_key_of_every_finding(engine, sys_info):
    from bob.csv_output import build_csv_output

    rows = list(csv.DictReader(io.StringIO(build_csv_output(engine, sys_info))))

    assert "key" in rows[0], "CSV has no column naming the finding"
    assert [r["key"] for r in rows] == [_KEY, _KEY2]


# The header as v0.17.1 shipped it. A positional consumer built against that
# release indexes into these fifteen; the new column has to come after them.
_V0171_HEADER = [
    "host", "timestamp", "score", "score_is_upper_bound", "score_low",
    "score_high", "risk", "alerts", "warnings", "level", "nature",
    "message", "detail", "fix_cmd", "note",
]


def test_csv_key_column_is_appended_not_inserted(engine, sys_info):
    """T11 put ``detail`` mid-list in v0.8.1 and made every column-by-index
    consumer re-index. There was nothing to gain by doing that again to a
    lookup field nobody reads in sequence.
    """
    from bob.csv_output import build_csv_output

    header = build_csv_output(engine, sys_info).splitlines()[0].split(",")

    assert header[: len(_V0171_HEADER)] == _V0171_HEADER, (
        "a v0.17.1 consumer reading by column index now reads the wrong field"
    )
    assert header[len(_V0171_HEADER):] == ["key"]


def test_csv_of_a_clean_audit_still_has_the_column(sys_info):
    """The no-findings row must carry every column, or the file is ragged."""
    from bob.csv_output import build_csv_output

    rows = list(csv.DictReader(io.StringIO(build_csv_output(ScoreEngine(), sys_info))))
    assert rows[0]["key"] == ""


# ---------------------------------------------------------------------------
# Every other sink, so the next drift is not silent either
# ---------------------------------------------------------------------------

def test_markdown_carries_the_key(engine, sys_info):
    from bob.markdown_output import build_markdown_output
    out = build_markdown_output(engine, sys_info)
    assert _KEY in out and _KEY2 in out


def test_html_carries_the_key(engine, sys_info):
    from bob.html_output import build_html_output
    out = build_html_output(engine, sys_info)
    assert _KEY in out and _KEY2 in out


def test_webhook_carries_the_key(engine, sys_info):
    from bob.webhook import build_generic_payload
    payload = json.dumps(build_generic_payload(engine, sys_info, "0.18.0"))
    assert _KEY in payload and _KEY2 in payload


def test_json_declares_a_key_field_for_findings():
    """``build_json_data`` needs a dozen snapshots; the field is what matters."""
    from pathlib import Path
    src = Path("bob/json_output.py").read_text(encoding="utf-8")
    assert '"key":           f.key,' in src, (
        "the JSON findings list no longer names the finding key"
    )


# ---------------------------------------------------------------------------
# The internal instruction is not a fact about the machine
# ---------------------------------------------------------------------------

def test_fix_action_stays_out_of_every_sink(engine, sys_info):
    """v0.18.0's ``fix_action`` tells BOB how to apply a fix. It is not a
    measurement, and no sink should present it as one.
    """
    from bob.csv_output import build_csv_output
    from bob.html_output import build_html_output
    from bob.markdown_output import build_markdown_output
    from bob.webhook import build_generic_payload

    rendered = {
        "csv": build_csv_output(engine, sys_info),
        "markdown": build_markdown_output(engine, sys_info),
        "html": build_html_output(engine, sys_info),
        "webhook": json.dumps(build_generic_payload(engine, sys_info, "0.18.0")),
    }
    for name, text in rendered.items():
        assert "NATIVE-ONLY-7f3a" not in text, (
            f"{name} prints the contents of the internal fix action"
        )
        assert "fix_action" not in text, f"{name} names the internal fix action"
