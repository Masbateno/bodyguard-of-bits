"""v0.15.3 — a leap day could take out the whole UFW log section.

Syslog timestamps carry no year, so ``_parse_timestamp`` builds the date with
the current year and rolls back one year when the result looks future-dated.
The ``datetime(current_year, ...)`` construction was guarded against
ValueError; the rollback that followed was not:

    ts = ts.replace(year=ts.year - 1)

Feb 29 exists in a leap year and not in the one before it. One such line
raised out of ``_parse_log``, and the runner's section-level barrier degraded
the entire log analysis — blocked-attempt statistics, top source IPs,
bruteforce detection windows — from a single line.

Nothing that worked before changed: a Feb 29 line of the current leap year,
read on or after that day, still parses exactly as it did.
"""

from __future__ import annotations

import ast
from datetime import datetime
from pathlib import Path

import pytest

import bob.checks.logs as logs_mod
from bob.checks.logs import _parse_log, _parse_timestamp

ROOT = Path(__file__).resolve().parent.parent

FEB29 = "Feb 29 10:00:00 h kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=22"
FEB28 = "Feb 28 10:00:00 h kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=22"


class TestLeapDayMatrix:
    @pytest.mark.parametrize(
        "year, now, expected",
        [
            # The cases that actually happen: a Feb 29 line of the current
            # leap year, read on or after that day. Unchanged by the fix.
            (2028, datetime(2028, 6, 1), datetime(2028, 2, 29, 10, 0, 0)),
            (2028, datetime(2028, 3, 1), datetime(2028, 2, 29, 10, 0, 0)),
            (2028, datetime(2028, 2, 29, 12), datetime(2028, 2, 29, 10, 0, 0)),
            # Future-dated in a leap year: came from an earlier leap year or a
            # clock behind. Used to raise; now skipped like any unusable line.
            (2028, datetime(2028, 1, 15), None),
            # Non-leap current year: already skipped before this fix, by the
            # datetime() guard. Listed so the two paths stay symmetric.
            (2027, datetime(2027, 6, 1), None),
        ],
    )
    def test_feb_29(self, year, now, expected):
        assert _parse_timestamp(FEB29, year, now) == expected

    def test_the_benign_twin_still_rolls_back(self):
        """Feb 28 in the same scenario must still roll back — otherwise the
        test above would pass on a parser that simply dropped every rollback."""
        assert _parse_timestamp(FEB28, 2028, datetime(2028, 1, 15)) == datetime(
            2027, 2, 28, 10, 0, 0
        )


class TestOneLineCannotCostTheSection:
    @staticmethod
    def _frozen(monkeypatch, when: datetime):
        class FakeDT(datetime):
            @classmethod
            def now(cls, tz=None):
                return when

        monkeypatch.setattr(logs_mod, "datetime", FakeDT)

    def test_a_leap_day_line_does_not_abort_the_parse(self, monkeypatch):
        self._frozen(monkeypatch, datetime(2028, 1, 15, 12))
        content = "\n".join([
            FEB29.replace("SRC=1.2.3.4", "SRC=9.9.9.9"),
            "Jan 14 10:00:00 h kernel: [UFW BLOCK] IN=eth0 SRC=7.7.7.7 DST=5.6.7.8 PROTO=TCP DPT=80",
            FEB28,
        ])
        entries = _parse_log(content, datetime(2027, 1, 1))
        assert len(entries) == 2, "the surviving lines must still be parsed"

    def test_the_same_log_without_the_leap_line_is_unaffected(self, monkeypatch):
        """Polarity pair: proves the assertion above measures the leap day and
        not some unrelated property of the fixture."""
        self._frozen(monkeypatch, datetime(2028, 1, 15, 12))
        content = "\n".join([
            "Jan 14 10:00:00 h kernel: [UFW BLOCK] IN=eth0 SRC=7.7.7.7 DST=5.6.7.8 PROTO=TCP DPT=80",
            FEB28,
        ])
        assert len(_parse_log(content, datetime(2027, 1, 1))) == 2


class TestNoUnguardedDateArithmetic:
    """Anti-drift guard generalising the defect.

    ``.replace(year=…)`` and its month/day siblings raise ValueError on a date
    that does not exist in the target — Feb 29 into a non-leap year, day 31
    into a 30-day month. Every such call must sit inside a try that handles
    ValueError.
    """

    @staticmethod
    def _protected_ranges(tree: ast.AST) -> list[tuple[int, int]]:
        ranges = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            handles = False
            for handler in node.handlers:
                exc = handler.type
                names = []
                if isinstance(exc, ast.Name):
                    names = [exc.id]
                elif isinstance(exc, ast.Tuple):
                    names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
                elif exc is None:
                    handles = True
                if {"ValueError", "Exception", "BaseException"} & set(names):
                    handles = True
            if handles:
                for stmt in node.body:
                    ranges.append((stmt.lineno, getattr(stmt, "end_lineno", stmt.lineno)))
        return ranges

    def test_every_date_replace_is_guarded(self):
        offenders = []
        for path in sorted(ROOT.joinpath("bob").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            ranges = self._protected_ranges(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                if node.func.attr != "replace":
                    continue
                if not any(k.arg in ("year", "month", "day") for k in node.keywords):
                    continue
                if not any(lo <= node.lineno <= hi for lo, hi in ranges):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        assert not offenders, f"unguarded date replace(): {offenders}"

    def test_the_guard_finds_the_call_it_is_meant_to_watch(self):
        """A sweep that matches nothing would pass forever."""
        src = (ROOT / "bob" / "checks" / "logs.py").read_text(encoding="utf-8")
        assert "replace(year=ts.year - 1)" in src
