"""A default that stands in for a measurement is a way of inventing one.

Found by declining the blind-audit instrument onto files: bind-mount an
unreadable file over each path BOB reads, one at a time, and look for a verdict
that appears.

`/proc/sys/vm/swappiness` produced `memory.swappiness_ssd_wear` — WARN with a
point — on a host whose real swappiness is 10. `_read_swappiness()` returned 60
on error, its docstring said so plainly, and the check compared that number
against the SSD threshold of 30 without knowing it had never been read.

The instrument's own limits are worth recording alongside the finding. The mask
replaces a file rather than merely revoking access, so it also changes st_mode
and st_uid: `/etc/sudoers` appeared to gain `file_perms.sudoers_file.too_permissive`,
which is the mask's permissions being reported faithfully, not a defect. A
sweep whose artefacts are not named will be read as ten findings instead of one.
"""

from __future__ import annotations

import pytest

import bob.checks.memory as memory
from bob.checks.memory import MemorySnapshot, check_memory


class TestAnUnreadValueStaysUnknown:
    def test_the_reader_answers_none(self, monkeypatch):
        def boom(*a, **kw):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(memory.Path, "read_text", boom)
        assert memory._read_swappiness() is None

    def test_a_real_value_is_still_read(self):
        value = memory._read_swappiness()
        assert value is None or 0 <= value <= 200

    def test_the_default_is_unknown(self):
        assert MemorySnapshot().swappiness is None


class TestNoVerdictOnAValueNeverMeasured:
    def test_unknown_swappiness_on_ssd_does_not_warn(self):
        snapshot = MemorySnapshot(swap_on_ssd=True, swappiness=None,
                                  mem_total_kb=8_000_000, swap_total_kb=2_000_000)
        result = check_memory(snapshot)
        keys = [f.key for f in result.findings]
        assert "memory.swappiness_ssd_wear" not in keys, (
            "a value that could not be read must not produce a verdict about it"
        )
        assert not any(d.key == "memory.swappiness_ssd_wear" for d in result.deductions)

    def test_a_measured_high_value_still_warns(self):
        """Polarity twin. Without it, a check that never warns would pass the
        test above and stop auditing swappiness entirely."""
        snapshot = MemorySnapshot(swap_on_ssd=True, swappiness=60,
                                  mem_total_kb=8_000_000, swap_total_kb=2_000_000)
        result = check_memory(snapshot)
        assert "memory.swappiness_ssd_wear" in [f.key for f in result.findings]
        assert result.deductions

    def test_a_measured_low_value_does_not(self):
        snapshot = MemorySnapshot(swap_on_ssd=True, swappiness=10,
                                  mem_total_kb=8_000_000, swap_total_kb=2_000_000)
        result = check_memory(snapshot)
        assert "memory.swappiness_ssd_wear" not in [f.key for f in result.findings]


class TestNoOtherCheckSubstitutesADefaultForAReading:
    """Anti-drift guard for the shape, not just this one reader.

    A helper that answers a plausible number when it could not read is
    indistinguishable from one that measured it. The pattern to reject is a
    numeric literal returned from an `except` that catches an I/O error —
    inside a *reader*. A first draft checked every function and flagged four
    `return 1` statements in cron installers, which are exit codes, not
    measurements: a guard that cannot tell those apart reports noise and gets
    switched off.
    """

    def test_no_reader_returns_a_number_from_an_except_block(self):
        import ast
        from pathlib import Path as P

        root = P(__file__).resolve().parent.parent / "bob"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            readers = [
                fn for fn in ast.walk(tree)
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                and fn.name.lstrip("_").startswith("read")
            ]
            for node in [h for fn in readers for h in ast.walk(fn)]:
                if not isinstance(node, ast.ExceptHandler):
                    continue
                caught = ast.dump(node.type) if node.type else ""
                if "OSError" not in caught and "IOError" not in caught:
                    continue
                for stmt in node.body:
                    if (isinstance(stmt, ast.Return)
                            and isinstance(stmt.value, ast.Constant)
                            and isinstance(stmt.value.value, (int, float))
                            and not isinstance(stmt.value.value, bool)
                            and stmt.value.value != 0):
                        offenders.append(
                            f"{path.relative_to(root.parent)}:{stmt.lineno} "
                            f"returns {stmt.value.value!r}"
                        )
        assert not offenders, (
            "a reader answers a plausible number when it could not read, which "
            f"is indistinguishable from having measured it: {offenders}"
        )
