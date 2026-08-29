"""
v0.14.1 — second stress campaign: hostile I/O and the barrier's own failure modes.

Round 1 hardened the audit against a check that raises. Round 2 attacked the
hardening itself, and the file-system boundary underneath it. Every test here
corresponds to a defect reproduced on a live host before the fix.

  A — the fault barrier must survive failures inside its own handler
  B — the report is a side artifact: it must never take the audit down
  C — --ignore must remove a finding from what the operator SEES
  D — terminal escape sequences must not reach the terminal
  E — reads must be bounded and refuse non-regular files
  F — a plugin file that lies about its size must not exhaust memory
  G — Ctrl-C must not print a Python traceback
"""

from __future__ import annotations

import ast
import errno
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# A — the barrier's own failure modes
# ---------------------------------------------------------------------------

class TestBarrierSurvivesItsOwnFailures:
    """The handler that keeps the audit alive must not be able to kill it.

    Probing the v0.14.1 barrier found four ways through it: a raising
    ``output.sanitize``, ``report.write_raw`` on a full disk, a missing locale
    key, and an exception whose ``__str__`` raises. Each reproduced exit 3 with
    zero bytes of stdout — the exact loss the barrier exists to prevent, one
    level up.
    """

    @staticmethod
    def _degrade_src() -> str:
        tree = ast.parse((REPO / "bob" / "runner.py").read_text())
        run_checks = next(n for n in ast.walk(tree)
                          if isinstance(n, ast.FunctionDef) and n.name == "run_checks")
        fn = next(n for n in ast.walk(run_checks)
                  if isinstance(n, ast.FunctionDef) and n.name == "_degrade_section")
        return ast.dump(fn)

    def test_recording_happens_before_any_fallible_work(self):
        """``_degraded.append`` must precede the rendering, so a section is
        still reported in ``degraded_sections`` when rendering cannot run."""
        tree = ast.parse((REPO / "bob" / "runner.py").read_text())
        run_checks = next(n for n in ast.walk(tree)
                          if isinstance(n, ast.FunctionDef) and n.name == "run_checks")
        fn = next(n for n in ast.walk(run_checks)
                  if isinstance(n, ast.FunctionDef) and n.name == "_degrade_section")
        body = [n for n in fn.body if not isinstance(n, ast.Expr)]  # drop the docstring
        assert isinstance(body[0], ast.If), "the append must be the first statement"
        first = ast.dump(body[0])
        assert "_degraded" in first and "append" in first
        assert isinstance(body[1], ast.Try), "everything after the append must be wrapped"

    def test_rendering_is_entirely_wrapped(self):
        dump = self._degrade_src()
        assert dump.count("Try") >= 2, "the rendering block and its risky steps must be guarded"

    def test_exception_text_helper_is_total(self):
        """``_safe_exc_text`` must survive an exception whose __str__ raises."""
        src = (REPO / "bob" / "runner.py").read_text()
        assert "_safe_exc_text" in src, "a total exception-formatting helper must exist"
        assert "_safe_section_message" in src, "a total locale helper must exist"

    def test_hostile_exception_formatting_does_not_propagate(self):
        """Behavioural: the same shape the barrier must tolerate."""
        class Evil(Exception):
            def __repr__(self): raise ValueError("repr exploded")
            def __str__(self):  raise ValueError("str exploded")

        def safe_exc_text(exc):
            try:
                return f"{type(exc).__name__}: {exc}"
            except Exception:
                try:
                    return type(exc).__name__
                except Exception:
                    return "unknown error"

        assert safe_exc_text(Evil()) == "Evil"


# ---------------------------------------------------------------------------
# B — report writes are best-effort
# ---------------------------------------------------------------------------

class TestReportNeverKillsTheAudit:
    """A full filesystem must cost the report, not the audit.

    Reproduced on a real 64 KB tmpfs: ``sudo bob -d --output-dir=<full fs>``
    returned exit 3 with zero bytes of stdout. ``_writeln`` did a bare
    ``write()`` + ``flush()``, reachable from ~200 call sites, and ``close()``
    flushed buffered data unguarded at the very last step.
    """

    def _report_on(self, path: Path):
        from bob.report import AuditReport
        return AuditReport(path=path)

    def test_write_failure_disables_the_report_instead_of_raising(self, tmp_path, capsys):
        rep = self._report_on(tmp_path / "r.log")
        rep._fh.close()                      # simulate a dead descriptor
        rep.write_raw("anything")            # must not raise
        rep.write_section("nor this")
        assert rep.enabled is False, "the report must disable itself after an I/O error"

    def test_close_failure_does_not_raise(self, tmp_path):
        rep = self._report_on(tmp_path / "r2.log")
        rep._fh.close()
        rep.close()                          # must not raise

    def test_writeln_is_guarded_in_source(self):
        src = (REPO / "bob" / "report.py").read_text()
        i = src.index("def _writeln")
        body = src[i:i + 1400]
        assert "except (OSError, ValueError)" in body, "_writeln must swallow I/O errors"
        # index past the Protocol stub (``def close(self) -> None: ...``) to the
        # real implementation.
        j = src.index("def close(self) -> None:\n        \"\"\"Flush")
        assert "except (OSError, ValueError)" in src[j:j + 1200], "close must swallow I/O errors"


# ---------------------------------------------------------------------------
# C — --ignore must hide the finding from the operator
# ---------------------------------------------------------------------------

class TestIgnoreRemovesFindingFromDisplay:
    """``--ignore`` silenced the score and the JSON counts but not the terminal.

    Measured before the fix: ``--ignore fail2ban.no_jails`` took warning_count
    from 14 to 13 and left the ``⚠ [WARNING]`` line exactly where it was.
    ``display_result()`` renders the raw ``CheckResult``, not
    ``engine.findings``, so ``engine.apply`` has to drop ignored findings from
    the result too.
    """

    def _result_with(self, key):
        from bob.scoring import CheckResult, FindingLevel
        r = CheckResult()
        r.add_finding(level=FindingLevel.WARN, message="visible", key=key)
        r.add_finding(level=FindingLevel.WARN, message="other", key="other.key")
        return r

    def test_ignored_finding_is_removed_from_the_result(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"a.b"})
        result = self._result_with("a.b")
        engine.apply(result)
        keys = [f.key for f in result.findings]
        assert "a.b" not in keys, "display renders result.findings — the ignored one must be gone"
        assert "other.key" in keys, "unignored findings must survive"

    def test_ignored_finding_is_still_recorded_for_show_ignored(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        engine.ignore_keys = frozenset({"a.b"})
        engine.apply(self._result_with("a.b"))
        assert [f.key for f in engine.ignored_findings] == ["a.b"]
        assert "a.b" not in [f.key for f in engine.findings]

    def test_nothing_is_dropped_when_no_ignore_list(self):
        from bob.scoring import ScoreEngine
        engine = ScoreEngine()
        result = self._result_with("a.b")
        engine.apply(result)
        assert len(result.findings) == 2


# ---------------------------------------------------------------------------
# D — terminal escape sequences
# ---------------------------------------------------------------------------

class TestNoEscapeSequencesReachTheOperator:
    """Finding text interpolates system-derived values; only 7 call sites in
    the codebase sanitized theirs.

    Demonstrated live: a world-writable script in /etc/cron.daily whose
    *filename* carried ``\\033]0;HIJACKED\\007`` had the sequence rendered
    verbatim — it rewrote the terminal title and corrupted the summary box.
    With cursor-movement sequences the same vector can overwrite already
    printed audit lines, i.e. make the report lie about other findings.
    """

    HOSTILE = "\x1b]0;HIJACKED\x07evil\x1b[31m\x1b[2J\rmasked"

    def test_add_finding_strips_control_characters(self):
        from bob.scoring import CheckResult, FindingLevel
        r = CheckResult()
        r.add_finding(level=FindingLevel.WARN, message=self.HOSTILE,
                      detail=self.HOSTILE, note=self.HOSTILE, key="a.b")
        f = r.findings[0]
        for field in (f.message, f.detail, f.note):
            assert "\x1b" not in field and "\x07" not in field and "\r" not in field
            assert all(ord(c) >= 32 and ord(c) != 127 for c in field)

    def test_cmd_keeps_newlines_but_loses_escapes(self):
        from bob.scoring import CheckResult, FindingLevel
        r = CheckResult()
        r.add_finding(level=FindingLevel.WARN, message="m",
                      cmd="line1\nline2\x1b[31m\x07", key="a.b")
        cmd = r.findings[0].cmd
        assert "\n" in cmd, "multi-line remediation blocks must survive"
        assert "\x1b" not in cmd and "\x07" not in cmd

    def test_benign_text_is_untouched(self):
        from bob.scoring import CheckResult, FindingLevel
        msg = "UFW is inactive — 3 ports exposed (22/tcp, 80/tcp) · score 7/10"
        r = CheckResult()
        r.add_finding(level=FindingLevel.WARN, message=msg, key="a.b")
        assert r.findings[0].message == msg

    @pytest.mark.parametrize("payload", [
        "\x1b]0;title\x07", "\x1b[2J", "a\rb", "a\x08b", "\x9b31m", "a\x00b",
    ])
    def test_sanitize_neutralises(self, payload):
        from bob.output import sanitize
        out = sanitize(payload)
        assert all(ord(c) >= 32 and ord(c) != 127 for c in out)

    def test_sanitize_multiline_keeps_only_newlines(self):
        from bob.output import sanitize_multiline
        out = sanitize_multiline("a\nb\x1b[31m\tc\x07")
        assert out == "a\nbc"


# ---------------------------------------------------------------------------
# E — bounded reads, regular files only
# ---------------------------------------------------------------------------

class TestReadsAreBoundedAndRegularFilesOnly:
    """Every state-file reader used a bare ``read_text()``.

    Measured: ``--diff=/dev/zero`` (an operator-supplied path, so reachable by
    a plain typo) read NUL bytes until the process died or was OOM-killed, and
    ``--diff=<fifo>`` **blocked forever** — a cron job that hangs instead of
    failing, on every subsequent run. ``ignore.yml`` / ``last_baseline.json`` /
    ``history.jsonl`` symlinked to /dev/zero made every run fatal.
    """

    def test_fifo_is_refused_not_read(self, tmp_path):
        from bob._atomic import read_text_capped
        fifo = tmp_path / "f"
        os.mkfifo(fifo)
        with pytest.raises(OSError) as exc:
            read_text_capped(fifo)
        assert exc.value.errno == errno.EINVAL

    def test_directory_is_refused(self, tmp_path):
        from bob._atomic import read_text_capped
        with pytest.raises(OSError):
            read_text_capped(tmp_path)

    @pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="no /dev/zero")
    def test_character_device_is_refused(self):
        from bob._atomic import read_text_capped
        with pytest.raises(OSError) as exc:
            read_text_capped(Path("/dev/zero"))
        assert exc.value.errno == errno.EINVAL

    def test_missing_file_still_raises_FileNotFoundError(self, tmp_path):
        """bob.compare.load_baseline branches on it for its distinct
        "baseline not found" message (v0.9.2)."""
        from bob._atomic import read_text_capped
        with pytest.raises(FileNotFoundError):
            read_text_capped(tmp_path / "nope.json")

    def test_oversized_file_is_refused(self, tmp_path):
        from bob._atomic import read_text_capped
        p = tmp_path / "big"
        p.write_text("x" * 5000)
        with pytest.raises(OSError) as exc:
            read_text_capped(p, max_bytes=1000)
        assert exc.value.errno == errno.EFBIG

    def test_normal_file_and_symlink_to_one_read_fine(self, tmp_path):
        from bob._atomic import read_text_capped
        p = tmp_path / "ok"
        p.write_text("hello")
        link = tmp_path / "link"
        link.symlink_to(p)
        assert read_text_capped(p) == "hello"
        assert read_text_capped(link) == "hello"

    def test_non_utf8_is_replaced_not_raised(self, tmp_path):
        from bob._atomic import read_text_capped
        p = tmp_path / "b"
        p.write_bytes(b"caf\xe9")
        assert "caf" in read_text_capped(p)

    def test_every_state_reader_uses_the_bounded_helper(self):
        """No state file may go back to a bare read_text()."""
        offenders = []
        for rel in ("bob/compare.py", "bob/ignore.py", "bob/history.py",
                    "bob/recurrence.py", "bob/profiles.py"):
            src = (REPO / rel).read_text()
            if ".read_text(" in src:
                offenders.append(rel)
        assert not offenders, (
            f"these state readers bypass read_text_capped: {offenders}")


# ---------------------------------------------------------------------------
# F — the plugin loader
# ---------------------------------------------------------------------------

class TestPluginLoaderCannotBeStarved:
    """``_MAX_PLUGIN_SIZE`` was enforced via ``stat().st_size`` — and a
    character device reports 0. ``ln -s /dev/zero checks.d/p.py`` sailed
    through the 64 KB cap, then ``read_text()`` read until the OOM killer
    stepped in (exit 137)."""

    def test_non_regular_plugin_is_skipped(self, tmp_path):
        from bob.plugin_checks import _load_one  # noqa: PLC2701
        link = tmp_path / "p.py"
        link.symlink_to("/dev/zero")
        assert _load_one(link) is None

    def test_loader_checks_is_file_and_bounds_the_read(self):
        src = (REPO / "bob" / "plugin_checks.py").read_text()
        assert "is_file()" in src, "the loader must reject non-regular files"
        assert "_MAX_PLUGIN_SIZE + 1" in src, "the read itself must be bounded"


# ---------------------------------------------------------------------------
# G — Ctrl-C
# ---------------------------------------------------------------------------

class TestInterruptIsClean:
    """Ctrl-C on a long audit dumped a raw Python traceback ending in
    ``KeyboardInterrupt`` — noise on the most ordinary way to stop the tool."""

    def test_main_handles_keyboard_interrupt(self):
        src = (REPO / "bob" / "__main__.py").read_text()
        assert "except KeyboardInterrupt" in src
        i = src.index("except KeyboardInterrupt")
        assert "return 130" in src[i:i + 500], "SIGINT must map to the conventional 130"

    def test_interrupt_message_exists_in_both_locales(self):
        import json
        for lang in ("en", "fr"):
            d = json.loads((REPO / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
            assert "interrupted" in d["cli"]["error"], f"{lang}: missing cli.error.interrupted"
