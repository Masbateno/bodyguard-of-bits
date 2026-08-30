"""
v0.14.1 robustness guards — regressions found by the local stress campaign.

Every test here corresponds to a defect that was reproduced end-to-end on a
live host before the fix, and each is written to FAIL if the fix is reverted
(the campaign's first draft of the v0.14.1 guard re-implemented the logic
inside the test and passed under mutation — that mistake is not repeated:
these drive the real code paths or assert on the real source).

Covered:
  A — runner._sec fault barrier (a failing section must not lose the audit)
  B — no decode-unsafe read may reappear anywhere in bob/
  C — history.load_history skips JSON-valid non-object lines
  D — --lang shape validation (no arbitrary filesystem read)
  E — report files are opened O_NOFOLLOW
  F — CSV formula injection is neutralised
  G — CLI dash guards on -p / --check / --skip
  H — domain_scores intentional-catch-all list stays truthful
"""

from __future__ import annotations

import ast
import json
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# A — the fault barrier in runner._sec
# ---------------------------------------------------------------------------

class TestSectionFaultBarrier:
    """``_sec`` must degrade a failing section, never abort the audit.

    Pre-v0.14.1 ``_sec`` had no exception handling: one check raising cost the
    operator the ENTIRE audit (exit 3, zero bytes of stdout). Reproduced live
    with a single latin-1 byte in an /etc/passwd GECOS field.

    ``run_checks`` is deliberately not exercised in the pytest layer (see the
    module docstring of tests/test_runner.py — it belongs to the integration
    matrix), so this is a structural guard on the real source: it fails if the
    try/except is removed or stops routing to ``_degrade_section``.
    """

    @staticmethod
    def _sec_node() -> ast.FunctionDef:
        tree = ast.parse((REPO / "bob" / "runner.py").read_text())
        run_checks = next(n for n in ast.walk(tree)
                          if isinstance(n, ast.FunctionDef) and n.name == "run_checks")
        return next(n for n in ast.walk(run_checks)
                    if isinstance(n, ast.FunctionDef) and n.name == "_sec")

    def test_sec_body_is_wrapped_in_a_try(self):
        sec = self._sec_node()
        assert any(isinstance(n, ast.Try) for n in sec.body), (
            "runner._sec must wrap the snapshot/check/apply sequence in a try — "
            "without it one failing check aborts the whole audit"
        )

    def test_barrier_catches_exception_and_degrades(self):
        sec = self._sec_node()
        try_node = next(n for n in sec.body if isinstance(n, ast.Try))
        names = {h.type.id for h in try_node.handlers
                 if isinstance(h.type, ast.Name)}
        assert "Exception" in names, "the barrier must catch Exception, not a narrow subset"
        called = {n.func.id for n in ast.walk(try_node)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "_degrade_section" in called, (
            "the handler must route to _degrade_section so the failure is "
            "reported as a finding and recorded in degraded_sections"
        )

    def test_check_and_snapshot_both_run_inside_the_barrier(self):
        """The snapshot factory must be invoked INSIDE the try.

        The barrier was initially ineffective because 29 call sites collected
        their snapshot eagerly, one line above the ``_sec`` call — outside the
        try, and snapshot collection is exactly where the file reads happen.
        """
        sec = self._sec_node()
        try_node = next(n for n in sec.body if isinstance(n, ast.Try))
        body_src = ast.dump(ast.Module(body=try_node.body, type_ignores=[]))
        assert "check_fn" in body_src, "check_fn must be called inside the barrier"
        assert "snapshot" in body_src, "the snapshot factory must be invoked inside the barrier"

    def test_no_sec_call_site_collects_its_snapshot_eagerly(self):
        """Every ``_sec`` call must pass a factory, not a pre-built snapshot.

        ``hardening_snapshot`` is the one documented exception — it also feeds
        ``ChecksResult`` for the --json-full sysctl block, so it stays eager.
        """
        import re
        src = (REPO / "bob" / "runner.py").read_text().splitlines()
        offenders = []
        for line in src:
            m = re.match(r'\s*_sec\(\s*"([a-z_]+)",\s*([a-z_]\w*)\s*[,)]', line)
            if not m:
                continue
            section, var = m.group(1), m.group(2)
            if var == "hardening_snapshot":
                continue
            # a bare local name assigned from *.from_system() above = eager
            if any(re.match(rf'\s*{re.escape(var)}\s*=.*from_system\(', x) for x in src):
                offenders.append((section, var))
        assert not offenders, (
            f"these sections collect their snapshot outside the fault barrier: {offenders}"
        )

    def test_checks_result_exposes_degraded_sections(self):
        from bob.runner import ChecksResult
        assert "degraded_sections" in ChecksResult._fields
        assert ChecksResult._field_defaults["degraded_sections"] == ()

    def test_degraded_sections_is_a_declared_v3_schema_key(self):
        from bob.json_output import SCHEMA_V3_REQUIRED_KEYS
        assert "degraded_sections" in SCHEMA_V3_REQUIRED_KEYS

    def test_json_builder_emits_degraded_sections(self):
        import inspect

        from bob.json_output import build_json_data
        assert "degraded_sections" in inspect.signature(build_json_data).parameters

    def test_locale_key_exists_in_both_languages(self):
        for lang in ("en", "fr"):
            data = json.loads((REPO / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))
            assert "section_unavailable" in data["audit"], f"{lang}: missing audit.section_unavailable"
            assert "{section}" in data["audit"]["section_unavailable"]


# ---------------------------------------------------------------------------
# B — decode safety across the whole package
# ---------------------------------------------------------------------------

class TestNoDecodeUnsafeReads:
    """No text read may raise UnicodeDecodeError past an OSError-only guard.

    ``UnicodeDecodeError`` is a ValueError, not an OSError, so it sailed
    through 33 ``except OSError`` guards. Proven fatal twice: a latin-1 GECOS
    field in /etc/passwd, and an accented comment in ~/.config/bob/ignore.yml
    written by a latin-1 editor (which bricked EVERY run for that user).
    """

    def test_every_guarded_read_declares_an_errors_policy(self):
        offenders = []
        for path in sorted((REPO / "bob").rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                handled = set()
                for h in node.handlers:
                    if isinstance(h.type, ast.Name):
                        handled.add(h.type.id)
                    elif isinstance(h.type, ast.Tuple):
                        handled.update(e.id for e in h.type.elts if isinstance(e, ast.Name))
                    elif h.type is None:
                        handled.add("*BARE*")
                if not handled:
                    continue
                if handled & {"UnicodeDecodeError", "UnicodeError", "ValueError",
                              "Exception", "BaseException", "*BARE*"}:
                    continue
                for n in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if (isinstance(n, ast.Call)
                            and isinstance(n.func, ast.Attribute)
                            and n.func.attr == "read_text"
                            and "errors" not in {k.arg for k in n.keywords}):
                        offenders.append(f"{path.relative_to(REPO)}:{n.lineno}")
        assert not offenders, (
            "read_text() without errors= inside an OSError-only try — a "
            "non-UTF-8 byte will escape as UnicodeDecodeError:\n  "
            + "\n  ".join(offenders)
        )

    def test_ignore_file_with_latin1_comment_does_not_raise(self):
        from bob.ignore import load_ignore_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml") as f:
            f.write(b"# r\xe8gle ignor\xe9e (latin-1)\n  - key: ssh.password_auth\n")
            p = Path(f.name)
        try:
            assert "ssh.password_auth" in load_ignore_keys(p)
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# C — history loader
# ---------------------------------------------------------------------------

class TestHistorySkipsMalformedLines:
    """A JSON-valid non-object line must be skipped, not fatal.

    ``_clamp_entry`` calls ``.get`` on whatever ``json.loads`` returned, so a
    line holding ``null`` / ``[1,2]`` / ``"str"`` raised AttributeError — which
    the loop's ``except (JSONDecodeError, ValueError)`` does not catch. The
    loop's whole purpose is to skip malformed lines.
    """

    @pytest.mark.parametrize("bad", ["null", "[1,2]", '"str"', "42", "true"])
    def test_non_object_line_is_skipped(self, bad, monkeypatch):
        import bob.history as H
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
            f.write('{"score":8,"ts":"2026-08-29T10:00:00"}\n')
            f.write(bad + "\n")
            f.write('{"score":6,"ts":"2026-08-29T11:00:00"}\n')
            p = Path(f.name)
        try:
            monkeypatch.setattr(H, "_HISTORY_FILE", p)
            entries = H.load_history()
            assert [e["score"] for e in entries] == [8, 6]
        finally:
            p.unlink()

    def test_non_utf8_history_does_not_raise(self, monkeypatch):
        import bob.history as H
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as f:
            f.write(b'{"score":8,"ts":"x"}\n\xff\xfe bad\n')
            p = Path(f.name)
        try:
            monkeypatch.setattr(H, "_HISTORY_FILE", p)
            assert [e["score"] for e in H.load_history()] == [8]
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# D — --lang shape validation
# ---------------------------------------------------------------------------

class TestLangValidation:
    """``--lang`` fed i18n.init(), which builds ``_LOCALES_DIR / f"{lang}.json"``.

    pathlib replaces the base when the right-hand side is absolute, so
    ``--lang=/tmp/x`` loaded /tmp/x.json as the translation table — an
    unvalidated argument reaching an arbitrary filesystem read, as root under
    sudo.
    """

    @pytest.mark.parametrize("bad", [
        "/tmp/evil", "../../etc/passwd", "en/../../x", "a" * 300,
        "en.json", "e n", "/etc/shadow",
    ])
    def test_path_shaped_values_are_rejected(self, bad):
        from bob.cli import CLIError, parse_args
        with pytest.raises(CLIError):
            parse_args([f"--lang={bad}"])
        with pytest.raises(CLIError):
            parse_args(["--lang", bad])

    @pytest.mark.parametrize("good", ["en", "fr", "de", "pt_BR", "en-GB"])
    def test_well_formed_codes_still_accepted(self, good):
        """An unknown but well-formed code must still fall back gracefully."""
        from bob.cli import parse_args
        assert parse_args([f"--lang={good}"]).lang == good

    def test_absolute_path_cannot_reach_the_locale_loader(self):
        """End-to-end: the CLI must never hand i18n a path outside locales/."""
        from bob.cli import CLIError, parse_args
        with tempfile.TemporaryDirectory() as d:
            evil = Path(d) / "evil.json"
            evil.write_text('{"audit": {"starting": "PWNED"}}')
            with pytest.raises(CLIError):
                parse_args([f"--lang={evil.with_suffix('')}"])


# ---------------------------------------------------------------------------
# E — report file creation
# ---------------------------------------------------------------------------

class TestReportOpenIsSymlinkSafe:
    """The report name is fully predictable and the open runs as root.

    ``bob_%Y%m%d_%H%M%S.log`` + O_CREAT|O_TRUNC without O_NOFOLLOW meant anyone
    able to write in the target directory (reachable via ``--output-dir``)
    could pre-plant a symlink and have root truncate an arbitrary file.
    """

    def test_open_uses_o_nofollow(self):
        src = (REPO / "bob" / "report.py").read_text()
        assert "O_NOFOLLOW" in src, "report open must set O_NOFOLLOW"

    def test_symlinked_report_path_is_refused(self):
        from bob.report import AuditReport
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "victim"
            target.write_text("precious")
            link = Path(d) / "bob_20260829_120000.log"
            link.symlink_to(target)
            with pytest.raises(OSError):
                AuditReport(path=link)
            assert target.read_text() == "precious", "root must not truncate the symlink target"

    def test_fd_based_chown_helper_exists(self):
        from bob.sysinfo import chown_fd_to_sudo_user
        assert callable(chown_fd_to_sudo_user)


# ---------------------------------------------------------------------------
# F — CSV formula injection
# ---------------------------------------------------------------------------

class TestCsvFormulaInjection:
    """csv.DictWriter quotes per RFC 4180, but a spreadsheet still evaluates a
    quoted field starting with = + - @ — so report content that merely passed
    through BOB (a cron command line, a container name) could execute."""

    # Only the printable formula leaders belong here. A control character can
    # no longer reach _csv_safe at all — Finding.__post_init__ strips it — and
    # prefixing "'" to a value that still held a bare CR produced a field the
    # csv module itself refuses to read back on Python 3.10. See
    # test_control_chars_never_reach_the_csv below.
    @pytest.mark.parametrize("payload", [
        '=cmd|"/C calc"!A1', "+1234", "-1+1", "@SUM(1+1)",
    ])
    def test_leading_formula_chars_are_neutralised(self, payload):
        import inspect

        from bob.csv_output import build_csv_output
        from bob.report import SystemInfo
        from bob.scoring import Finding, FindingLevel, ScoreEngine

        engine = ScoreEngine()
        engine.findings.append(Finding(level=FindingLevel.WARN, key="cron.risky",
                                       message=payload, detail=payload,
                                       cmd=payload, note=payload))
        params = inspect.signature(SystemInfo).parameters
        si = SystemInfo(**{k: ("x" if v.default is inspect._empty else v.default)
                           for k, v in params.items()})
        import csv as _csv
        import io
        rows = list(_csv.DictReader(io.StringIO(build_csv_output(engine, si))))
        for col in ("message", "detail", "fix_cmd", "note"):
            assert rows[0][col].startswith("'"), f"{col} not neutralised"
            assert rows[0][col][1:] == payload, f"{col} value not preserved verbatim"

    def test_control_chars_never_reach_the_csv(self):
        """A CR in a field would make the export unreadable by csv itself.

        Reproduced on CI (Python 3.10): a value neutralised to "'\rlead" is
        written unquoted, and csv.DictReader then raises "new-line character
        seen in unquoted field". The fix is upstream — the character is gone
        before the writer sees it — so this pins the round-trip, not the prefix.
        """
        import csv as _csv
        import inspect
        import io

        from bob.csv_output import build_csv_output
        from bob.report import SystemInfo
        from bob.scoring import Finding, FindingLevel, ScoreEngine

        engine = ScoreEngine()
        for payload in ("\rlead", "\tlead", "a\rb", "x\x00y"):
            engine.findings.append(Finding(level=FindingLevel.WARN, key="cron.risky",
                                           message=payload, detail=payload,
                                           cmd=payload, note=payload))
        params = inspect.signature(SystemInfo).parameters
        si = SystemInfo(**{k: ("x" if v.default is inspect._empty else v.default)
                           for k, v in params.items()})
        out = build_csv_output(engine, si)
        rows = list(_csv.DictReader(io.StringIO(out)))   # must not raise
        assert len(rows) == 4
        for r in rows:
            for col in ("message", "detail", "fix_cmd", "note"):
                assert "\r" not in r[col] and "\t" not in r[col] and "\x00" not in r[col]

    def test_plugin_supplied_text_is_sanitised(self):
        """The v0.14.1 claim was "one choke point for every format". It was not.

        ``bob/_sandbox.py`` rebuilds a Finding directly from the JSON a plugin
        returned — the least trustworthy strings in the program — and so
        bypassed the sanitisation that lived in ``add_finding``. Moving it to
        ``Finding.__post_init__`` is what makes the claim true.
        """
        from bob.scoring import Finding, FindingLevel

        hostile = "\x1b]0;HIJACK\x07evil\r\x1b[2J"
        f = Finding(level=FindingLevel.WARN, message=hostile, detail=hostile,
                    note=hostile, cmd="line1\n" + hostile, key="plugin.x")
        for field in (f.message, f.detail, f.note):
            assert all(ord(c) >= 32 and ord(c) != 127 for c in field), field
        assert "\n" in f.cmd, "cmd must keep its newlines"
        assert "\x1b" not in f.cmd and "\r" not in f.cmd

    def test_sanitisation_lives_in_the_dataclass_not_the_helper(self):
        """Guard the fix's location: add_finding is not the only constructor."""
        import ast
        src = (REPO / "bob" / "scoring.py").read_text()
        tree = ast.parse(src)
        finding = next(n for n in ast.walk(tree)
                       if isinstance(n, ast.ClassDef) and n.name == "Finding")
        assert any(isinstance(n, ast.FunctionDef) and n.name == "__post_init__"
                   for n in finding.body), (
            "Finding must sanitise in __post_init__ — bob/_sandbox.py builds "
            "Finding() directly from plugin-supplied JSON and would otherwise "
            "bypass it")

    def test_benign_text_is_untouched(self):
        from bob.csv_output import _csv_safe
        for benign in ["ssh.password_auth", "UFW is inactive", "", "0 findings"]:
            assert _csv_safe(benign) == benign


# ---------------------------------------------------------------------------
# G — CLI dash guards
# ---------------------------------------------------------------------------

class TestValueOptionsRejectFlags:
    """The M-4 (v0.7.3) dash guard was never applied to -p / --check / --skip,
    so ``bob --skip --quiet`` silently swallowed --quiet."""

    @pytest.mark.parametrize("opt", ["-p", "--profile", "--check", "--skip"])
    @pytest.mark.parametrize("flag", ["--quiet", "-q", "--json"])
    def test_a_following_flag_is_not_taken_as_the_value(self, opt, flag):
        from bob.cli import CLIError, parse_args
        with pytest.raises(CLIError):
            parse_args([opt, flag])

    @pytest.mark.parametrize("opt", ["-p", "--profile", "--check", "--skip"])
    def test_empty_value_is_rejected(self, opt):
        from bob.cli import CLIError, parse_args
        with pytest.raises(CLIError):
            parse_args([opt, ""])

    @pytest.mark.parametrize("opt", ["--check", "--skip"])
    @pytest.mark.parametrize("value", [",", ",,,", "  ,  "])
    def test_separator_only_value_never_means_no_filter(self, opt, value):
        """``--check ,`` used to yield an empty (falsy) frozenset, silently
        running the FULL audit while ``--check=`` raised."""
        from bob.cli import CLIError, parse_args
        with pytest.raises(CLIError):
            parse_args([opt, value])
        with pytest.raises(CLIError):
            parse_args([f"{opt}={value}"])


# ---------------------------------------------------------------------------
# H — domain_scores catch-all bookkeeping
# ---------------------------------------------------------------------------

class TestIntentionalCatchallStaysTruthful:
    """Silencing the unmapped-prefix debug log must not silence a real drift."""

    def test_no_listed_prefix_is_actually_mapped(self):
        from bob.domain_scores import _INTENTIONAL_CATCHALL, _PREFIX_TO_DOMAIN
        overlap = _INTENTIONAL_CATCHALL & set(_PREFIX_TO_DOMAIN)
        assert not overlap, (
            f"these prefixes ARE mapped, remove them from the catch-all list: {overlap}"
        )

    def test_listed_prefixes_still_resolve_to_firewall(self):
        from bob.domain_scores import _INTENTIONAL_CATCHALL, key_to_domain
        for prefix in _INTENTIONAL_CATCHALL:
            assert key_to_domain(f"{prefix}.anything") == "firewall"

    def test_an_unknown_prefix_still_logs(self, caplog):
        import logging

        from bob.domain_scores import key_to_domain
        with caplog.at_level(logging.DEBUG, logger="bob.domain_scores"):
            key_to_domain("brand_new_check.some_finding")
        assert any("has no entry" in r.message for r in caplog.records), (
            "a genuinely unmapped prefix must still be logged"
        )
