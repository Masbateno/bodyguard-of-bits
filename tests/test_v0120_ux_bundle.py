"""v0.12.0 UX bundle — F2 (severity presentation), F4 (explain), F6 (root gate).

(F1 score model lives in test_v0120_score_model.py; F9 JSON naming in
test_v0120_json_schema.py.)
"""

from __future__ import annotations

import pytest

from bob.scoring import ScoreEngine, CheckResult, FindingLevel


# ---------------------------------------------------------------------------
# F2 — summary bullet reflects the finding's severity, matching the body
# ---------------------------------------------------------------------------


def _summary_lines(findings_spec):
    """Build an engine with (level, nature, key, msg) findings and return the
    flat joined text of the summary findings block."""
    from bob.display import _summary_findings_lines
    from bob.checks._run import _identity_t

    engine = ScoreEngine()
    result = CheckResult()
    for level, nature, key, msg in findings_spec:
        if level == FindingLevel.ALERT:
            result.alert_with_deduction(key=key, message=msg, points=1, nature=nature)
        else:
            result.warn_with_deduction(key=key, message=msg, points=1, nature=nature)
    engine.apply(result)
    engine.finalize()
    lines = _summary_findings_lines(engine, _identity_t, 78)
    return "\n".join(f"{c}" for c, _ in lines)


class TestF2SeverityBullet:
    def test_warn_action_item_uses_warn_bullet(self):
        """A WARN-severity 'action' finding shows ⚠ in the summary (matching
        its ⚠ body line), not ✖ — even though it sits under 'Action required'."""
        text = _summary_lines([(FindingLevel.WARN, "action", "firmware.fwupd_updates", "WARNFIND")])
        # the item line carries ⚠, not ✖
        item_line = next(l for l in text.splitlines() if "WARNFIND" in l)
        assert "⚠" in item_line
        assert "✖" not in item_line

    def test_alert_action_item_uses_alert_bullet(self):
        text = _summary_lines([(FindingLevel.ALERT, "action", "ssh.permit_root_login", "ALERTFIND")])
        item_line = next(l for l in text.splitlines() if "ALERTFIND" in l)
        assert "✖" in item_line

    def test_action_section_header_still_present(self):
        """The section header still groups by nature — the ✖ header stays as
        the section marker even when the items under it are WARN (⚠)."""
        text = _summary_lines([(FindingLevel.WARN, "action", "firmware.fwupd_updates", "WF")])
        assert "✖ summary.block_action" in text  # identity-t echoes the key


# ---------------------------------------------------------------------------
# F4 — `--explain <unknown>` returns non-zero + offers a fuzzy suggestion
# ---------------------------------------------------------------------------


class TestF4ExplainExitAndSuggestion:
    @pytest.fixture(autouse=True)
    def _en(self):
        from bob import i18n
        i18n.init("en")
        yield
        i18n.init("en")

    def test_run_explain_returns_true_for_valid_key(self):
        from bob.explain import run_explain
        from bob import i18n
        assert run_explain("ssh.password_auth", i18n.t) is True

    def test_run_explain_returns_true_for_list(self):
        from bob.explain import run_explain
        from bob import i18n
        assert run_explain("list", i18n.t) is True

    def test_run_explain_returns_false_for_unknown(self):
        from bob.explain import run_explain
        from bob import i18n
        assert run_explain("ssh.passwd_auth", i18n.t) is False
        assert run_explain("zzz.nothing", i18n.t) is False

    def test_typo_prints_fuzzy_suggestion(self, capsys):
        from bob.explain import run_explain
        from bob import i18n
        run_explain("ssh.passwd_auth", i18n.t)
        out = capsys.readouterr().out
        assert "Did you mean" in out
        assert "ssh.password_auth" in out

    def test_unrelated_key_prints_no_suggestion(self, capsys):
        from bob.explain import run_explain
        from bob import i18n
        run_explain("zzz.nothing", i18n.t)
        out = capsys.readouterr().out
        assert "Did you mean" not in out

    def test_main_exit_codes(self):
        from bob.__main__ import main, EXIT_OK, EXIT_ERROR
        assert main(["--explain", "ssh.password_auth"]) == EXIT_OK
        assert main(["--explain", "list"]) == EXIT_OK
        assert main(["--explain", "ssh.passwd_auth"]) == EXIT_ERROR  # typo
        assert main(["--explain", "zzz.nothing"]) == EXIT_ERROR


# ---------------------------------------------------------------------------
# F6 — --check / --skip validation runs BEFORE the root gate
# ---------------------------------------------------------------------------


class TestF6CheckValidationBeforeRoot:
    """The test process is non-root; if validation ran after the root gate,
    an all-invalid --check would demand sudo first. F6 makes the validation
    fire first, so the operator learns the token is wrong without sudo."""

    def test_all_invalid_check_reports_error_not_root(self, capsys):
        from bob.__main__ import main, EXIT_ERROR
        rc = main(["--check=nonexistent", "--offline"])
        err = capsys.readouterr().err
        assert rc == EXIT_ERROR
        # The error is about the unknown check, NOT "must be run as root".
        assert "must be run as root" not in err
        assert "check" in err.lower()

    def test_validation_precedes_root_in_source(self):
        """Static guard: validate_check_filters must appear before the audit's
        require_root() in _run() so the ordering can't silently regress."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "__main__.py").read_text(encoding="utf-8")
        # the dispatch logic lives in _run(); slice from there
        body = src[src.index("def _run("):]
        i_validate = body.index("validate_check_filters(config)")
        # the require_root() that gates the audit must come after the validate
        assert i_validate < body.index("require_root()", i_validate), (
            "validate_check_filters must run before the audit's require_root()"
        )
