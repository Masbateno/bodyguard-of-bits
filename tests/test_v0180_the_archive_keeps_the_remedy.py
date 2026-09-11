"""The archived .log kept the accusation and threw away the remedy.

``-d`` is documented as the *detailed report*, and README_TECH promises
"findings, and recommendations". What it held was one line per finding:
a timestamp, a level and a message. The terminal that produced it had
printed the explanation and the command; none of that reached the file.

Measured before the fix, on the same run:

    screen:  ✖ [ALERT] /usr/local/bin/oddbin is SUID root and belongs to no package
                 → A SUID binary no package ships is the shape a left-behind…
                 → sudo chmod u-s /usr/local/bin/oddbin

    .log:    2026-09-11 00:07:56 [ALERT] /usr/local/bin/oddbin is SUID root…

``write_finding`` had accepted a ``detail`` argument since the file was
written; no caller had ever passed it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob import i18n, output
from bob.display import display_result
from bob.report import AuditReport
from bob.scoring import CheckResult, Finding, FindingLevel


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")
    output.init(no_color=True, quiet=False)


def _alert() -> Finding:
    return Finding(
        level=FindingLevel.ALERT,
        message="/usr/local/bin/oddbin is SUID root and belongs to no package",
        detail="A SUID binary no package ships is the shape an escalation takes.",
        cmd="sudo chmod u-s /usr/local/bin/oddbin",
        key="suid_audit.unowned_suid",
        nature="action",
    )


def _write(tmp_path: Path, *findings: Finding, quiet: bool = False) -> str:
    report = AuditReport.open(tmp_path, "0.18.0")
    result = CheckResult()
    result.findings.extend(findings)
    display_result(result, report, False)
    report.close()
    return sorted(tmp_path.glob("*.log"))[0].read_text(encoding="utf-8")


def test_the_log_carries_the_command_it_showed_on_screen(tmp_path):
    log = _write(tmp_path, _alert())
    assert "sudo chmod u-s /usr/local/bin/oddbin" in log, (
        "the archive names the problem and not the fix"
    )


def test_the_log_carries_the_explanation(tmp_path):
    log = _write(tmp_path, _alert())
    assert "shape an escalation takes" in log


def test_the_log_names_the_finding(tmp_path):
    """Identity, not prose: a message is translated and gets reworded."""
    log = _write(tmp_path, _alert())
    assert "suid_audit.unowned_suid" in log


def test_a_check_command_is_not_marked_as_a_fix(tmp_path):
    """``cmd_type`` survives the trip: → applies a change, ? only looks."""
    log = _write(tmp_path, Finding(
        level=FindingLevel.WARN, message="sshd is started under OpenRC",
        cmd="rc-service sshd status", cmd_type="check",
        key="services.exposed.ssh"))
    assert "? rc-service sshd status" in log
    assert "→ rc-service sshd status" not in log


def test_quiet_silences_the_screen_and_not_the_archive(tmp_path, capsys):
    """``-q -d`` is how a cron job asks for a file and no output."""
    report = AuditReport.open(tmp_path, "0.18.0")
    result = CheckResult()
    result.findings.append(_alert())
    display_result(result, report, False, quiet=True)
    report.close()
    log = sorted(tmp_path.glob("*.log"))[0].read_text(encoding="utf-8")

    assert capsys.readouterr().out.strip() == "", "quiet still printed"
    assert "sudo chmod u-s /usr/local/bin/oddbin" in log, (
        "a file stripped of its remediation is the one nobody can act on later"
    )
    assert "suid_audit.unowned_suid" in log


def test_a_finding_with_no_body_adds_no_empty_lines(tmp_path):
    """The mirror: nothing to add, nothing added."""
    log = _write(tmp_path, Finding(
        level=FindingLevel.OK, message="Everything checks out", key=""))
    body = [ln for ln in log.splitlines() if ln.startswith("    ")]
    assert body == [], f"empty body lines written: {body!r}"
