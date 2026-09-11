"""--fix applies only the fixes of the sections --check selected.

Measured on the Raspberry Pi Zero W: `bob --check=raspberry_pi --fix --apply
--yes` also ran `apt install -y ufw`. UFW comes from the firewall section,
which is always-on — it runs and displays for context under any --check — but
its fix should not be applied when the operator narrowed the run to
raspberry_pi.

Findings now carry the section that produced them (stamped by
ScoreEngine.apply), and run_fixes filters by --check with the same prefix
rule --check uses elsewhere.
"""

from __future__ import annotations

import types

import pytest

from bob import i18n
from bob.scoring import CheckResult, Finding, FindingLevel, ScoreEngine


@pytest.fixture(autouse=True)
def _english():
    i18n.init("en")


# ---------------------------------------------------------------------------
# The stamp
# ---------------------------------------------------------------------------

def test_apply_stamps_the_section_on_each_finding():
    engine = ScoreEngine()
    result = CheckResult()
    result.add_finding(level=FindingLevel.WARN, message="UFW is not installed",
                       key="prerequisites.ufw_missing", nature="action",
                       cmd="sudo apt install -y ufw")
    engine.apply(result, section="firewall")
    assert engine.findings[-1].section == "firewall"


def test_a_finding_that_already_names_a_section_keeps_it():
    engine = ScoreEngine()
    f = Finding(level=FindingLevel.INFO, message="x", key="a.b", section="preset")
    r = CheckResult()
    r.findings.append(f)
    engine.apply(r, section="override")
    assert engine.findings[-1].section == "preset"


# ---------------------------------------------------------------------------
# The filter — run_fixes under --check
# ---------------------------------------------------------------------------

def _engine_with_two_sections():
    engine = ScoreEngine()
    fw = CheckResult()
    fw.add_finding(level=FindingLevel.WARN, message="UFW is not installed",
                   key="prerequisites.ufw_missing", nature="action",
                   cmd="sudo apt install -y ufw")
    engine.apply(fw, section="firewall")
    pi = CheckResult()
    pi.add_finding(level=FindingLevel.WARN, message="cloud-init seed holds a hash",
                   key="raspberry_pi.seed_password", nature="action",
                   cmd="sudo sed -i '/passwd/d' /boot/firmware/user-data")
    engine.apply(pi, section="raspberry_pi")
    return engine


def _preview(engine, check_only, capsys):
    """Drive run_fixes in preview mode (no --apply) and return its stdout."""
    from bob.fixes import run_fixes
    config = types.SimpleNamespace(
        check_only=frozenset(check_only), apply=False, assume_yes=False,
        yes=False, quiet=False, no_color=True,
    )
    run_fixes(engine, config, i18n.t)
    return capsys.readouterr().out


def test_check_raspberry_pi_excludes_the_firewall_fix(capsys):
    out = _preview(_engine_with_two_sections(), ["raspberry_pi"], capsys)
    assert "user-data" in out, "the selected raspberry_pi fix is shown"
    assert "ufw" not in out, (
        "the always-on firewall fix must not appear under --check=raspberry_pi"
    )


def test_check_firewall_includes_the_firewall_fix(capsys):
    """The mirror: selecting firewall shows its fix, even though the finding
    key is prerequisites.* not firewall.* — matching is on section."""
    out = _preview(_engine_with_two_sections(), ["firewall"], capsys)
    assert "ufw" in out
    assert "user-data" not in out


def test_no_check_filter_shows_everything(capsys):
    out = _preview(_engine_with_two_sections(), [], capsys)
    assert "ufw" in out and "user-data" in out


def test_run_fixes_preview_counts_only_selected_section(capsys):
    from bob.fixes import run_fixes
    engine = _engine_with_two_sections()
    config = types.SimpleNamespace(
        check_only=frozenset(["raspberry_pi"]), apply=False, assume_yes=False,
        yes=False, quiet=False, no_color=True,
    )
    run_fixes(engine, config, i18n.t)
    out = capsys.readouterr().out
    assert "ufw" not in out, "the firewall fix leaked into a raspberry_pi-scoped run"
    assert "user-data" in out or "seed" in out.lower()
