"""`--fix --apply` must not execute a command declared read-only.

`cmd_type` says whether a command remediates (`"fix"`) or only diagnoses. Its
own docstring: *read-only diagnostic commands that do not change state*. A
guard added in v0.13.2 validates the field at write time, rejecting anything
outside `fix`/`check`.

`run_fixes` never read it. It selected on `nature == "action"` alone, so six
findings whose command is a diagnostic were counted as automatic fixes,
executed, and reported as `✔ Applied`:

  * four SMART alerts answered with `smartctl -a` — reading a dying disk's
    counters does not repair it, and smartctl's exit code is a bit field, so
    BOB said "applied" on a healthy disk and "manual (exit 8)" on a failing
    one: the verdict tracked disk health rather than whether anything was
    fixed;
  * a full partition answered with `du`;
  * "no fail2ban jails" answered with `fail2ban-client status`.

The operator was told a failing disk had been remediated. Declared, validated
at write time, and never consumed — this project's oldest shape.

The classification of those six is unchanged and correct: a failing disk *is*
an action and `smartctl -a` *is* a diagnostic. What was wrong is that `nature`
was doing two jobs, "the operator must act" and "put it in the fix list".
Reading `cmd_type` returns the second to the field written for it.
"""

from __future__ import annotations

import ast
import io
import pathlib
import sys
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _render(findings, *, apply_=True, lang="en"):
    from bob import i18n, output
    from bob import fixes
    i18n.init(lang)
    output.init(no_color=True)
    engine = types.SimpleNamespace(findings=findings)
    config = types.SimpleNamespace(yes=True, apply=apply_, fix=True, quiet=False)
    buf, old = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        fixes.run_fixes(engine, config, i18n.t)
    finally:
        sys.stdout = old
        i18n.init("en")
    return buf.getvalue()


def _finding(cmd_type, cmd="/bin/true", message="a finding"):
    from bob.scoring import Finding, FindingLevel
    return Finding(level=FindingLevel.ALERT, message=message, key="probe.key",
                   nature="action", cmd=cmd, cmd_type=cmd_type)


class TestADiagnosticIsNeverApplied:

    def test_a_check_command_is_not_executed(self):
        """`/bin/true` would succeed; the point is that it is never run."""
        out = _render([_finding("check", message="SMART says the disk is failing")])
        assert "Applied" not in out, (
            "a read-only diagnostic was reported as an applied fix"
        )

    def test_it_is_still_shown_with_its_command(self):
        """Dropping it from the fix list must not drop it from the screen.

        `manual_items` holds findings with *no* command, so a naive exclusion
        would have removed these six from both lists. Visible but mislabelled
        was bad; invisible is worse.
        """
        out = _render([_finding("check", cmd="sudo smartctl -a /dev/sda")])
        assert "sudo smartctl -a /dev/sda" in out
        assert "the disk" in out or "a finding" in out

    def test_a_real_fix_is_still_applied(self):
        """The polarity twin: excluding diagnostics must not exclude fixes."""
        out = _render([_finding("fix")])
        assert "Applied" in out

    def test_the_two_do_not_interfere(self):
        out = _render([_finding("check", message="diagnostic only"),
                       _finding("fix", message="a real fix")])
        assert "1 of 1" in out, f"the applied count is wrong: {out}"
        assert "diagnostic only" in out

    def test_the_count_excludes_diagnostics(self):
        """"N automatic fixes available" must not count what BOB cannot do."""
        out = _render([_finding("check"), _finding("check"), _finding("fix")],
                      apply_=False)
        assert "1 automatic" in out, out

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_bucket_is_translated(self, lang):
        from bob import i18n
        out = _render([_finding("check")], apply_=False, lang=lang)
        i18n.init(lang)
        try:
            title = i18n.t("fixes.diagnostic_items_title")
        finally:
            i18n.init("en")
        assert not title.startswith("["), f"{lang}: the title is untranslated"
        assert title in out


class TestTheSixKeepTheirClassification:
    """Reclassifying would have been treating the symptom.

    `nature="improvement"` would demote a dying disk to a nice-to-have;
    `cmd_type="fix"` would declare `smartctl -a` a remediation, which is the
    claim being removed. Both fields are right; the consumer was not.
    """

    _EXPECTED = {
        "disk.smart_failed", "disk.reallocated_sectors", "disk.pending_sectors",
        "disk.uncorrectable_errors", "disk.partition_critical",
        "fail2ban.no_jails",
    }

    @staticmethod
    def _action_checks() -> "set[str]":
        found = set()
        for path in sorted((_ROOT / "bob" / "checks").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                kw = {k.arg: k.value for k in node.keywords}
                get = lambda name: (kw[name].value
                                    if name in kw and isinstance(kw[name], ast.Constant)
                                    else None)
                if get("nature") == "action" and get("cmd_type") == "check" and "cmd" in kw:
                    found.add(get("key") or "<dynamic>")
        return found

    def test_the_set_is_the_one_this_release_examined(self):
        """A new one appearing means a judgement call nobody has made yet."""
        assert self._action_checks() == self._EXPECTED, (
            "the set of action-with-a-diagnostic findings changed; each one is "
            "a decision about whether BOB can fix it, not a default"
        )

    def test_none_of_them_became_a_fix(self):
        from bob.scoring import Finding  # noqa: F401 — import guard only
        src = (_ROOT / "bob" / "checks" / "disk.py").read_text(encoding="utf-8")
        assert 'cmd_type="check"' in src, (
            "the SMART findings no longer declare their command diagnostic"
        )


def test_no_editor_command_can_reach_the_apply_path():
    """An interactive editor run with stdin closed and a 30 s timeout.

    None of the three `sudo nano …` commands is `nature="action"` today, so
    none reaches `auto_items` — but that is an accident of classification, not
    a design. This pins it.
    """
    offenders = []
    for path in sorted((_ROOT / "bob" / "checks").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            kw = {k.arg: k.value for k in node.keywords}
            if "cmd" not in kw:
                continue
            cmd = ast.unparse(kw["cmd"])
            if not any(ed in cmd for ed in ("nano", "vim", "vi ", "$EDITOR")):
                continue
            nature = kw.get("nature")
            nature = nature.value if isinstance(nature, ast.Constant) else None
            ctype = kw.get("cmd_type")
            ctype = ctype.value if isinstance(ctype, ast.Constant) else "fix"
            if nature == "action" and ctype == "fix":
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        f"these would launch an editor under --fix --apply, with stdin closed "
        f"and a 30-second timeout: {offenders}"
    )


class TestTheCountIsAPromiseBobCanKeep:
    """"N automatic fixes available" was announced before consent, then broken.

    Twelve findings carry shell operators — `ssh.password_auth` among them, the
    most consequential fix in the tool. They were counted, the operator was
    told "2 fix(es) will be applied automatically", and every one was refused
    at execution with "unsafe shell syntax". `0 of 2 fix(es) applied.`

    The refusal was right; its timing was not. Asking whether BOB can run a
    command belongs where the command is classified, not after the operator
    has already agreed to all of them.
    """

    _SHELL = ("sudo sysctl -w net.ipv4.conf.all.rp_filter=1 && echo x "
              "| sudo tee -a /etc/sysctl.conf")

    def test_a_command_bob_cannot_run_is_not_counted(self):
        out = _render([_finding("fix", cmd=self._SHELL)], apply_=False)
        assert "1 automatic" not in out, "counted a fix BOB refuses to run"

    def test_it_is_shown_with_its_command_instead(self):
        out = _render([_finding("fix", cmd=self._SHELL)], apply_=False)
        assert "sysctl" in out, "the command vanished from the screen"

    def test_apply_no_longer_promises_then_refuses(self):
        out = _render([_finding("fix", cmd=self._SHELL)])
        assert "will be applied automatically" not in out, (
            "BOB still announces it will apply a command it then refuses"
        )
        assert "0 of" not in out, out

    def test_a_runnable_fix_is_still_counted_and_applied(self):
        """Polarity twin — the point is not to stop applying fixes."""
        out = _render([_finding("fix", cmd="/bin/true")])
        assert "Applied" in out and "1 of 1" in out

    @pytest.mark.parametrize("cmd,runnable", [
        ("sudo ufw enable", True),
        ("sudo chmod 600 /etc/shadow", True),
        ("sudo systemctl enable --now fail2ban", True),
        ("sudo sed -i 's/a/b/' /etc/ssh/sshd_config", True),
        ("sudo sysctl -w a=1 && echo x | sudo tee -a /etc/sysctl.conf", False),
        ("du -x -h /var 2>/dev/null | sort -rh", False),
        ("sudo nano /etc/default/ufw", False),
        ("sudo /usr/bin/nano /etc/fstab", False),
        ("sudo vim /etc/fstab", False),
    ])
    def test_the_predicate(self, cmd, runnable):
        from bob.fixes import _can_apply_unattended
        assert _can_apply_unattended(cmd) is runnable, cmd

    def test_an_editor_is_refused_by_the_predicate_not_by_luck(self):
        """Three findings offer `sudo nano …`; none is nature=action today.

        That is an accident of classification, and the apply path runs commands
        with stdin closed on a 30-second timeout — an editor would hang there
        until killed. The predicate makes it structural.
        """
        from bob.fixes import _can_apply_unattended
        assert not _can_apply_unattended("sudo nano /etc/fail2ban/jail.local")


class TestTheHeaderDoesNotSayZeroOverAnUrgentList:
    """"0 automatic fix(es) available" reads as "nothing to do" to a skimmer."""

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_it_says_what_is_true_instead(self, lang):
        out = _render([_finding("check", cmd="sudo smartctl -a /dev/sda")],
                      apply_=False, lang=lang)
        assert "0 automatic" not in out
        assert "0 correction" not in out

    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_the_box_still_closes(self, lang):
        """A longer message must not push the border out of the frame."""
        for findings in ([_finding("check", cmd="sudo smartctl -a /dev/sda")],
                         [_finding("fix", cmd="/bin/true")],
                         []):
            out = _render(findings, apply_=False, lang=lang)
            widths = {len(line) for line in out.splitlines() if line.startswith("║")}
            assert len(widths) <= 1, f"{lang}: ragged box {sorted(widths)}"
