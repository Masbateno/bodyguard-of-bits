"""BOB's verdicts were portable; the remedies attached to them were not.

v0.15.2 taught the package *query* to ask five managers instead of dpkg alone,
because a dpkg-only question reported every service absent on four
distributions out of five. The advice half of that lesson went unlearned:
eighteen findings told the operator to run ``sudo apt install …`` whatever host
they were on, so BOB was right about the problem and wrong about the fix.

The names were **measured in containers**, not recalled, and the recalled
version was wrong in three places (2026-09-08 — ``fedora:latest``,
``archlinux:latest``, ``alpine:latest``):

===================  =================  ====================  ==============
BOB wants            Debian             Fedora                Arch
===================  =================  ====================  ==============
auditd               auditd             **audit**             **audit**
libpam-pwquality     libpam-pwquality   **libpwquality**      **libpwquality**
borgbackup           borgbackup         borgbackup            **borg**
aide                 aide               aide                  **absent**
intel microcode      intel-microcode    **microcode_ctl**     **intel-ucode**
===================  =================  ====================  ==============

The last row is not advice. ``rpm -q intel-microcode`` answers nothing on
Fedora, and the firmware check turned that into *"no microcode package
installed"* with a one-point deduction — a false verdict on every host of two
distribution families, while the query helper's own docstring had named
``microcode_ctl`` since v0.15.2.

So a synthesised command is worse than none: a specific, confident instruction
that installs nothing, which the operator has no reason to doubt. Where the
name is unknown BOB says what it is looking for and admits the gap.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from bob import i18n
from bob.checks._run import (
    _INSTALL_MANAGERS,
    _MANAGER_ALIASES,
    _PACKAGE_NAMES,
    install_advice,
    install_command,
    install_fix,
    package_name,
    package_name_candidates,
)

_ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestTheMeasuredNamesAreTheOnesUsed:
    """The three differences a recalled table got wrong."""

    @pytest.mark.parametrize("logical,manager,expected", [
        ("auditd",    "dnf",    "audit"),
        ("auditd",    "pacman", "audit"),
        ("auditd",    "apk",    "audit"),
        ("auditd",    "apt",    "auditd"),
        ("pwquality", "dnf",    "libpwquality"),
        ("pwquality", "apt",    "libpam-pwquality"),
        ("borgbackup", "pacman", "borg"),
        ("clamav-daemon", "dnf", "clamd"),
        ("microcode-intel", "dnf",    "microcode_ctl"),
        ("microcode-intel", "pacman", "intel-ucode"),
        ("microcode-amd",   "pacman", "amd-ucode"),
    ])
    def test_name(self, logical, manager, expected):
        assert package_name(logical, manager) == expected

    @pytest.mark.parametrize("logical,manager", [
        ("aide",    "pacman"),   # not in Arch's repositories at all
        ("apparmor", "dnf"),     # Fedora ships SELinux
        ("iptables", "dnf"),     # iptables-nft vs -legacy is a decision
        ("auto-updates", "dnf"), # dnf-automatic, and its name moved with dnf5
        ("rkhunter", "apk"),
    ])
    def test_the_gaps_are_declared_as_gaps(self, logical, manager):
        assert package_name(logical, manager) is None

    def test_yum_and_apt_get_inherit_rather_than_duplicate(self):
        assert _MANAGER_ALIASES == {"yum": "dnf", "apt-get": "apt"}
        assert package_name("auditd", "yum") == package_name("auditd", "dnf")
        assert package_name("auditd", "apt-get") == package_name("auditd", "apt")


class TestUnknownNamesProduceNoCommand:
    """None is a verdict here, not a failure."""

    @pytest.mark.parametrize("logical,manager", [
        ("aide", "pacman"), ("apparmor", "dnf"), ("iptables", "dnf"),
        ("auto-updates", "pacman"), ("auditd", "zypper"),
    ])
    def test_no_command_is_invented(self, logical, manager):
        assert install_command(logical, manager=manager) is None

    def test_a_partly_known_group_yields_nothing(self):
        # auditd is `audit` on Alpine but audispd-plugins is absent there.
        # Installing half of what the finding asks for is not the fix.
        assert package_name("auditd", "apk") == "audit"
        assert package_name("audit-plugins", "apk") is None
        assert install_command("auditd", "audit-plugins", manager="apk") is None

    def test_no_manager_at_all_yields_nothing(self):
        assert install_command("fail2ban", manager="") is None

    def test_a_command_never_comes_back_with_an_empty_package_list(self):
        for logical in _PACKAGE_NAMES:
            for manager, _template in _INSTALL_MANAGERS:
                cmd = install_command(logical, manager=manager)
                if cmd is None:
                    continue
                head = cmd.split()
                assert head[-1] not in ("install", "add", "-S", "--noconfirm",
                                        "--no-interactive", "-y"), (
                    f"{logical}/{manager} rendered an argument-less command: {cmd!r}"
                )

    @pytest.mark.parametrize("lang", ("en", "fr"))
    def test_the_advice_names_the_debian_package_and_admits_the_gap(self, lang):
        i18n.init(lang=lang)
        text = install_advice(i18n.t, "aide", manager="pacman")
        assert not text.startswith("["), "unresolved locale key"
        assert "aide" in text
        assert "pacman" in text


class TestDebianOnlyFollowUpsDoNotTravel:
    """aideinit, pam-auth-update and dpkg-reconfigure exist only on Debian."""

    @pytest.mark.parametrize("manager", ["dnf", "pacman", "apk", "zypper"])
    def test_no_command_when_the_follow_up_cannot_run(self, manager, monkeypatch):
        monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: manager)
        cmd, detail = install_fix(i18n.t, "", "aide", then_apt="sudo aideinit")
        assert cmd is None, f"{manager} was handed Debian's aideinit"
        assert detail, "the operator was left with nothing at all"

    def test_apt_still_gets_the_whole_remedy(self, monkeypatch):
        monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: "apt")
        cmd, _detail = install_fix(i18n.t, "", "aide", then_apt="sudo aideinit")
        assert cmd == "sudo apt install -y aide && sudo aideinit"

    def test_a_portable_follow_up_does_travel(self, monkeypatch):
        monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: "pacman")
        cmd, _detail = install_fix(i18n.t, "", "apparmor",
                                   then="sudo systemctl enable --now apparmor")
        assert cmd == ("sudo pacman -S --noconfirm apparmor "
                       "&& sudo systemctl enable --now apparmor")


class TestTheMicrocodeVerdictIsNotDebianOnly:
    """The false verdict: a point deducted on two whole distribution families."""

    def test_every_measured_name_is_asked_for(self):
        for vendor, expected in (("intel", {"intel-microcode", "microcode_ctl", "intel-ucode"}),
                                 ("amd", {"amd64-microcode", "amd-ucode-firmware", "amd-ucode"})):
            assert set(package_name_candidates(f"microcode-{vendor}")) == expected

    def test_the_snapshot_asks_for_all_of_them(self):
        src = (_ROOT / "bob" / "checks" / "firmware.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "package_name_candidates"]
        assert calls, (
            "firmware.py no longer asks for every known microcode name; "
            "rpm -q intel-microcode answers nothing on Fedora"
        )

    def test_absence_is_not_asserted_without_a_known_name(self):
        from bob.checks.firmware import FirmwareSnapshot, check_firmware
        from bob.scoring import FindingLevel as FL

        snap = FirmwareSnapshot()
        snap.cpu_vendor = "intel"
        snap.microcode_installed = False
        snap.package_query_possible = True
        snap.microcode_name_known = False        # openSUSE, or anything unprobed
        result = check_firmware(snap)
        keys = {f.key for f in result.findings}
        assert "firmware.microcode_unknown" in keys
        assert "firmware.microcode_missing" not in keys
        assert not any(f.level in (FL.WARN, FL.ALERT) for f in result.findings), (
            "a point was deducted for an absence BOB never established"
        )

    def test_absence_is_still_asserted_when_the_name_is_known(self):
        from bob.checks.firmware import FirmwareSnapshot, check_firmware

        snap = FirmwareSnapshot()
        snap.cpu_vendor = "intel"
        snap.microcode_installed = False
        snap.package_query_possible = True
        snap.microcode_name_known = True
        keys = {f.key for f in check_firmware(snap).findings}
        assert "firmware.microcode_missing" in keys, (
            "the check went silent on the case it exists for"
        )


class TestNoCallSiteHardcodesDebian:
    """The sweep, held as a property rather than as a list of files."""

    def test_no_finding_carries_a_literal_package_manager_command(self):
        offenders = []
        for path in sorted((_ROOT / "bob").rglob("*.py")):
            if path.name == "_run.py":
                continue          # the table itself, checked above
            src = path.read_text(encoding="utf-8")
            tree = ast.parse(src)
            for node in ast.walk(tree):
                # An annotated assignment is how the one that got away was
                # written: `install_cmd: str = "sudo apt install …"`.
                if isinstance(node, (ast.AnnAssign, ast.Assign)):
                    value = node.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        if any(f"{m} install" in value.value or f"{m} add " in value.value
                               for m in ("apt", "apt-get", "dnf", "yum", "zypper", "apk")):
                            offenders.append(
                                f"{path.relative_to(_ROOT)}:{node.lineno}: "
                                f"{value.value[:60]}")
                    continue
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    # Not just ``cmd=``: clamav froze its command into a
                    # dataclass default named ``install_cmd`` and handed it over
                    # as ``cmd=snapshot.install_cmd``, so a guard watching the
                    # keyword alone read a variable and saw nothing. The
                    # property is about the *string*, wherever it is written.
                    if kw.arg is None or "cmd" not in kw.arg:
                        continue
                    raw = kw.value
                    if isinstance(raw, ast.JoinedStr):
                        text = "".join(p.value for p in raw.values
                                       if isinstance(p, ast.Constant))
                    elif isinstance(raw, ast.Constant) and isinstance(raw.value, str):
                        text = raw.value
                    else:
                        continue
                    if any(f"{m} install" in text or f"{m} add " in text
                           for m in ("apt", "apt-get", "dnf", "yum", "zypper", "apk")):
                        offenders.append(
                            f"{path.relative_to(_ROOT)}:{node.lineno}: {text[:60]}")
        assert not offenders, (
            "findings still name one distribution's package manager directly; "
            f"route them through install_fix: {offenders}"
        )

    def test_every_logical_name_used_is_declared(self):
        """A typo would silently raise at audit time, inside a check."""
        used = set()
        for path in sorted((_ROOT / "bob").rglob("*.py")):
            if path.name == "_run.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if getattr(node.func, "id", "") not in (
                        "install_fix", "install_command", "package_name_candidates"):
                    continue
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        used.add(arg.value)
        # install_fix takes (t, detail, *logical) — the detail is not a name.
        used = {u for u in used if u in _PACKAGE_NAMES or "." not in u}
        unknown = sorted(u for u in used if u not in _PACKAGE_NAMES)
        assert not unknown, f"logical package names with no mapping declared: {unknown}"


class TestRpmAnswersNoToAnAbsentPackage:
    """v0.15.2's fix carried the same fault, inverted, for the whole rpm family.

    ``rpm -q nosuchpackage`` prints *"package nosuchpackage is not installed"*
    on **stdout** and exits 1. The query table said ``marker=None`` for rpm,
    meaning "any output at all proves the package is installed" — so on RHEL,
    Fedora and openSUSE every query answered yes, for every name, including
    names that exist nowhere. Measured on ``fedora:latest``: v0.16.4 answered
    ``rpm`` for ``amd64-microcode``, a Debian package, and for a string invented
    on the spot.

    The failure mode is silence. A check that believes a package is present
    stops asking about it, so the services section, the DDNS clients and the
    microcode verdict were all quietly decided by a string comparison against
    an error message.
    """

    def test_rpm_is_judged_by_its_exit_code(self):
        from bob.checks._run import _PACKAGE_QUERIES
        rows = {tool: (args, marker, by_exit)
                for tool, args, marker, by_exit in _PACKAGE_QUERIES}
        args, marker, by_exit = rows["rpm"]
        assert by_exit, (
            "rpm is judged by its output again; its output on failure is a "
            "sentence, and a non-empty one"
        )
        assert "--quiet" in args, "rpm still prints the sentence"

    def test_the_managers_that_stay_silent_are_still_judged_by_output(self):
        # pacman and apk print nothing on stdout when the package is missing
        # (measured the same day). Switching them too would be churn.
        from bob.checks._run import _PACKAGE_QUERIES
        rows = {tool: by_exit for tool, _a, _m, by_exit in _PACKAGE_QUERIES}
        assert rows["pacman"] is False
        assert rows["apk"] is False
        assert rows["dpkg-query"] is False

    def test_an_error_sentence_on_stdout_is_not_an_installed_package(self, monkeypatch):
        """The behaviour, not the table: replay rpm's real answer."""
        import bob.checks._run as run_mod
        from bob.checks._run import CommandResult

        monkeypatch.setattr(run_mod, "_command_exists", lambda tool: tool == "rpm")
        monkeypatch.setattr(
            run_mod, "run_result",
            lambda *a, **k: CommandResult(
                ok=False,
                stdout="package ce-paquet-nexiste-pas is not installed\n",
                stderr="",
            ),
        )
        assert run_mod.package_installed("ce-paquet-nexiste-pas") is None, (
            "rpm's 'is not installed' sentence was read as proof of installation"
        )

    def test_a_real_rpm_success_is_still_a_yes(self, monkeypatch):
        import bob.checks._run as run_mod
        from bob.checks._run import CommandResult

        monkeypatch.setattr(run_mod, "_command_exists", lambda tool: tool == "rpm")
        monkeypatch.setattr(
            run_mod, "run_result",
            lambda *a, **k: CommandResult(ok=True, stdout="", stderr=""),
        )
        assert run_mod.package_installed("bash") == "rpm", (
            "--quiet prints nothing on success, so an output test would say no"
        )


class TestTheNoCommandBranchIsExercisedOnThisHost:
    """The suite runs on Debian, where a command is always produced.

    So the branch that matters most on every other distribution — the one where
    BOB declines to invent a command — never executed here, and a defect in it
    was invisible to a green suite. It was not hypothetical: ``Finding.cmd`` is
    typed ``str`` and sanitised unconditionally, so the first ``cmd=None``
    raised AttributeError *inside a check*, where fault isolation swallowed it
    and rendered the section "unavailable". Three checks died that way on
    Arch and Fedora containers while every test here passed.

    These force the branch by naming a manager rather than by detecting one.
    """

    @pytest.mark.parametrize("manager", ["dnf", "pacman", "apk", "zypper", ""])
    def test_every_converted_check_survives_having_no_command(self, manager, monkeypatch):
        monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: manager)
        i18n.init(lang="en")

        import importlib

        # Every module converted to the shared install layer, discovered from
        # the source rather than listed here: a check added to the layer later
        # is covered without anyone remembering to add it.
        converted = sorted({
            path.stem for path in (_ROOT / "bob" / "checks").glob("*.py")
            if "install_fix(" in path.read_text(encoding="utf-8")
            and not path.stem.startswith("_")      # _run defines it
        })
        assert len(converted) >= 10, f"the sweep found too few modules: {converted}"

        import inspect

        exercised = []
        for name in converted:
            mod = importlib.import_module(f"bob.checks.{name}")
            check_fn = next(getattr(mod, n) for n in dir(mod)
                            if n.startswith("check_") and callable(getattr(mod, n)))
            # The state object is whatever the check's first parameter is
            # annotated with — a *Snapshot for most, FirewallStatus for the
            # firewall. Read it rather than listing it, so a rename cannot make
            # this quietly cover one module fewer.
            first = next(iter(inspect.signature(check_fn).parameters.values()))
            state_cls = getattr(mod, str(first.annotation).strip("'\""), None)
            assert state_cls is not None, (
                f"{name}: cannot build the state for {check_fn.__name__}"
                f" (annotation {first.annotation!r})")
            try:
                state = state_cls()
            except TypeError:
                # FirewallStatus takes its fields positionally; "not installed"
                # is the state that reaches the install advice.
                import dataclasses
                state = state_cls(*[
                    ("" if fld.type in ("str", str) else False)
                    for fld in dataclasses.fields(state_cls)
                    if fld.default is dataclasses.MISSING
                    and fld.default_factory is dataclasses.MISSING
                ])
            result = check_fn(state, t=i18n.t)      # must not raise
            assert result.findings is not None, f"{name} produced nothing at all"
            exercised.append(name)
        assert len(exercised) == len(converted)

    def test_a_finding_may_carry_no_command(self):
        from bob.scoring import Finding, FindingLevel
        f = Finding(level=FindingLevel.INFO, message="m", cmd=None,
                    detail=None, note=None, key="k")
        assert f.cmd == "" and f.detail == "" and f.note == ""

    @pytest.mark.parametrize("manager", ["dnf", "pacman", "apk", "zypper", ""])
    def test_the_operator_is_never_left_with_nothing(self, manager, monkeypatch):
        """No command must still mean advice, not silence."""
        monkeypatch.setattr("bob.checks._run.detect_install_manager", lambda: manager)
        i18n.init(lang="en")
        cmd, detail = install_fix(i18n.t, "", "aide", then_apt="sudo aideinit")
        if cmd is None:
            assert detail.strip(), f"{manager}: no command and no explanation either"
