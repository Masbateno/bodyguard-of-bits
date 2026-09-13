"""Advice BOB publishes gets followed twice, so it has to be safe twice.

Measured on a Debian 13 VM, v0.17.1 development. The rp_filter fix, run three
times, left three identical lines in ``99-hardening.conf``. ``echo X | sudo tee
-a F`` is what an operator types once; BOB hands it out as advice, and advice
gets followed again — after a failed attempt, after a reboot, after the next
audit repeats the same finding.

Three more defects surfaced with it, each measured on that machine:

* **Eleven filenames for the same settings.** Every ``cmd=`` wrote
  ``99-hardening.conf``; the ``--explain`` prose for those same settings taught
  ``99-rp-filter.conf``, ``99-network-security.conf``, ``99-aslr.conf``,
  ``99-ptrace.conf``, ``99-dmesg.conf``, ``99-kptr.conf``, ``99-suid-dump.conf``
  and more. An operator who read the explanation and then applied the fix wrote
  the same key into two files.

* **``sudo tee >> FILE``**, in the log_martians prose. The redirection is
  performed by the calling shell, which is not root — that is the whole reason
  ``sudo tee`` exists. As an unprivileged user on the VM: ``cannot create
  /etc/sysctl.d/99-preuve.conf: Permission denied``, and no file created.

* **The three samba fixes were no-ops.** smb.conf is section-scoped, and
  appending puts the line in whatever section is last — on stock Debian 13 that
  is ``[print$]`` at line 224. With ``min protocol = SMB3`` appended,
  ``testparm --section-name=global`` still answered ``SMB2_02`` and samba
  rejected the line outright: *"Parameter min protocol unknown for section
  print$"*. All three are global-only parameters. BOB's own parser reads them
  from ``[global]``, so the tool knew where they belonged while its advice did
  not.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from bob.checks._run import SYSCTL_CONF, append_once, sysctl_fix_cmd
from bob.checks.auditd import _suggest_rules_cmd
from bob.checks.kernel_hardening import _fix_cmd
from bob.checks.samba import _global_directive_cmd

_SRC = Path(__file__).resolve().parent.parent / "bob"
_LOCALES = _SRC / "locales"

def _command_statements():
    """Statements of BOB source that build a shell command, prose excluded.

    Two earlier drafts scanned line by line and both were wrong. The first
    reported the docstrings that *explain* the guard as the defect. The second
    still flagged `append_once` itself, whose `grep` and whose `tee` live on
    different lines of one f-string. A statement is the unit that holds a whole
    command, and `ast` skips docstrings for free.
    """
    out = []
    for path in sorted(_SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover — would fail the whole suite anyway
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                continue  # a docstring, or a bare string
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # its own docstring would come along; the body is walked
            if not isinstance(node, ast.stmt):
                continue
            try:
                text = ast.unparse(node)
            except Exception:  # pragma: no cover
                continue
            if "tee" in text:
                out.append((str(path.relative_to(_SRC.parent)), " ".join(text.split())))
    return out


class TestNoBareAppendSurvivesInCode:
    def test_there_is_something_to_check(self):
        assert _command_statements(), "no command builder found — guard lost its aim"

    def test_every_append_is_guarded(self):
        """`tee -a` writes unconditionally; `tee FILE` overwrites, which is safe."""
        bare = [(w, ln) for w, ln in _command_statements()
                if "tee -a" in ln and "grep -qxF" not in ln
                and "append_once" not in ln]
        assert not bare, (
            "unguarded append(s) — applying the advice twice writes the line "
            f"twice: {bare}"
        )

    def test_no_redirection_pretends_to_be_privileged(self):
        for locale in ("en", "fr"):
            text = (_LOCALES / f"{locale}.json").read_text(encoding="utf-8")
            assert "sudo tee >>" not in text, (
                f"{locale}.json teaches `sudo tee >> FILE`, which fails with "
                "permission denied for any non-root operator"
            )
        for where, stmt in _command_statements():
            assert "sudo tee >>" not in stmt, where


class TestTheGeneratedCommandsAreIdempotent:
    @pytest.mark.parametrize("cmd", [
        sysctl_fix_cmd("net.ipv4.conf.all.rp_filter=1"),
        _fix_cmd("kernel.randomize_va_space", 2),
        _suggest_rules_cmd(["/etc/shadow"]),
    ])
    def test_each_one_checks_before_it_writes(self, cmd):
        assert "grep -qxF" in cmd, f"writes unconditionally: {cmd}"

    def test_the_samba_directive_deletes_then_inserts(self):
        """v0.18.4: the samba fix is idempotent by *replacement*, not a grep
        guard. It deletes every existing assignment of the parameter (all
        spellings) and inserts the directive once — so a re-run deletes the
        inserted line too and re-inserts a single copy, and, unlike the old
        grep-then-append form, samba's last-wins resolution can no longer let a
        stale ``NT1`` line below the insert keep SMB1 alive (field-test finding
        on a real Pi). See _global_directive_cmd."""
        cmd = _global_directive_cmd("min protocol = SMB2",
                                    "min protocol", "server min protocol")
        assert " -E '/^[[:space:]]*(min protocol|server min protocol)[[:space:]]*=/Id'" in cmd
        # delete precedes insert, so the offending line cannot survive below it
        assert cmd.index("/Id'") < cmd.index("/a min protocol = SMB2")

    def test_the_sysctl_fix_still_applies_it_live(self):
        cmd = sysctl_fix_cmd("net.ipv4.conf.all.rp_filter=1")
        live, sep, persist = cmd.partition("&&")
        assert sep, "the fix lost its live half"
        assert "sysctl -w" in live
        assert SYSCTL_CONF in persist

    def test_the_guard_is_grouped_so_a_no_op_is_not_a_failure(self):
        """`A && B || C` without braces makes 'already done' look like failure."""
        cmd = sysctl_fix_cmd("net.ipv4.conf.all.rp_filter=1")
        assert "&& {" in cmd and cmd.rstrip().endswith("}")

    def test_append_once_quotes_what_it_is_given(self):
        cmd = append_once("a b; rm -rf /", "/tmp/f")
        assert "'a b; rm -rf /'" in cmd


class TestOneFileForOneSetting:
    """Not one file for everything — one file per *setting*, consistently.

    Per-key files are a legitimate pattern: `99-swappiness.conf` is written
    with a plain `tee`, idempotent by overwrite. What is asserted here is
    agreement between the fix and the prose that explains it, not a single
    filename across the tool.
    """

    _PAT = re.compile(
        r"([a-z0-9_]+(?:\.[a-z0-9_]+)+)\s*=[^\n]*?/etc/sysctl\.d/([0-9a-z._-]+\.conf)")

    def _param_to_files(self):
        mapping: "dict[str, set[str]]" = {}
        texts = [p.read_text(encoding="utf-8") for p in sorted(_SRC.rglob("*.py"))]
        texts += [(_LOCALES / f"{loc}.json").read_text(encoding="utf-8")
                  for loc in ("en", "fr")]
        for text in texts:
            for param, conf in self._PAT.findall(text):
                mapping.setdefault(param, set()).add(conf)
        return mapping

    def test_there_is_something_to_check(self):
        assert self._param_to_files(), "no sysctl setting found — guard is inert"

    def test_no_setting_is_taught_two_files(self):
        split = {p: sorted(f) for p, f in self._param_to_files().items() if len(f) > 1}
        assert not split, (
            "these settings are persisted to more than one file depending on "
            f"where the operator reads: {split}"
        )


class TestTheSambaFixReachesGlobal:
    """It has to land where samba reads it, not where the file happens to end."""

    @pytest.mark.parametrize("directive", [
        "min protocol = SMB2", "server signing = mandatory", "map to guest = never",
    ])
    def test_it_targets_the_global_section(self, directive):
        cmd = _global_directive_cmd(directive)
        assert "global" in cmd and "sed -i" in cmd, (
            "appending to the end of smb.conf puts the directive in the last "
            "section — measured on Debian 13: [print$], where samba rejects it"
        )
        assert "tee -a /etc/samba/smb.conf" not in cmd

    def test_no_bare_append_to_smb_conf_is_left(self):
        offenders = [(w, st) for w, st in _command_statements()
                     if "tee -a /etc/samba/smb.conf" in st]
        assert not offenders, offenders
