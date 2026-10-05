"""v0.24.1 — remediation sed commands run under BusyBox sed too.

Measured on real Alpine 3.24: every SSH drop-in fix since v0.19.0 stopped at
its first step with "sed: unsupported command I". GNU sed's ``/regex/I`` address
flag (case-insensitive match) does not exist in BusyBox; ``s///I`` does, so only
the address form is banned. ``sed_ci`` spells the case-insensitivity letter by
letter instead.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from bob.checks._run import sed_ci
from bob.checks.ssh._directives import _sshd_directive_fix

_CHECKS = Path(__file__).resolve().parent.parent / "bob" / "checks"
#: A sed *address* with the I flag: /…/I followed by a command letter (d, p, a…)
#: or by the closing quote. ``s/…/…/I`` is a substitution flag BusyBox accepts.
_ADDRESS_I = re.compile(r"(?<!s)/\^[^/]*/I[dpaic]?['\"]")


def test_sed_ci_spells_each_letter():
    assert sed_ci("X11Forwarding") == "[Xx]11[Ff][Oo][Rr][Ww][Aa][Rr][Dd][Ii][Nn][Gg]"
    assert sed_ci("min protocol") == "[Mm][Ii][Nn] [Pp][Rr][Oo][Tt][Oo][Cc][Oo][Ll]"


def test_no_check_builds_a_gnu_only_case_insensitive_address():
    offenders = []
    for path in _CHECKS.rglob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _ADDRESS_I.search(line):
                offenders.append(f"{path.relative_to(_CHECKS)}:{n}: {line.strip()}")
    assert not offenders, "BusyBox sed refuses /regex/I:\n" + "\n".join(offenders)


@pytest.mark.skipif(shutil.which("busybox") is None, reason="busybox not installed")
def test_the_dropin_fix_runs_under_busybox_sed(tmp_path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "00-bob-hardening.conf").write_text("x11forwarding=yes\n", encoding="utf-8")
    cmd = _sshd_directive_fix("X11Forwarding no", "X11Forwarding", {"_dropin_dir": str(d)})
    edit = cmd.split(" && sudo sshd -t")[0].replace("sudo ", "")
    edit = edit.replace("sed -i", "busybox sed -i")
    r = subprocess.run(["sh", "-c", edit], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (d / "00-bob-hardening.conf").read_text(encoding="utf-8") == "X11Forwarding no\n"


@pytest.mark.skipif(shutil.which("busybox") is None, reason="busybox not installed")
def test_the_main_file_fix_runs_under_busybox_sed(tmp_path):
    conf = tmp_path / "sshd_config"
    conf.write_text("Port 22\nStrictModes  no\nMatch User x\n    ForceCommand /bin/false\n",
                    encoding="utf-8")
    cmd = _sshd_directive_fix("StrictModes yes", "StrictModes", {})
    edit = cmd.split(" && sudo sshd -t")[0].replace("sudo ", "")
    edit = edit.replace("sed -i", "busybox sed -i").replace("/etc/ssh/sshd_config", str(conf))
    r = subprocess.run(["sh", "-c", edit], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    lines = conf.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "StrictModes yes"
    assert sum("strictmodes" in ln.lower() for ln in lines) == 1
