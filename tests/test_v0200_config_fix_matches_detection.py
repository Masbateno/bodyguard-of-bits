"""v0.20.0 — a monolithic-config sed fix must match what the check detects.

The v0.19.0 campaign found two remediations that *lied*: samba appended instead
of replacing, ssh edited the wrong file. Both were fixes whose `sed` did not
touch the line the detection had flagged, so `--fix` reported success while the
next audit re-raised the finding. The same fragility survived in two monolithic
targets whose fixes used an over-literal `sed` pattern:

  * ufw IPv6: detection matches `^IPV6\\s*=\\s*no` (spaces, any case), but the
    fix matched only the exact literal `^IPV6=no` — a no-op on `IPV6 = no` or
    `IPV6=NO`.
  * umask: detection allows `\\s+` between `umask` and the value (a tab, several
    spaces) and reads login.defs case-insensitively, but the fix required one
    literal space and an uppercase `UMASK` — a no-op on `umask\\t002`.

This guard forges each non-canonical-but-valid form, runs BOB's own detection to
confirm it flags it, applies the *shipped* fix command, and runs the detection
again: the finding must clear. Detection and remediation are exercised through
the real readers, so a fix that reverts to the literal pattern fails here.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from bob.checks.firewall import _ipv6_enable_cmd, _read_ipv6_config
from bob.checks.umask import (
    _fix_cmd, _scan, _normalize,
    _LOGIN_DEFS_RE, _UMASK_RE,
)


def _run_fix(cmd: str, target: Path, orig_path: str) -> None:
    """Apply a shipped fix command's sed program to *target*.

    The commands are `sudo sed -i … <path> [&& …]`; drop the sudo and any
    trailing `&& ufw reload`, retarget the hardcoded path onto the temp file,
    and run the sed under a shell (the replacement text carries a space, so the
    single-quoted program must be honoured). Only the sed program is under test
    — the reload is a runtime step.
    """
    sed_part = cmd.split("&&", 1)[0].strip()
    assert sed_part.startswith("sudo sed "), sed_part
    sed_part = sed_part[len("sudo "):].replace(orig_path, str(target))
    subprocess.run(sed_part, shell=True, check=True)


class TestUfwIpv6FixMatchesDetection:
    @pytest.mark.parametrize("line", [
        "IPV6=no",          # canonical
        "IPV6 = no",        # spaces around =
        "IPV6=NO",          # uppercase value
        "IPV6 =No # note",  # mixed spacing + case + trailing comment
    ])
    def test_roundtrip_clears_the_finding(self, tmp_path, line):
        conf = tmp_path / "ufw"
        conf.write_text(line + "\n", encoding="utf-8")
        # Detection: IPv6 reads as disabled (False).
        assert _read_ipv6_config(conf) is False, f"detection missed {line!r}"
        _run_fix(_ipv6_enable_cmd(), conf, "/etc/default/ufw")
        # After the fix, IPv6 must read as enabled.
        assert _read_ipv6_config(conf) is True, (
            f"fix was a no-op on {line!r}: {conf.read_text()!r}")


class TestUmaskFixMatchesDetection:
    def _bad(self, path, regex) -> bool:
        v = _scan(path, regex)
        return v in ("000", "002")

    @pytest.mark.parametrize("line", [
        "umask 002",        # one space
        "umask\t002",       # a tab
        "umask  000",       # two spaces
        "  umask\t\t002 # c",  # indent + tabs + trailing comment
    ])
    def test_shell_file_roundtrip(self, tmp_path, line):
        prof = tmp_path / "profile"
        prof.write_text(line + "\n", encoding="utf-8")
        assert self._bad(prof, _UMASK_RE), f"detection missed {line!r}"
        _run_fix(_fix_cmd(str(prof)), prof, str(prof))   # source == prof → shell-file branch
        assert not self._bad(prof, _UMASK_RE), (
            f"fix was a no-op on {line!r}: {prof.read_text()!r}")

    @pytest.mark.parametrize("line", [
        "UMASK\t002",       # canonical (tab)
        "UMASK 002",        # a space
        "umask 002",        # lowercase (login.defs is read case-insensitively)
    ])
    def test_login_defs_roundtrip(self, tmp_path, line):
        defs = tmp_path / "login.defs"
        defs.write_text(line + "\n", encoding="utf-8")
        assert self._bad(defs, _LOGIN_DEFS_RE), f"detection missed {line!r}"
        # _fix_cmd hardcodes /etc/login.defs; retarget its sed at the temp file.
        cmd = _fix_cmd("/etc/login.defs")
        _run_fix(cmd, defs, "/etc/login.defs")
        assert not self._bad(defs, _LOGIN_DEFS_RE), (
            f"fix was a no-op on {line!r}: {defs.read_text()!r}")


def test_the_readers_agree_022_is_clean():
    """Sanity: the fixed value the seds write is the one detection calls clean."""
    assert _normalize("0022") == "022"
