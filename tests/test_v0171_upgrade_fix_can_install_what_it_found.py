"""The command BOB proposes must be able to install what BOB detected.

Measured on a Debian 13 VM, v0.17.1 development. BOB reported::

    ⚠  2 security package(s) pending update:
       linux-image-6.12.107+deb13-amd64, linux-image-amd64
    → sudo apt-get upgrade -y

`--fix --apply --yes` then printed ``✔ Applied`` and ``1 of 1 fix(es)
applied.`` — in six seconds, on a kernel upgrade. Nothing had happened::

    The following packages have been kept back:
    0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.

    dpkg-query: no packages found matching linux-image-6.12.107+deb13-amd64

The next audit reported the identical two packages.

The cause is an asymmetry BOB's own source describes. Detection runs
``apt-get -s dist-upgrade``, and `_collect_pending_updates` explains why: plain
``upgrade`` "refuses to upgrade any package that would require installing a
new package … this hides every security update bundled with a kernel
transition". The fix then proposed plain ``upgrade``. BOB was looking with one
command and repairing with a strictly weaker one, and reporting the exit code
of the weaker one as success.

``--with-new-pkgs`` closes it: measured on the same VM it installs the kernel
("1 upgraded, 1 newly installed") and, unlike ``dist-upgrade``, removes
nothing — the line an unattended auditor must not cross.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "bob"

#: apt-get's plain `upgrade` without this flag cannot install a new package,
#: so it cannot apply a kernel security update.
_NEW_PKGS = "--with-new-pkgs"


def _apt_upgrade_fix_commands() -> list[tuple[str, str]]:
    """Every `apt-get upgrade` / `apt upgrade` BOB hands an operator as a cmd."""
    found = []
    for path in sorted(_SRC.rglob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("cmd="):
                continue
            m = re.search(r'cmd="([^"]*)"', stripped)
            if not m:
                continue
            cmd = m.group(1)
            # `dist-upgrade` has to match too: a first draft of this collector
            # forbade a preceding hyphen, so swapping the fix to dist-upgrade
            # dropped it out of the list entirely and every check below passed
            # on an empty set. The mutation bench caught that, nothing else
            # would have.
            if re.search(r"(?<![\w-])(apt|apt-get|aptitude)(?![\w-])", cmd) and \
               re.search(r"(?<!\w)(dist-upgrade|full-upgrade|upgrade)(?![\w-])", cmd):
                found.append((str(path.relative_to(_SRC.parent)), cmd))
    # v0.19.0: the upgrade command moved into updates._upgrade_cmd — one entry
    # per manager, so a dnf host is not told to run apt. A cmd built by a call
    # (`cmd=_upgrade_cmd(mgr)`) is invisible to the literal scrape above, the
    # same blind spot _install_templates covers for _INSTALL_MANAGERS, so the
    # scrape has to follow the command into that table.
    from bob.checks.updates import _upgrade_cmd
    for mgr in ("apt", "dnf", "zypper", "pacman", "apk"):
        cmd = _upgrade_cmd(mgr)
        if re.search(r"(?<![\w-])(apt|apt-get|aptitude)(?![\w-])", cmd) and \
           re.search(r"(?<!\w)(dist-upgrade|full-upgrade|upgrade)(?![\w-])", cmd):
            found.append((f"bob/checks/updates.py:_upgrade_cmd[{mgr}]", cmd))
    return found


class TestTheProposedUpgradeCanInstallAKernel:
    def test_there_is_something_to_check(self):
        assert _apt_upgrade_fix_commands(), \
            "no apt upgrade command found — the guard has lost its aim"

    @pytest.mark.parametrize("where,cmd", _apt_upgrade_fix_commands())
    def test_no_plain_apt_get_upgrade_is_offered_as_a_fix(self, where, cmd):
        if "dist-upgrade" in cmd or "full-upgrade" in cmd:
            pytest.skip("already the broad form")
        assert _NEW_PKGS in cmd, (
            f"{where}: `{cmd}` cannot install a package that is not yet "
            "installed, so it cannot apply a kernel security update — it "
            "returns 0 with the package kept back and BOB prints 'Applied'"
        )

    @pytest.mark.parametrize("where,cmd", _apt_upgrade_fix_commands())
    def test_no_fix_removes_packages_unattended(self, where, cmd):
        assert "dist-upgrade" not in cmd and "full-upgrade" not in cmd, (
            f"{where}: `{cmd}` may remove packages, which an auto-applied fix "
            "must never do without a human looking"
        )


class TestDetectionAndRemediationStayReconciled:
    """The asymmetry itself, named so it cannot come back quietly."""

    def test_detection_still_uses_the_broad_simulation(self):
        src = (_SRC / "checks" / "updates.py").read_text(encoding="utf-8")
        # The invariant is the *broad* simulation (dist-upgrade, not plain
        # upgrade), whatever wrapper runs it. v0.20.1 moved the call from `_run`
        # to `run_result` so a timed-out simulation is no longer read as "zero
        # pending" (test_v0201_apt_dist_upgrade_timeout); pin the argv, not the
        # wrapper name.
        assert '"apt-get", "-s", "dist-upgrade"' in src, (
            "detection no longer simulates dist-upgrade — if it narrowed, the "
            "reasoning behind --with-new-pkgs needs re-checking rather than "
            "this guard being deleted"
        )

    def test_the_fix_offered_for_that_detection_matches_it(self):
        # Behavioural, not a source scrape: the cmd is now `_upgrade_cmd(mgr)`,
        # so build the apt security finding and read the command BOB actually
        # hands the operator. That is the detection→remediation link this whole
        # file exists to hold.
        from bob.checks.updates import UpdatesSnapshot, check_updates
        snap = UpdatesSnapshot(
            manager="apt", apt_available=True,
            pending_security=["linux-image-6.12.107+deb13-amd64", "linux-image-amd64"],
        )
        result = check_updates(snap)
        cmd = next((f.cmd for f in result.findings
                    if f.key == "updates.security_pending"), None)
        assert cmd, "security_pending lost its cmd"
        assert _NEW_PKGS in cmd, (
            "BOB collects this finding with `apt-get -s dist-upgrade` and would "
            f"repair it with `{cmd}`, which cannot install a new package — the "
            "exact gap that made a kernel update report as applied"
        )


class TestTheFlagIsUnderstood:
    """What --with-new-pkgs does and does not do, as measured on the VM."""

    def test_it_is_documented_where_it_is_used(self):
        src = (_SRC / "checks" / "updates.py").read_text(encoding="utf-8")
        i = src.index(_NEW_PKGS)
        window = src[max(0, i - 1400):i + 1400]
        assert "kept back" in window, (
            "the flag is there with no note saying what it fixes — the next "
            "reader will simplify it away"
        )
