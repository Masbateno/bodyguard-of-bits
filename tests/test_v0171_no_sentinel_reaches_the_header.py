"""Three firewalls in one header, and only one of them leaked a sentinel.

openSUSE Leap 15.6, where ufw is genuinely absent::

    ║  UFW           : vN/A                                    ║
    ║  iptables      : not installed                           ║
    ║  nftables      : not installed                           ║

Same fact about the machine, two ways of saying it, and the third is not a
sentence at all. `collect_system_info` returned the string ``"N/A"`` for a
missing ufw while returning ``""`` for its two neighbours, and three render
sites then prefixed a version marker to whatever came back — the terminal
banner, the text report and the Markdown report. The value that leaked was
BOB's own placeholder, printed as though it described the host.

The absence is decided once now, at the source, in the same shape as the other
two; the version marker is added by the caller only when there is a version to
mark. Measured after the fix: openSUSE prints ``not installed`` on all three
rows, Debian 13 still prints ``v0.36.2``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from bob.report import SystemInfo

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "bob"


def _system_info(ufw: str) -> SystemInfo:
    return SystemInfo(
        os_name="openSUSE Leap 15.6", hostname="h", kernel="k",
        ufw_version=ufw, iptables_version="", nftables_version="",
        user="root", config_path="/root/.config/bob/config.conf",
        language="en", version="0.17.1",
    )


class TestTheSourceReportsAbsenceLikeItsNeighbours:
    def test_a_missing_ufw_is_empty_not_a_placeholder(self):
        src = (_SRC / "sysinfo.py").read_text(encoding="utf-8")
        m = re.search(r"ufw_version = ufw_match\.group\(0\) if ufw_match else (.+)", src)
        assert m, "the ufw version line moved — re-aim this guard"
        assert m.group(1).strip() == '""', (
            "ufw reports its absence with a sentinel while iptables and "
            "nftables report theirs with an empty string; the render sites "
            "cannot tell a placeholder from a version"
        )

    @pytest.mark.parametrize("field,var", [("iptables", "ipt"), ("nftables", "nft")])
    def test_the_neighbours_still_use_the_same_shape(self, field, var):
        src = (_SRC / "sysinfo.py").read_text(encoding="utf-8")
        assert f'{field}_version = {var}_match.group(1) if {var}_match else ""' in src, (
            f"{field} changed how it reports absence — the three fields have "
            "to agree or a render site cannot treat them the same way")


class TestNoRenderSitePrefixesUnconditionally:
    """The 'v' belongs to a version, not to whatever arrives."""

    @pytest.mark.parametrize("rel", ["output.py", "report.py", "report_markdown.py"])
    def test_no_bare_version_prefix_on_the_ufw_field(self, rel):
        src = (_SRC / rel).read_text(encoding="utf-8")
        offenders = [ln.strip() for ln in src.splitlines()
                     if "ufw_version" in ln and re.search(r'[v"]\{[a-z_.]*ufw_version\}', ln)
                     and "if" not in ln]
        assert not offenders, (
            f"{rel} marks the ufw field as a version without checking there is "
            f"one: {offenders}"
        )

    @pytest.mark.parametrize("rel", ["report.py", "report_markdown.py"])
    def test_each_writer_names_the_absence(self, rel):
        src = (_SRC / rel).read_text(encoding="utf-8")
        assert "not_installed" in src or "not installed" in src, (
            f"{rel} has no wording for an absent firewall, so an empty value "
            "would render as nothing at all"
        )


class TestWhatTheWritersActuallyProduce:
    """Guarding the render, not the helper — built the way the writers are."""

    def _text_report(self, tmp_path, ufw: str) -> str:
        from bob.report import AuditReport
        rep = AuditReport.open(directory=tmp_path, version="0.17.1")
        rep.write_header(_system_info(ufw),
                         labels={"not_installed": "not installed"})
        rep.close()
        return rep.path.read_text(encoding="utf-8")

    def test_absent_ufw_is_named_in_the_text_report(self, tmp_path):
        out = self._text_report(tmp_path, "")
        assert "not installed" in out
        assert "N/A" not in out
        assert "ufw v" not in out

    def test_present_ufw_still_shows_its_version(self, tmp_path):
        assert "0.36.2" in self._text_report(tmp_path, "0.36.2")

    def _markdown_report(self, tmp_path, ufw: str) -> str:
        """MarkdownReport buffers in memory; close() writes nothing."""
        from bob.report_markdown import MarkdownReport
        rep = MarkdownReport.open(directory=tmp_path, version="0.17.1")
        rep.write_header(_system_info(ufw))
        return "\n".join(rep._lines)

    def test_absent_ufw_is_named_in_markdown(self, tmp_path):
        out = self._markdown_report(tmp_path, "")
        assert "not installed" in out
        assert "**Firewall (UFW):** v" not in out

    def test_present_ufw_still_shows_its_version_in_markdown(self, tmp_path):
        assert "0.36.2" in self._markdown_report(tmp_path, "0.36.2")  # bare, SemVer §8


class TestOnlyTheUfwFieldWasAffected:
    """`os_name = "N/A"` stays: it is an honest default, not a marked version."""

    def test_the_ufw_assignment_carries_no_placeholder(self):
        src = (_SRC / "sysinfo.py").read_text(encoding="utf-8")
        line = [ln for ln in src.splitlines()
                if ln.strip().startswith("ufw_version = ufw_match")]
        assert line, "the ufw version assignment moved — re-aim this guard"
        assert "N/A" not in line[0]


class TestTheMachineIdentifiesItselfWithoutHelperBinaries:
    """Arch Linux ships no `hostname`; a report saying `Host : N/A` names nothing."""

    def test_hostname_and_kernel_come_from_the_syscall(self):
        # Comment lines excluded: the comment explaining this fix names the
        # call it removed, and a naive substring search reported the
        # explanation as the defect — the third time that trap fired today.
        src = "\n".join(ln for ln in (_SRC / "sysinfo.py")
                         .read_text(encoding="utf-8").splitlines()
                         if not ln.strip().startswith("#"))
        assert 'run("hostname")' not in src, (
            "the hostname is read from a binary that Arch Linux does not ship, "
            "and the failure prints as the N/A sentinel in the header"
        )
        assert 'run("uname", "-r")' not in src, (
            "the kernel version has the same exposure as the hostname did, two "
            "lines away — it moved with it rather than waiting its turn"
        )
        assert "_uname = os.uname()" in src

    def test_they_are_answered_even_with_no_binaries_at_all(self):
        """`run()` returning its sentinel must not reach either field."""
        from bob import sysinfo
        with patch.object(sysinfo, "collect_system_info", sysinfo.collect_system_info):
            with patch("subprocess.run", side_effect=FileNotFoundError("no binaries")):
                info = sysinfo.collect_system_info("0.17.1", "en")
        assert info.hostname == os.uname().nodename
        assert info.kernel == os.uname().release
        assert "N/A" not in (info.hostname + info.kernel)
