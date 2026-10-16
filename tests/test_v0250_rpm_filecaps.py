"""v0.25.0 — on an rpm host, a capability's origin is proved, not guessed.

``_KNOWN`` recognises a binary by its name. Measured on Fedora 44: a copy of
``newuidmap`` in /usr/local/bin with ``cap_setuid`` — root by another name —
owned by no package, passed as the shadow-utils binary and BOB said OK. The
rpm database records each packaged file's capabilities (``%{FILECAPS}``):
BOB now asks it, and a file no package owns, or one carrying more than its
package ships, is not known whatever its name. Replayed on the same host: the
unowned copy WARN −1, a packaged ``arping`` given ``cap_setuid`` WARN −1, the
17 packaged files OK.
"""

from __future__ import annotations

import pytest

from bob.checks import _run, file_capabilities as fc
from bob.checks.file_capabilities import FileCapabilitiesSnapshot, check_file_capabilities

# `rpm -qf --qf '[%{FILENAMES}\t%{FILECAPS}\n]' …` on Fedora 44 (LC_ALL=C), trimmed.
_RPM_OUT = ("/usr/bin/arping\tcap_net_raw=p\n/usr/share/man/man8/arping.8.gz\t\n"
            "/usr/bin/newuidmap\tcap_setuid=ep\n/usr/bin/newgidmap\tcap_setgid=ep\n"
            "/usr/bin/suexec\tcap_setgid,cap_setuid=ep\n")
_RPM_ERR = "file /usr/local/bin/newuidmap is not owned by any package\n"


class TestTheCapabilityText:
    @pytest.mark.parametrize("text, names", [
        ("cap_setgid,cap_setuid=ep", {"setgid", "setuid"}),
        ("cap_net_raw+p", {"net_raw"}),
        ("cap_net_raw=p cap_sys_nice+ep", {"net_raw", "sys_nice"}),
        ("", set()),
    ])
    def test_names(self, text, names):
        assert fc._parse_cap_text(text) == frozenset(names)

    def test_a_bare_assignment_is_every_capability(self):
        assert fc._parse_cap_text("=ep") == frozenset(fc._CAP_NAMES)


class TestWhatRpmSays:
    @pytest.fixture
    def rpm(self, monkeypatch):
        monkeypatch.setattr(fc, "_command_exists", lambda c: c == "rpm")
        monkeypatch.setattr(fc, "run_result",
                            lambda *a, **k: _run.CommandResult(_RPM_OUT, False, _RPM_ERR, 1))

    def test_owned_and_unowned(self, rpm):
        got = fc._rpm_filecaps(["/usr/bin/arping", "/usr/bin/suexec", "/usr/local/bin/newuidmap"])
        assert got == {"/usr/bin/arping": frozenset({"net_raw"}),
                       "/usr/bin/suexec": frozenset({"setgid", "setuid"}),
                       "/usr/local/bin/newuidmap": None}

    def test_a_path_rpm_said_nothing_about_is_left_to_the_name(self, rpm):
        assert "/opt/x/tool" not in fc._rpm_filecaps(["/opt/x/tool"])

    def test_no_rpm_no_answer(self, monkeypatch):
        monkeypatch.setattr(fc, "_command_exists", lambda c: False)
        assert fc._rpm_filecaps(["/usr/bin/arping"]) == {}

    def test_the_snapshot_asks(self):
        import inspect
        assert "snap.rpm_caps = _rpm_filecaps([p for p, _ in snap.entries])" in \
            inspect.getsource(FileCapabilitiesSnapshot.from_system)


def _verdict(entries, rpm_caps):
    r = check_file_capabilities(FileCapabilitiesSnapshot(entries=entries, files_seen=10, rpm_caps=rpm_caps))
    return {f.key for f in r.findings}, [(d.key, d.points) for d in r.deductions]


class TestTheVerdict:
    def test_an_unowned_copy_with_a_known_name(self):
        keys, deds = _verdict([("/usr/local/bin/newuidmap", frozenset({"setuid"}))],
                              {"/usr/local/bin/newuidmap": None})
        assert "file_capabilities.root_equivalent" in keys and deds == [("file_capabilities.root_equivalent", 1)]

    def test_a_packaged_binary_given_more(self):
        keys, _ = _verdict([("/usr/bin/arping", frozenset({"net_raw", "setuid"}))],
                           {"/usr/bin/arping": frozenset({"net_raw"})})
        assert "file_capabilities.root_equivalent" in keys

    def test_a_packaged_grant_with_a_name_the_list_lacks(self):
        """rpm proves it: no list of names needed (sssd's helpers were added by hand)."""
        keys, deds = _verdict([("/usr/libexec/newpkg/helper", frozenset({"setuid"}))],
                              {"/usr/libexec/newpkg/helper": frozenset({"setuid"})})
        assert keys == {"file_capabilities.ok"} and not deds

    def test_without_rpm_the_name_still_decides(self):
        keys, _ = _verdict([("/usr/bin/newuidmap", frozenset({"setuid"}))], {})
        assert keys == {"file_capabilities.ok"}


class TestTheDetailSaysWhyItIsNotKnown:
    """The detail names what the rpm database answered for each flagged file —
    the two cases measured on Fedora 44: a copy no package owns, and arping
    carrying a capability its package does not ship."""

    def _detail(self, entries, rpm_caps):
        r = check_file_capabilities(FileCapabilitiesSnapshot(entries=entries, files_seen=10, rpm_caps=rpm_caps),
                                    t=lambda k, **kw: f"{k}{kw}")
        return next(f.detail for f in r.findings if f.key == "file_capabilities.root_equivalent")

    def test_unowned(self):
        d = self._detail([("/usr/local/bin/newuidmap", frozenset({"setuid"}))],
                         {"/usr/local/bin/newuidmap": None})
        assert "file_capabilities.provenance_unowned" in d and "/usr/local/bin/newuidmap" in d

    def test_more_than_the_package_ships(self):
        d = self._detail([("/usr/bin/arping", frozenset({"net_raw", "setuid"}))],
                         {"/usr/bin/arping": frozenset({"net_raw"})})
        assert "file_capabilities.provenance_packaged" in d and "net_raw" in d

    def test_no_rpm_answer_no_claim(self):
        d = self._detail([("/opt/x", frozenset({"setuid"}))], {})
        assert "provenance" not in d

    @pytest.mark.parametrize("lang, needle", [("en", "no package owns it"), ("fr", "aucun paquet ne le possède")])
    def test_rendered(self, lang, needle):
        from bob import i18n
        i18n.init(lang)
        try:
            r = check_file_capabilities(FileCapabilitiesSnapshot(
                entries=[("/usr/local/bin/newuidmap", frozenset({"setuid"}))], files_seen=1,
                rpm_caps={"/usr/local/bin/newuidmap": None}), t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert needle in next(f.detail for f in r.findings if f.key == "file_capabilities.root_equivalent")
