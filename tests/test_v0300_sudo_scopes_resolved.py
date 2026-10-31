"""v0.30.0 — command patterns, netgroups and host names resolved as sudo does.

0.29.0 said these scopes "not resolved" (file_perms.sudo_scope_unresolved):
the rule was set aside, no -2, the score a ceiling. Measured on Debian 13
(sudo 1.9.16p2, 31 October 2026, `~/.cache/bob-fieldtest/sudoesc/p5bench.sh`,
the account bobesc, `netgroup: files`), each scope against what sudo did:

- `Defaults!<pattern> noexec` on /usr/bin/env: /usr/bin/e*, /usr/*/env,
  /usr/bin/[ef]nv, /usr/bin/en? and /usr/bin/* applied (exec blocked);
  /usr/bin/z* and /usr/* did not (`*` does not cross a `/`);
- `Defaults:+admins runas_default=daemon` on python3: applied (euid 1) for
  (,bobesc,), (otherhost,bobesc,), (,bobesc,example.org), (,,) and a nested
  netgroup; not (euid 0) for (,alice,) nor an undefined netgroup;
- `Defaults@<name> runas_default=daemon`: on a host named bobbench,
  bobbench applied, bobbench.example.org and bobbench.other.org did not; on
  a host named bobbench.example.org, bobbench.example.org and bobbench
  applied, bobbench.other.org did not.

BOB now matches every one of the 21 cases. Still not resolved: a netgroup
nsswitch did not answer for, a host given as an address or a pattern, a
domain name under `Defaults fqdn` (resolved through DNS), an undefined alias.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import file_perms as fp


class _Res:
    def __init__(self, ok, stdout="", code=0):
        self.ok, self.stdout, self.code, self.stderr = ok, stdout, code, ""


@pytest.mark.parametrize("pattern, applies", [
    ("/usr/bin/e*", True), ("/usr/bin/z*", False), ("/usr/*/env", True), ("/usr/*", False),
    ("/usr/bin/[ef]nv", True), ("/usr/bin/en?", True), ("/usr/bin/*", True),
    ("/usr/bin/[!a]nv", True), ("/usr/bin/[a-d]nv", False), ("/usr/bin/[env", None),
    ("/usr/bin/e\\nv", None), ("/usr/bin/e* -u root", None), ("/usr/bin?env", False),
], ids=["G1", "G2", "G3", "G4", "G5", "G6", "G7", "negated-class", "range", "unclosed", "escaped", "with-args",
        "question-no-slash"])
def test_command_patterns(pattern, applies):
    assert fp._match_command(pattern, "/usr/bin/env", {}) is applies


class TestNetgroups:

    @pytest.fixture
    def getent(self, monkeypatch):
        def install(stdout=None, code=0, sources=("files",)):
            monkeypatch.setattr(fp, "run_result", lambda *a, **k: _Res(stdout is not None, stdout or "", code))
            monkeypatch.setattr(fp, "_netgroup_sources", lambda: list(sources))
        return install

    @pytest.mark.parametrize("line, applies", [
        ("admins                ( ,bobesc,)", True),
        ("admins                ( ,alice,)", False),
        ("admins                (otherhost,bobesc,)", True),
        ("admins                ( ,bobesc,example.org)", True),
        ("admins                (h1,carol,) ( ,bobesc,) ( ,,dom)", True),
        ("admins                ( ,,)", True),
        ("admins                ", False),
    ], ids=["NG1-in", "NG2-out", "NG4-host-field", "NG5-domain-field", "NG6-nested-expanded", "NG7-any-user",
            "empty"])
    def test_what_getent_answers(self, getent, line, applies):
        getent(stdout=line + "\n")
        assert fp._match_account("+admins", "bobesc") is applies

    def test_an_undefined_netgroup_with_files_only(self, getent):
        getent(stdout=None, code=2, sources=("files",))
        assert fp._match_account("+admins", "bobesc") is False

    @pytest.mark.parametrize("sources", [("nis",), ("files", "ldap"), ()], ids=["nis", "files-ldap", "none-read"])
    def test_a_source_that_may_not_have_answered(self, getent, sources):
        getent(stdout=None, code=2, sources=sources)
        assert fp._match_account("+admins", "bobesc") is None

    def test_getent_failing_otherwise(self, getent):
        getent(stdout=None, code=1)
        assert fp._match_account("+admins", "bobesc") is None

    def test_the_sources(self, tmp_path, monkeypatch):
        conf = tmp_path / "nsswitch.conf"
        conf.write_text("passwd: files\nnetgroup:       files [NOTFOUND=return] nis\n")
        real = fp.Path
        monkeypatch.setattr(fp, "Path", lambda p: conf if p == "/etc/nsswitch.conf" else real(p))
        assert fp._netgroup_sources() == ["files", "nis"]


@pytest.mark.parametrize("hostname, name, applies", [
    ("bobbench", "bobbench.example.org", False), ("bobbench", "bobbench", True),
    ("bobbench", "bobbench.other.org", False),
    ("bobbench.example.org", "bobbench.example.org", True), ("bobbench.example.org", "bobbench", True),
    ("bobbench.example.org", "bobbench.other.org", False),
    ("bobbench", "BobBench", True), ("bobbench", "192.0.2.10", None), ("bobbench", "bob*", None),
], ids=["H1-short-host", "H2-short-host", "H3-short-host", "H1-long-host", "H2-long-host", "H3-long-host",
        "case", "address", "pattern"])
def test_host_names(monkeypatch, hostname, name, applies):
    monkeypatch.setattr("socket.gethostname", lambda: hostname)
    assert fp._match_host(name, {}) is applies


def test_a_domain_name_under_fqdn_stays_not_resolved(monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "bobbench.example.org")
    aliases = fp._sudo_fqdn(["Defaults env_reset, fqdn\n"])
    assert aliases == {"Defaults fqdn": ["on"]}
    assert fp._match_host("bobbench.example.org", aliases) is None
    assert fp._sudo_fqdn(["Defaults !fqdn\n", "Defaults:bobesc fqdn_x\n"]) == {}


@pytest.mark.parametrize("lang, words", [
    ("en", "a netgroup nsswitch did not answer for, a host given as an address or a pattern"),
    ("fr", "un netgroup pour lequel nsswitch n'a pas répondu, un hôte donné par une adresse ou un motif"),
])
def test_what_is_said(lang, words):
    i18n.init(lang)
    try:
        assert words in i18n.t("file_perms.sudo_scope_unresolved_runas", command="/usr/bin/python3", line="x")
    finally:
        i18n.init(lang="en")
