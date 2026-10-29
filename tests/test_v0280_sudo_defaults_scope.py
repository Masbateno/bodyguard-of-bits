"""v0.28.0 — sudo's Defaults read in the scope they govern: noexec, runas_default.

0.27.0 read NOEXEC from the rule's tag only, and counted every runas_default
scope it did not resolve (a group, a host) as applying. Measured on Debian 13
(sudo 1.9.16p2, 25 October 2026), `bobesc ALL=(root) NOPASSWD: /usr/bin/env`
then `sudo -n /usr/bin/env sh -c 'id -u'`:

- exec blocked by `Defaults noexec`, `Defaults:bobesc noexec`,
  `Defaults:%bobesc noexec` (its primary group), `Defaults:%grpin noexec` (a
  supplementary one), `Defaults!/usr/bin/env noexec`, `Defaults!ENVS noexec`
  (a Cmnd_Alias) and `Defaults>root noexec` — BOB said root-equivalent (−2);
- exec ran under `Defaults noexec` with the rule's `EXEC:` tag,
  `Defaults:other`, `Defaults:%grpout` (not a member), `Defaults>daemon`,
  `Defaults!/usr/bin/id`, and `Defaults noexec` then `Defaults:bobesc
  !noexec` — the −2 is right there; a `NOEXEC:` tag under `Defaults !noexec`
  blocked it.

And `bobesc ALL = NOPASSWD: /usr/bin/python3` (no Runas_Spec): python3 ran as
euid 0 under `Defaults:%grpout runas_default=daemon`, `Defaults:ALL,!bobesc
…` and `Defaults@elsewhere …` — BOB said not root; as euid 1 under
`Defaults:%grpin …`, `Defaults:%bobesc …` and `Defaults@<this host> …`.
"""

from __future__ import annotations

import pytest

from bob.checks import file_perms as fp

ENV = "bobesc ALL=(root) NOPASSWD:{tags} /usr/bin/env\n"
PY = "bobesc ALL = NOPASSWD: /usr/bin/python3\n"


@pytest.fixture
def host(monkeypatch, tmp_path):
    """bobesc in groups bobesc (primary) and grpin, on host bobbench, with
    sudo's noexec library present and /usr/bin/env dynamically linked."""
    monkeypatch.setattr(fp, "_account_groups",
                        lambda user: (1000, {1000, 1001}, {"bobesc", "grpin"}) if user == "bobesc"
                        else (0, {0}, {"root"}) if user == "root" else None)
    monkeypatch.setattr("socket.gethostname", lambda: "bobbench")
    monkeypatch.setattr(fp, "_sudo_noexec_library", lambda: "/usr/libexec/sudo/sudo_noexec.so")
    monkeypatch.setattr(fp, "_dynamically_linked", lambda path: True)
    monkeypatch.setattr(fp, "_run", lambda *a, **k: "")

    def flagged(text):
        sudoers = tmp_path / "sudoers"
        sudoers.write_text(text)
        monkeypatch.setattr(fp, "_sudoers_files", lambda: ([sudoers], True))
        snap = fp.FilePermsSnapshot.from_system()
        return [c for _l, c, _w, _x in snap.nopasswd_root_equivalent]
    return flagged


class TestNoexecByDefaults:

    @pytest.mark.parametrize("defaults, tags", [
        ("Defaults noexec", ""),
        ("Defaults:bobesc noexec", ""),
        ("Defaults:%bobesc noexec", ""),
        ("Defaults:%grpin noexec", ""),
        ("Defaults!/usr/bin/env noexec", ""),
        ("Cmnd_Alias ENVS = /usr/bin/env\nDefaults!ENVS noexec", ""),
        ("Defaults>root noexec", ""),
        ("Defaults !noexec", "NOEXEC:"),
    ], ids=["global", "user", "primary-group", "group", "command", "alias", "runas-root", "tag-over-negated"])
    def test_exec_blocked_is_not_root_equivalent(self, host, defaults, tags):
        assert host(defaults + "\n" + ENV.format(tags=tags)) == []

    @pytest.mark.parametrize("defaults, tags", [
        ("", ""),
        ("Defaults noexec", "EXEC:"),
        ("Defaults:other noexec", ""),
        ("Defaults:%grpout noexec", ""),
        ("Defaults>daemon noexec", ""),
        ("Defaults!/usr/bin/id noexec", ""),
        ("Defaults noexec\nDefaults:bobesc !noexec", ""),
    ], ids=["none", "exec-tag", "other-user", "other-group", "runas-daemon", "other-command", "negated-later"])
    def test_exec_that_ran_stays_root_equivalent(self, host, defaults, tags):
        assert host(defaults + "\n" + ENV.format(tags=tags)) == ["/usr/bin/env"]

    def test_a_scope_bob_cannot_resolve_makes_no_claim(self, host):
        assert host("Defaults:+admins noexec\n" + ENV.format(tags="")) == []


class TestRunasDefaultScopes:

    @pytest.mark.parametrize("defaults", [
        "Defaults:%grpin runas_default=daemon",
        "Defaults:%bobesc runas_default=daemon",
        "Defaults@bobbench runas_default=daemon",
        "Defaults runas_default=daemon",
    ], ids=["group", "primary-group", "this-host", "global"])
    def test_runs_as_daemon_is_not_root(self, host, defaults):
        assert host(defaults + "\n" + PY) == []

    @pytest.mark.parametrize("defaults", [
        "",
        "Defaults:%grpout runas_default=daemon",
        "Defaults:ALL,!bobesc runas_default=daemon",
        "Defaults@elsewhere runas_default=daemon",
        "Defaults runas_default=daemon\nDefaults:bobesc runas_default=root",
    ], ids=["none", "other-group", "negated", "other-host", "set-back-to-root"])
    def test_runs_as_root_is_root_equivalent(self, host, defaults):
        assert host(defaults + "\n" + PY) == ["/usr/bin/python3"]

    def test_an_alias_scope_makes_no_claim(self, host):
        assert host("Defaults:ADMINS runas_default=daemon\n" + PY) == []


class TestTheResolver:

    @pytest.mark.parametrize("scope, applies", [
        ("", True), (":ALL", True), (":bobesc", True), (":alice", False), (":%grpin", True),
        (":%grpout", False), (":%#1001", True), (":#1000", True), (":ALL,!bobesc", False),
        (":!bobesc,ALL", True), (":ADMINS", None), (":+netgrp", None), (":%:dom", None),
        ("@bobbench", True), ("@elsewhere", False), ("@web.example.org", None),
        (">root", True), (">daemon", False), (">%root", True), (">OPS", None),
    ])
    def test_scopes(self, host, scope, applies):
        assert fp._defaults_scope_applies(scope, "bobesc", "/usr/bin/env", {}) is applies

    @pytest.mark.parametrize("scope, applies", [
        ("!/usr/bin/env", True), ("!/usr/bin/", True), ("!/usr/sbin/", False), ("!/usr/bin/id", False),
        ("!/usr/bin/e*", None), ("!ENVS", True), ("!NOPE", None), ("!ALL", True),
    ])
    def test_command_scopes(self, host, scope, applies):
        assert fp._defaults_scope_applies(scope, "bobesc", "/usr/bin/env", {"ENVS": ["/usr/bin/env"]}) is applies

    def test_a_rule_for_a_group_is_not_resolved_by_one_account(self, host):
        assert fp._defaults_scope_applies(":bobesc", "%admins") is None
        assert fp._defaults_scope_applies(":%admins", "%admins") is True

    def test_the_order_sudo_applies(self):
        texts = ["Defaults!/usr/bin/env !noexec\nDefaults noexec\n"]
        assert [s for s, _b in fp._sudo_defaults(texts)] == ["", "!/usr/bin/env"]


def test_the_groups_sudo_matches_are_the_primary_and_the_supplementary(monkeypatch):
    import grp
    import os
    import pwd
    from types import SimpleNamespace
    monkeypatch.setattr(pwd, "getpwnam", lambda u: SimpleNamespace(pw_uid=1000, pw_gid=1000))
    monkeypatch.setattr(os, "getgrouplist", lambda u, g: [g, 1001])
    monkeypatch.setattr(grp, "getgrgid", lambda g: SimpleNamespace(gr_name={1000: "bobesc", 1001: "grpin"}[g]))
    assert fp._account_groups("bobesc") == (1000, {1000, 1001}, {"bobesc", "grpin"})
