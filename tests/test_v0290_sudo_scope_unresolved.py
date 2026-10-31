"""v0.29.0 — a sudo rule whose weight a Defaults scope BOB cannot resolve decides is said.

Until 0.29.0 such a rule was set aside in silence: no −2, no word, and a score
that did not read as a ceiling. Measured on Debian 13 (sudo 1.9.16p2, 31
October 2026, `~/.cache/bob-fieldtest/sudoesc/unresolved.sh`), as bobesc:

- `bobesc ALL = NOPASSWD: /usr/bin/python3` (no Runas_Spec) ran as euid 0
  under `Defaults:ADMINS runas_default=daemon` with `User_Alias ADMINS =
  alice`, `Defaults:+admins …` and `Defaults@bobbench.example.org …`; as euid
  1 with `User_Alias ADMINS = bobesc` and `Host_Alias HERE = bobbench`;
- `bobesc ALL=(root) NOPASSWD: /usr/bin/env` then `env sh -c id` ran the
  shell (uid 0) under `Defaults:ADMINS noexec` with ADMINS = alice,
  `Defaults:+admins noexec` and `Defaults!/usr/bin/z* noexec`; nothing ran
  with ADMINS = bobesc, `Runas_Alias RA = root` + `Defaults>RA noexec` and
  `Defaults!/usr/bin/e* noexec`.

The same forms go either way, so BOB says it does not know: an INFO per
command, no deduction, and a key that makes the score a ceiling.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import file_perms as fp
from bob.checks.file_perms import FilePermsSnapshot, check_file_perms
from bob.visibility import is_visibility_key

PY = "bobesc ALL = NOPASSWD: /usr/bin/python3"
ENV = "bobesc ALL=(root) NOPASSWD: /usr/bin/env"
KEY = "file_perms.sudo_scope_unresolved"


@pytest.fixture
def host(monkeypatch, tmp_path):
    """bobesc in groups bobesc and grpin, on host bobbench, sudo's noexec
    library present, every binary dynamically linked."""
    monkeypatch.setattr(fp, "_account_groups",
                        lambda user: (1000, {1000, 1001}, {"bobesc", "grpin"}) if user == "bobesc"
                        else (0, {0}, {"root"}) if user == "root" else None)
    monkeypatch.setattr("socket.gethostname", lambda: "bobbench")
    monkeypatch.setattr(fp, "_sudo_noexec_library", lambda: "/usr/libexec/sudo/sudo_noexec.so")
    monkeypatch.setattr(fp, "_dynamically_linked", lambda path: True)
    monkeypatch.setattr(fp, "_run", lambda *a, **k: "")

    def snapshot(text):
        sudoers = tmp_path / "sudoers"
        sudoers.write_text(text + "\n")
        monkeypatch.setattr(fp, "_sudoers_files", lambda: ([sudoers], True))
        return FilePermsSnapshot.from_system()
    return snapshot


class TestTheMeasuredCases:

    @pytest.mark.parametrize("defaults", [
        "Defaults:+admins runas_default=daemon",
        "Defaults@bobbench.example.org runas_default=daemon",
        "Defaults:UNDEFINED runas_default=daemon",
    ], ids=["netgroup", "domain-name", "undefined-alias"])
    def test_runas_default_bob_cannot_resolve_is_said(self, host, defaults):
        snap = host(defaults + "\n" + PY)
        assert snap.sudo_scope_unresolved == [(PY, "/usr/bin/python3", "runas")]
        assert snap.nopasswd_root_equivalent == []

    @pytest.mark.parametrize("defaults", [
        "Defaults:+admins noexec",
        "Defaults!/usr/bin/e* noexec",
        "Defaults!/usr/bin/z* noexec",
    ], ids=["netgroup", "glob-this", "glob-other"])
    def test_noexec_bob_cannot_resolve_is_said(self, host, defaults):
        snap = host(defaults + "\n" + ENV)
        assert snap.sudo_scope_unresolved == [(ENV, "/usr/bin/env", "noexec")]
        assert snap.nopasswd_root_equivalent == []

    @pytest.mark.parametrize("defaults, rule", [("", PY), ("", ENV)], ids=["python3", "env"])
    def test_the_controls_stay_root_equivalent(self, host, defaults, rule):
        snap = host(defaults + "\n" + rule)
        assert snap.sudo_scope_unresolved == []
        assert [c for _l, c, _w, _x in snap.nopasswd_root_equivalent] == [rule.split()[-1]]


class TestOnlyWhereItDecides:

    def test_a_command_that_is_not_root_anyway_says_nothing(self, host):
        rule = "bobesc ALL = NOPASSWD: /usr/bin/id"
        snap = host("Defaults:+admins runas_default=daemon\nDefaults:+admins noexec\n" + rule)
        assert snap.sudo_scope_unresolved == []
        assert snap.nopasswd_root_equivalent == []

    def test_root_anyway_under_noexec_stays_a_deduction(self, host):
        """python3 under NOEXEC still writes files as root (measured, 0.27.0):
        the unresolved noexec does not decide, and the −2 stands."""
        rule = "bobesc ALL=(root) NOPASSWD: /usr/bin/python3"
        snap = host("Defaults:+admins noexec\n" + rule)
        assert snap.sudo_scope_unresolved == []
        assert [c for _l, c, _w, _x in snap.nopasswd_root_equivalent] == ["/usr/bin/python3"]

    def test_noexec_that_cannot_hold_does_not_decide(self, host, monkeypatch):
        """Without sudo's noexec library no noexec holds: the shell runs
        whatever the scope, and the −2 stands."""
        monkeypatch.setattr(fp, "_sudo_noexec_library", lambda: None)
        snap = host("Defaults:+admins noexec\n" + ENV)
        assert snap.sudo_scope_unresolved == []
        assert [c for _l, c, _w, _x in snap.nopasswd_root_equivalent] == ["/usr/bin/env"]

    def test_a_noexec_tag_is_established(self, host):
        """The rule's own NOEXEC tag decides, whatever the Defaults say."""
        snap = host("Defaults:+admins !noexec\nbobesc ALL=(root) NOPASSWD:NOEXEC: /usr/bin/env")
        assert snap.sudo_scope_unresolved == []
        assert snap.nopasswd_root_equivalent == []

    def test_a_runas_spec_leaves_runas_default_out(self, host):
        rule = "bobesc ALL=(root) NOPASSWD: /usr/bin/python3"
        snap = host("Defaults:+admins runas_default=daemon\n" + rule)
        assert snap.sudo_scope_unresolved == []
        assert [c for _l, c, _w, _x in snap.nopasswd_root_equivalent] == ["/usr/bin/python3"]

    def test_an_established_other_account_still_says_nothing(self, host):
        snap = host("Defaults runas_default=daemon\n" + PY)
        assert snap.sudo_scope_unresolved == []
        assert snap.nopasswd_root_equivalent == []


class TestWhatTheAuditSays:

    @pytest.mark.parametrize("lang, why, words", [
        ("en", "runas", "Defaults runas_default whose scope BOB cannot resolve"),
        ("en", "noexec", "Defaults noexec whose scope BOB cannot resolve"),
        ("fr", "runas", "Defaults runas_default dont BOB ne résout pas la portée"),
        ("fr", "noexec", "Defaults noexec dont BOB ne résout pas la portée"),
    ])
    def test_said_without_a_deduction(self, lang, why, words):
        snap = FilePermsSnapshot(sudoers_nopasswd_specific=[PY],
                                 sudo_scope_unresolved=[(PY, "/usr/bin/python3", why)])
        i18n.init(lang)
        try:
            res = check_file_perms(snap, t=i18n.t)
        finally:
            i18n.init(lang="en")
        said = [f for f in res.findings if f.key == KEY]
        assert len(said) == 1
        assert words in said[0].message and "/usr/bin/python3" in said[0].message and PY in said[0].message
        assert said[0].level.name == "INFO"
        assert res.deductions == []

    def test_not_counted_as_often_intentional(self):
        other = "bobesc ALL=(root) NOPASSWD: /usr/bin/id"
        snap = FilePermsSnapshot(sudoers_nopasswd_specific=[PY, other],
                                 sudo_scope_unresolved=[(PY, "/usr/bin/python3", "runas")])
        res = check_file_perms(snap, t=lambda k, **kw: f"{k}|{kw.get('count')}")
        assert "file_perms.sudoers_nopasswd_specific|1" in [f.message for f in res.findings]

    def test_the_score_reads_as_a_ceiling(self):
        assert is_visibility_key(KEY)


JOURNAL = "bobesc ALL=(root) NOPASSWD: /usr/bin/journalctl"
X = '"SYSTEMD_PAGERSECURE"'


class TestTheEnvironmentInItsScope:
    """Measured on Debian 13 (sudo 1.9.16p2, systemd 257, 31 October 2026,
    `~/.cache/bob-fieldtest/sudoesc/envkeep.sh`): `SYSTEMD_PAGERSECURE=0 sudo
    -n printenv SYSTEMD_PAGERSECURE` as bobesc. 0.27.0 read any env_keep or
    !env_reset line as reaching every account, and deducted −2 for a
    journalctl rule where the variable did not reach it."""

    @pytest.fixture(autouse=True)
    def _systemd(self, monkeypatch):
        monkeypatch.setattr(fp, "_systemd_version", lambda: 257)

    @pytest.mark.parametrize("defaults", [
        f"Defaults env_keep += {X}",
        f"Defaults:bobesc env_keep += {X}",
        f"Defaults:%grpin env_keep += {X}",
        "Defaults !env_reset",
        f"Defaults!/usr/bin/journalctl env_keep += {X}",
        f"Defaults>root env_keep += {X}",
        f"Defaults env_keep = {X}",
        'Defaults env_keep += "LANG SYSTEMD_*"',
    ], ids=["global", "user", "group", "no-env-reset", "command", "runas-root", "assign", "wildcard"])
    def test_reaches_the_command(self, host, defaults):
        snap = host(defaults + "\n" + JOURNAL)
        assert [(c, w) for _l, c, w, _x in snap.nopasswd_root_equivalent] == [("/usr/bin/journalctl", "escape")]

    @pytest.mark.parametrize("defaults", [
        "",
        f"Defaults:alice env_keep += {X}",
        "Defaults:alice !env_reset",
        f"Defaults!/usr/bin/printenv env_keep += {X}",
        f"Defaults env_keep += {X}\nDefaults:bobesc env_keep -= {X}",
        f"Defaults>daemon env_keep += {X}",
        "Defaults !env_reset\nDefaults:bobesc env_reset",
        f"Defaults@elsewhere env_keep += {X}",
        f"Defaults env_keep += {X}\nDefaults env_keep = \"LANG\"",
    ], ids=["none", "other-user", "other-user-no-reset", "other-command", "removed-later", "runas-daemon",
            "reset-back", "other-host", "assigned-away"])
    def test_does_not_reach_it(self, host, defaults):
        snap = host(defaults + "\n" + JOURNAL)
        assert snap.nopasswd_root_equivalent == []
        assert snap.sudo_scope_unresolved == []

    @pytest.mark.parametrize("defaults", [
        "Defaults:+admins !env_reset",
        f"Defaults:UNDEFINED env_keep += {X}",
    ], ids=["netgroup", "undefined-alias"])
    def test_a_scope_bob_cannot_resolve_is_said(self, host, defaults):
        snap = host(defaults + "\n" + JOURNAL)
        assert snap.nopasswd_root_equivalent == []
        assert snap.sudo_scope_unresolved == [(JOURNAL, "/usr/bin/journalctl", "env")]

    def test_a_setenv_tag_needs_no_defaults(self, host):
        rule = "bobesc ALL=(root) NOPASSWD:SETENV: /usr/bin/journalctl"
        snap = host(f"Defaults:+admins env_keep += {X}\n" + rule)
        assert [c for _l, c, _w, _x in snap.nopasswd_root_equivalent] == ["/usr/bin/journalctl"]
        assert snap.sudo_scope_unresolved == []

    @pytest.mark.parametrize("lang, words", [("en", "SYSTEMD_PAGERSECURE=0"), ("fr", "SYSTEMD_PAGERSECURE=0")])
    def test_said(self, lang, words):
        snap = FilePermsSnapshot(sudoers_nopasswd_specific=[JOURNAL],
                                 sudo_scope_unresolved=[(JOURNAL, "/usr/bin/journalctl", "env")])
        i18n.init(lang)
        try:
            res = check_file_perms(snap, t=i18n.t)
        finally:
            i18n.init(lang="en")
        said = [f.message for f in res.findings if f.key == KEY]
        assert len(said) == 1 and words in said[0] and "env_keep" in said[0]
        assert res.deductions == []


class TestAliasesResolved:
    """v0.29.0 — User_Alias, Runas_Alias and Host_Alias are written in the
    sudoers BOB reads: resolved, and measured against sudo on Debian 13 (same
    benches): python3 at euid 1 with ADMINS = bobesc, euid 0 with ADMINS =
    alice; env's shell blocked with ADMINS = bobesc and with `Runas_Alias RA
    = root` + `Defaults>RA noexec`, run with ADMINS = alice; the variable
    reached journalctl with ADMINS = bobesc, not with ADMINS = alice."""

    @pytest.fixture(autouse=True)
    def _systemd(self, monkeypatch):
        monkeypatch.setattr(fp, "_systemd_version", lambda: 257)

    @pytest.mark.parametrize("defaults, rule, root", [
        ("User_Alias ADMINS = bobesc\nDefaults:ADMINS runas_default=daemon", PY, False),
        ("User_Alias ADMINS = alice\nDefaults:ADMINS runas_default=daemon", PY, True),
        ("Host_Alias HERE = bobbench\nDefaults@HERE runas_default=daemon", PY, False),
        ("Host_Alias THERE = elsewhere\nDefaults@THERE runas_default=daemon", PY, True),
        ("User_Alias ADMINS = bobesc\nDefaults:ADMINS noexec", ENV, False),
        ("User_Alias ADMINS = alice\nDefaults:ADMINS noexec", ENV, True),
        ("Runas_Alias RA = root\nDefaults>RA noexec", ENV, False),
        ("Runas_Alias RA = daemon\nDefaults>RA noexec", ENV, True),
        (f"User_Alias ADMINS = bobesc\nDefaults:ADMINS env_keep += {X}", JOURNAL, True),
        (f"User_Alias ADMINS = alice\nDefaults:ADMINS env_keep += {X}", JOURNAL, False),
    ], ids=["R1-user-with", "R2-user-without", "R5-host-this", "host-other", "N1-user-with",
            "N2-user-without", "N4-runas-root", "runas-daemon", "E9-user-with", "E10-user-without"])
    def test_measured(self, host, defaults, rule, root):
        snap = host(defaults + "\n" + rule)
        assert snap.sudo_scope_unresolved == []
        assert bool(snap.nopasswd_root_equivalent) is root

    @pytest.mark.parametrize("aliases, applies", [
        ({"User_Alias A": ["B"], "User_Alias B": ["bobesc"]}, True),
        ({"User_Alias A": ["ALL", "!bobesc"]}, False),
        ({"User_Alias A": ["!bobesc", "ALL"]}, True),
        ({"User_Alias A": ["%grpin"]}, True),
        ({"User_Alias A": ["+netgrp"]}, None),
        ({"User_Alias A": ["+netgrp", "bobesc"]}, True),
        ({"User_Alias A": ["A"]}, None),
        ({}, None),
    ], ids=["nested", "negated-last", "negated-first", "group", "netgroup", "decided-after", "loop", "undefined"])
    def test_the_resolver(self, host, aliases, applies):
        assert fp._defaults_scope_applies(":A", "bobesc", None, aliases) is applies

    def test_the_table(self):
        texts = ["User_Alias ADMINS = bobesc, %grpin : OPS = alice\n"
                 "Runas_Alias RA = root\nHost_Alias HERE = bobbench, \\\n  other\n"
                 "Cmnd_Alias ENVS = /usr/bin/env\n# User_Alias GONE = x\n"]
        assert fp._named_aliases(texts) == {"User_Alias ADMINS": ["bobesc", "%grpin"], "User_Alias OPS": ["alice"],
                                            "Runas_Alias RA": ["root"], "Host_Alias HERE": ["bobbench", "other"]}

    def test_the_snapshot_hands_them(self):
        import inspect
        src = inspect.getsource(fp.FilePermsSnapshot.from_system)
        assert "aliases = {**_cmnd_aliases(texts), **_named_aliases(texts)}" in src
        assert "_runas_default_state(line.split()[0], runas_overrides, aliases)" in src
