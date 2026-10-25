"""v0.27.0 — a NOPASSWD rule for a command that is root anyway weighs like NOPASSWD:ALL.

Found on a Mint host (0.26.0): `so6 ALL=(root) NOPASSWD: /home/so6/.local/bin/bob,
/usr/bin/python3` was an INFO, "specific commands, often intentional" — root
without a password for any process of that user. Measured on an Alpine VM
(24 October 2026), as the account a rule names, each of these returned uid 0:
`sudo -n python3 -c …`, `find … -exec id`, `env id`, `tar --checkpoint-action=exec`,
a script the account rewrote, `less /etc/hosts` then `!id`, `vi /etc/hosts`
then `:!id`; `/usr/bin/id` and `python3 /opt/fixed.py` (root-owned, arguments
written out) gave nothing more. Decided by the user: WARN −2, as NOPASSWD:ALL.

Measured again on a real Debian 13 host (sudo 1.9.16p2, systemd 257, 24 October
2026), driven in a pty as the account a rule names: `less /etc/hosts`,
`more /etc/services` and `man man` then `!id` gave uid 0; under NOEXEC they ran
nothing ("exec failed"), nor did env, xargs, nice, timeout, stdbuf, taskset or
ionice; vi, python3, bash and find still wrote a file as root under NOEXEC.
`sudo journalctl` answered `!` with "Command not available" (systemd 247+ runs
less in secure mode under sudo); root in its own session got its shell. With
free arguments, systemctl (a unit the account wrote) and apt-get (an
APT::Update::Pre-Invoke hook) gave uid 0.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bob import i18n
from bob.checks import file_perms as fp
from bob.checks.file_perms import FilePermsSnapshot, check_file_perms

RULE = ("bobtest ALL=(root) NOPASSWD: /usr/bin/python3, /usr/bin/find, /usr/bin/env, /bin/tar, "
        "BOBVIEW, {tool}, /usr/bin/id, /usr/bin/python3 /opt/fixed.py")
ALIASES = {"BOBVIEW": ["/usr/bin/less /etc/hosts", "/usr/bin/vi /etc/hosts"]}


@pytest.fixture
def tool(tmp_path):
    t = tmp_path / "tool"
    t.write_text("#!/bin/sh\necho tool\n")
    t.chmod(0o755)
    return t


def _flagged(line, aliases=None):
    out = []
    for command in fp._nopasswd_commands(line, aliases or {}) or []:
        found = fp._root_equivalent(command)
        if found:
            out.append((command, found[0]))
    return out


class TestTheRuleIsRead:

    def test_tags_carry_and_passwd_switches_back(self):
        line = "u ALL=(root) /bin/a, NOPASSWD: /bin/b, /bin/c, PASSWD: /bin/d"
        assert fp._nopasswd_commands(line, {}) == ["/bin/b", "/bin/c"]

    @pytest.mark.parametrize("runas, root", [("(root)", True), ("(ALL)", True), ("(ALL:ALL)", True),
                                             ("", True), ("(www-data)", False), ("(backup, nobody)", False)])
    def test_only_a_rule_that_runs_as_root(self, runas, root):
        line = f"u ALL={runas} NOPASSWD: /usr/bin/python3"
        assert bool(fp._nopasswd_commands(line, {})) is root

    @pytest.mark.parametrize("line, grants", [
        ("u ALL=(root) NOPASSWD:NOEXEC: /usr/bin/less /etc/hosts, /usr/bin/env",
         [("/usr/bin/less /etc/hosts", True, False), ("/usr/bin/env", True, False)]),
        ("u ALL=(root) NOEXEC: NOPASSWD: /usr/bin/less /etc/hosts", [("/usr/bin/less /etc/hosts", True, False)]),
        ("u ALL=(root) NOPASSWD:NOEXEC: /usr/bin/less /etc/hosts, EXEC: /usr/bin/env",
         [("/usr/bin/less /etc/hosts", True, False), ("/usr/bin/env", False, False)]),
        ("u ALL=(root) NOPASSWD: /usr/bin/env", [("/usr/bin/env", False, False)]),
        ("u ALL=(root) NOPASSWD:SETENV: /usr/bin/journalctl, NOSETENV: /usr/bin/id",
         [("/usr/bin/journalctl", False, True), ("/usr/bin/id", False, False)]),
    ])
    def test_noexec_carries_and_exec_switches_back(self, line, grants):
        assert fp._nopasswd_grants(line, {}) == grants

    def test_a_command_alias_is_resolved(self):
        texts = ["Cmnd_Alias BOBVIEW = /usr/bin/less /etc/hosts, /usr/bin/vi /etc/hosts\n"]
        aliases = fp._cmnd_aliases(texts)
        assert fp._nopasswd_commands("u ALL=(root) NOPASSWD: BOBVIEW", aliases) == ALIASES["BOBVIEW"]


class TestWhatIsRootAnyway:

    def test_the_measured_bench(self, tool):
        flagged = dict(_flagged(RULE.format(tool=tool), ALIASES))
        assert flagged == {
            "/usr/bin/python3": "arguments", "/usr/bin/find": "arguments", "/usr/bin/env": "arguments",
            "/bin/tar": "arguments", "/usr/bin/less /etc/hosts": "escape", "/usr/bin/vi /etc/hosts": "editor",
            str(tool): "writable",
        }

    @pytest.mark.parametrize("command, why", [
        ("/usr/bin/python3.12", "arguments"),
        ("/usr/bin/find /var/log -name *.gz", "arguments"),      # a wildcard opens the arguments
        ("/usr/bin/python3 /opt/fixed.py", None),                # written out, root-owned script (absent here)
        ('/usr/bin/find ""', None),                              # "" forbids any argument
        ("ALL", "arguments"),                                    # ALL among other commands
    ])
    def test_by_name_and_arguments(self, command, why):
        found = fp._root_equivalent(command)
        assert (found[0] if found else None) == why

    @pytest.mark.parametrize("pager_env", [True])
    def test_journalctl_when_the_variable_can_pass(self, pager_env):
        """Measured on Debian 13 after the review: with SETENV, or env_keep +=
        "SYSTEMD_PAGERSECURE", SYSTEMD_PAGERSECURE=0 turned the secure pager
        off — journalctl's `:e /etc/shadow` showed root's hash."""
        found = fp._root_equivalent("/usr/bin/journalctl", systemd=257, pager_env=pager_env)
        assert found and found[0] == "escape"

    @pytest.mark.parametrize("defaults, passes", [
        ('Defaults:bobesc env_keep += "SYSTEMD_PAGERSECURE"\n', True),
        ('Defaults env_keep = "LANG SYSTEMD_PAGERSECURE"\n', True),
        ("Defaults !env_reset\n", True),
        ('Defaults env_keep += "LANG"\n', False),
        ("# Defaults !env_reset\n", False),
    ])
    def test_what_lets_the_variable_through(self, defaults, passes):
        assert fp._sudo_env_passes_pager_secure([defaults]) is passes

    def test_journalctl_under_doas_is_never_secure(self):
        """Measured on Debian 13 (systemd 257, opendoas): the secure pager
        detects sudo only — under doas, `:e /etc/shadow` showed root's hash."""
        import inspect
        src = inspect.getsource(fp.FilePermsSnapshot.from_system)
        assert "pager_env=True) if command else None" in src

    @pytest.mark.parametrize("systemd, why", [(246, "escape"), (247, None), (257, None), (None, None)])
    def test_journalctl_by_systemds_version(self, systemd, why):
        found = fp._root_equivalent("/usr/bin/journalctl -u nginx", systemd=systemd)
        assert (found[0] if found else None) == why

    @pytest.mark.parametrize("command, why", [
        ("/usr/bin/less /etc/services", "reads"), ("/usr/bin/more /etc/services", None), ("/usr/bin/man man", None),
        ("/usr/bin/env", None), ("/usr/bin/xargs", None), ("/usr/bin/nice", None), ("/usr/bin/timeout", None),
        ("/usr/bin/stdbuf", None), ("/usr/bin/taskset", None), ("/usr/bin/ionice", None),
        ("/usr/bin/vi /etc/hosts", "editor"), ("/usr/bin/python3", "arguments"),
        ("/usr/bin/bash", "arguments"), ("/usr/bin/find", "arguments"),
    ])
    def test_under_noexec_the_measured_bench(self, command, why):
        found = fp._root_equivalent(command, noexec=True)
        assert (found[0] if found else None) == why

    @pytest.mark.parametrize("lang, words", [("en", "opens any file as root"),
                                             ("fr", "ouvre n'importe quel fichier en root")])
    def test_a_pager_that_still_reads_says_so(self, lang, words):
        """Measured after the review: under NOEXEC, less then `:e /etc/shadow`
        showed root's hash; the account alone could not read it."""
        line = "u ALL=(root) NOPASSWD:NOEXEC: /usr/bin/less /etc/services"
        snap = FilePermsSnapshot(sudoers_nopasswd_specific=[line],
                                 nopasswd_root_equivalent=[(line, "/usr/bin/less /etc/services", "reads", "less")])
        i18n.init(lang)
        try:
            res = check_file_perms(snap, t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in res.findings)
        assert [d.points for d in res.deductions] == [2]

    def test_without_noexec_the_same_pagers_and_wrappers_are_root(self):
        for command in ("/usr/bin/less /etc/services", "/usr/bin/more /etc/services", "/usr/bin/man man",
                        "/usr/bin/env", "/usr/bin/xargs"):
            assert fp._root_equivalent(command), command

    def test_a_root_owned_binary_with_fixed_arguments_is_not(self):
        if os.stat("/usr/bin/id").st_uid != 0:
            pytest.skip("/usr/bin/id not root-owned here")
        assert fp._root_equivalent("/usr/bin/id -u") is None

    def test_a_directory_another_account_can_write(self, tmp_path):
        d = tmp_path / "bin"; d.mkdir()
        b = d / "tool"; b.write_text(""); b.chmod(0o755)
        assert fp._root_equivalent(f"{b} --now")[0] == "writable"

    def test_the_script_an_interpreter_is_handed(self, tmp_path):
        script = tmp_path / "job.py"; script.write_text("")
        if not os.path.exists("/usr/bin/python3") or os.stat("/usr/bin/python3").st_uid != 0:
            pytest.skip("/usr/bin/python3 not root-owned here")
        found = fp._root_equivalent(f"/usr/bin/python3 {script}")
        assert found and found[0] == "writable"

    def test_group_write_by_root_group_is_root_only(self, tmp_path, monkeypatch):
        class _St:
            st_uid, st_gid, st_mode = 0, 0, 0o40775
        monkeypatch.setattr(fp.os, "stat", lambda p: _St)
        assert fp._writable_by_another("/opt/x") is None


class TestDoas:

    @pytest.mark.parametrize("line, command", [
        ("permit nopass bob as root cmd /usr/bin/python3", "/usr/bin/python3"),
        ("permit nopass bob cmd /usr/bin/find args /var -name x", "/usr/bin/find /var -name x"),
        ("permit nopass bob cmd /usr/bin/find args", '/usr/bin/find ""'),
        ("permit nopass bob as www cmd /usr/bin/python3", None),
    ])
    def test_the_command(self, line, command):
        assert fp._doas_command(line) == command


class TestTheVersionRead:

    @pytest.mark.parametrize("out, version", [("systemd 257 (257.13-1~deb13u1)\n+PAM +AUDIT", 257),
                                              ("systemd 255 (255.4-1ubuntu8.18)", 255), ("", None)])
    def test_systemctl_version(self, monkeypatch, out, version):
        monkeypatch.setattr(fp, "_run", lambda *a, **k: out)
        assert fp._systemd_version() == version

    def test_the_snapshot_hands_noexec_and_the_version(self):
        import inspect
        src = inspect.getsource(fp.FilePermsSnapshot.from_system)
        assert "_root_equivalent(command, noexec=noexec, systemd=systemd," in src
        assert "pager_env=setenv or env_passes)" in src


class TestTheFinding:

    def _snap(self, tool):
        line = RULE.format(tool=tool)
        found = [(line, c, w, fp._root_equivalent(c)[1]) for c, w in _flagged(line, ALIASES)]
        return FilePermsSnapshot(sudoers_nopasswd_specific=[line, "u ALL=(root) NOPASSWD: /usr/bin/id"],
                                 nopasswd_root_equivalent=found)

    def test_one_warn_per_command_two_points_once(self, tool):
        res = check_file_perms(self._snap(tool), t=lambda k, **kw: k)
        warns = [f for f in res.findings if f.key == "file_perms.nopass_root_equivalent"]
        assert len(warns) == 7
        assert [d.points for d in res.deductions if d.key == "file_perms.nopass_root_equivalent"] == [2]

    def test_a_doas_rule_found_root_is_not_also_often_intentional(self):
        root = "permit nopass bob cmd /usr/bin/python3"
        snap = FilePermsSnapshot(doas_nopass_specific=[root, "permit nopass bob cmd /usr/bin/id args -u"],
                                 nopasswd_root_equivalent=[(root, "/usr/bin/python3", "arguments", "python3")])
        res = check_file_perms(snap, t=lambda k, **kw: f"{k}|{kw.get('count')}")
        info = [f.message for f in res.findings if f.key == "file_perms.doas_nopass_specific"]
        assert info == ["file_perms.doas_nopass_specific|1"]

    @pytest.mark.parametrize("lang, words", [("en", "an editor writes any file as root"),
                                             ("fr", "un éditeur écrit n'importe quel fichier en root")])
    def test_the_editor_is_said(self, tool, lang, words):
        i18n.init(lang)
        try:
            res = check_file_perms(self._snap(tool), t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in res.findings)

    def test_a_rule_found_root_is_not_also_often_intentional(self, tool):
        res = check_file_perms(self._snap(tool), t=lambda k, **kw: f"{k}|{kw.get('count')}")
        info = [f.message for f in res.findings if f.key == "file_perms.sudoers_nopasswd_specific"]
        assert info == ["file_perms.sudoers_nopasswd_specific|1"]       # only the /usr/bin/id rule

    @pytest.mark.parametrize("lang, words", [("en", "python3 runs whatever it is handed"),
                                             ("fr", "python3 exécute ce qu'on lui donne")])
    def test_the_text_names_the_binary(self, tool, lang, words):
        i18n.init(lang)
        try:
            res = check_file_perms(self._snap(tool), t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in res.findings)

    def test_explain_cis_and_the_old_advice(self):
        from bob.cis_refs import get_cis_code
        from bob.explain import EXPLAIN_KEYS
        assert "file_perms.nopass_root_equivalent" in EXPLAIN_KEYS
        assert get_cis_code("file_perms.nopass_root_equivalent") == get_cis_code("file_perms.sudoers_nopasswd_all")
        i18n.init("en")
        how = i18n.t("explain.file_perms.sudoers_nopasswd_all.how")
        assert "NOPASSWD: /usr/bin/apt-get" not in how      # apt-get with free arguments is root anyway


class TestNoexecIsEstablished:
    """Found by the external review: NOEXEC depends on sudo's noexec library and
    on a binary that loads it. Measured on Alpine 3.24 (sudo 1.9.17p2): under
    NOEXEC a static busybox ran `sh -c id` as root; the dynamic env ran nothing."""

    @pytest.mark.parametrize("conf, sudo_v, exists, expected", [
        ("Path noexec /opt/sudo/noexec.so\n", "", {"/opt/sudo/noexec.so"}, "/opt/sudo/noexec.so"),
        ("#Path noexec /usr/libexec/sudo/sudo_noexec.so\n",
         "Sudo version 1.9.16p2\nConfigure options: --prefix=/usr --libdir=${prefix}/lib/x86_64-linux-gnu\n",
         {"/usr/libexec/sudo/sudo_noexec.so"}, "/usr/libexec/sudo/sudo_noexec.so"),          # Debian 13
        ("", "Configure options: --prefix=/usr --libexecdir=/usr/lib --mandir=/usr/share/man\n",
         {"/usr/lib/sudo/sudo_noexec.so"}, "/usr/lib/sudo/sudo_noexec.so"),                   # Alpine 3.24
        ("", "Sudo version 1.9.16p2\n", {"/usr/libexec/sudo/sudo_noexec.so"}, None),          # not root
        ("", "Configure options: --prefix=/usr\n", set(), None),                              # no library
    ])
    def test_the_library(self, monkeypatch, conf, sudo_v, exists, expected):
        monkeypatch.setattr(fp, "read_text_capped", lambda *a, **k: conf)
        monkeypatch.setattr(fp, "_run", lambda *a, **k: sudo_v)
        monkeypatch.setattr(fp, "strict_is_file", lambda p: str(p) in exists)
        assert fp._sudo_noexec_library() == expected

    def test_the_library_through_the_real_file_test(self, monkeypatch, tmp_path):
        """Found on the Debian replay: strict_is_file wants a Path, and the
        mocked test above passed a str through — the section crashed on the
        host ("an internal error prevented this check from running")."""
        lib = tmp_path / "sudo_noexec.so"; lib.write_bytes(b"")
        monkeypatch.setattr(fp, "read_text_capped", lambda *a, **k: f"Path noexec {lib}\n")
        assert fp._sudo_noexec_library() == str(lib)
        monkeypatch.setattr(fp, "read_text_capped", lambda *a, **k: f"Path noexec {tmp_path}/absent.so\n")
        assert fp._sudo_noexec_library() is None

    def test_the_snapshot_runs_with_a_noexec_rule(self, monkeypatch, tmp_path):
        """The section end to end, with nothing between it and the file tests."""
        sudoers = tmp_path / "sudoers"
        sudoers.write_text("u ALL=(root) NOPASSWD:NOEXEC: /usr/bin/less /etc/services, /usr/bin/env\n")
        monkeypatch.setattr(fp, "_sudoers_files", lambda: ([sudoers], True))
        lib = tmp_path / "libexec" / "sudo" / "sudo_noexec.so"
        lib.parent.mkdir(parents=True); lib.write_bytes(b"")
        monkeypatch.setattr(fp, "read_text_capped",
                            lambda p, *a, **k: "" if str(p) == "/etc/sudo.conf" else Path(p).read_text())
        monkeypatch.setattr(fp, "_run", lambda *a, **k: f"Configure options: --prefix={tmp_path}\n")
        snap = fp.FilePermsSnapshot.from_system()
        assert snap.sudoers_nopasswd_specific

    @staticmethod
    def _elf(tmp_path, interp):
        import struct
        ph = struct.pack("<IIQQQQQQ", 3 if interp else 1, 0, 0, 0, 0, 0, 0, 0)
        head = (b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
                + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0))
        f = tmp_path / ("dyn" if interp else "static")
        f.write_bytes(head + ph)
        return str(f)

    def test_dynamic_static_and_script(self, tmp_path):
        assert fp._dynamically_linked(self._elf(tmp_path, True))
        assert not fp._dynamically_linked(self._elf(tmp_path, False))
        script = tmp_path / "s.sh"; script.write_text("#!/bin/sh\n")
        assert not fp._dynamically_linked(str(script))
        assert not fp._dynamically_linked(str(tmp_path / "absent"))

    def test_the_snapshot_requires_both(self):
        import inspect
        src = inspect.getsource(fp.FilePermsSnapshot.from_system)
        assert "noexec = noexec and noexec_lib is not None and _dynamically_linked(command.split()[0])" in src


class TestTheSamePowerCountsOnce:
    """Decided by the user after the external review: where NOPASSWD:ALL (or
    doas permit nopass without cmd) already deducts −2, a root-equivalent rule
    is said and deducts nothing more."""

    def _res(self, tool, **extra):
        line = RULE.format(tool=tool)
        found = [(line, c, w, fp._root_equivalent(c)[1]) for c, w in _flagged(line, ALIASES)]
        snap = FilePermsSnapshot(sudoers_nopasswd_specific=[line], nopasswd_root_equivalent=found, **extra)
        return check_file_perms(snap, t=lambda k, **kw: k)

    @pytest.mark.parametrize("extra", [{"sudoers_nopasswd_all": ["u ALL=(ALL) NOPASSWD: ALL"]},
                                       {"doas_nopass_all": ["permit nopass u"]}])
    def test_beside_a_full_grant(self, tool, extra):
        res = self._res(tool, **extra)
        assert any(f.key == "file_perms.nopass_root_equivalent" for f in res.findings)
        keys = [d.key for d in res.deductions]
        assert "file_perms.nopass_root_equivalent" not in keys
        assert sum(d.points for d in res.deductions) == 2

    def test_sudo_all_and_doas_all_keep_theirs_and_this_adds_nothing(self, tool):
        """The policy, written out after the third review: detection stays per
        mechanism (each rule is said); deductions do not add up for the same
        power. NOPASSWD:ALL and doas permit nopass without cmd deduct 2 each,
        as since 0.21.3 (kept by the user); a root-equivalent rule beside
        either deducts nothing — per host, as NOPASSWD:ALL is counted."""
        res = self._res(tool, sudoers_nopasswd_all=["u ALL=(ALL) NOPASSWD: ALL"],
                        doas_nopass_all=["permit nopass u"])
        by_key = {}
        for d in res.deductions:
            by_key[d.key] = by_key.get(d.key, 0) + d.points
        assert by_key == {"file_perms.sudoers_nopasswd_all": 2, "file_perms.doas_nopass_all": 2}
        assert sum(f.key == "file_perms.nopass_root_equivalent" for f in res.findings) == 7

    def test_alone_it_deducts(self, tool):
        assert [d.points for d in self._res(tool).deductions] == [2]


class TestFileWritersAndSudoedit:
    """Found by the fifth review, measured on Debian 13 (24 October 2026): a
    writer with a fixed argument naming a protected path, and sudoedit /
    visudo / vipw, write a root-owned file without a password. `sudo -n
    /usr/bin/tee /etc/sudoers.d/pwn` and `sudo -n /usr/bin/cp x /etc/sudoers.d/y`
    each wrote a sudoers drop-in owned by root; a sudoedit rule on
    /etc/sudoers.d parsed and granted the edit. A writer with a benign fixed
    target, or sudoedit of one, is not flagged (a finite list of paths)."""

    @pytest.mark.parametrize("command, why, what", [
        ("/usr/bin/tee /etc/sudoers.d/pwn", "writes", "/etc/sudoers.d/pwn"),
        ("/usr/bin/cp /home/x /etc/sudoers.d/y", "writes", "/etc/sudoers.d/y"),
        ("/usr/bin/dd of=/etc/shadow", "writes", "/etc/shadow"),
        ("/usr/bin/install -m 0644 /home/x /etc/cron.d/job", "writes", "/etc/cron.d/job"),
        ("/usr/bin/cp /a /root/.ssh/authorized_keys", "writes", "/root/.ssh/authorized_keys"),
        ("/usr/bin/ln -s /evil /etc/systemd/system/x.service", "writes", "/etc/systemd/system/x.service"),
        ("sudoedit /etc/sudoers.d/x", "writes", "/etc/sudoers.d/x"),
        ("sudoedit", "writes", "any file"),
        ("sudo -e /etc/shadow", "writes", "/etc/shadow"),
        ("visudo", "writes", "/etc/sudoers"),
        ("/usr/sbin/visudo -f /etc/sudoers.d/x", "writes", "/etc/sudoers"),
        ("vipw", "writes", "/etc/passwd"),
        ("/usr/bin/tee /var/log/app.log", None, None),        # benign fixed target
        ("/usr/bin/cp /a /b", None, None),
        ("sudoedit /etc/motd", None, None),
        ("/usr/bin/tee", "arguments", "tee"),                 # free: already covered
    ])
    def test_the_measured_cases(self, command, why, what):
        found = fp._root_equivalent(command)
        assert (found[0] if found else None) == why
        if what is not None:
            assert found[1] == what

    @pytest.mark.parametrize("arg, sensitive", [
        ("/etc/sudoers.d/x", True), ("of=/etc/shadow", True), ("/etc/cron.d/j", True),
        ("/var/spool/cron/crontabs/root", True), ("/etc/systemd/system/x", True),
        ("/home/u/.ssh/authorized_keys", True), ("/etc/pam.d/sshd", True),
        ("/var/log/app.log", False), ("/tmp/x", False), ("/home/u/file", False),
    ])
    def test_which_targets_are_sensitive(self, arg, sensitive):
        assert fp._is_sensitive_write_target(arg) is sensitive

    @pytest.mark.parametrize("lang, words", [("en", "writes /etc/sudoers.d/pwn as root"),
                                             ("fr", "écrit /etc/sudoers.d/pwn en root")])
    def test_the_text(self, lang, words):
        line = "u ALL=(root) NOPASSWD: /usr/bin/tee /etc/sudoers.d/pwn"
        snap = FilePermsSnapshot(sudoers_nopasswd_specific=[line],
                                 nopasswd_root_equivalent=[(line, "/usr/bin/tee /etc/sudoers.d/pwn",
                                                            "writes", "/etc/sudoers.d/pwn")])
        i18n.init(lang)
        try:
            res = check_file_perms(snap, t=i18n.t)
        finally:
            i18n.init(lang="en")
        assert any(words in f.message for f in res.findings)


class TestRunasDefault:
    """Found by the third review, measured on Debian 13: with `Defaults
    runas_default=daemon` (or `Defaults:bobesc runas_default=daemon`), `bobesc
    ALL = NOPASSWD: /usr/bin/python3` ran python3 as euid 1, and `-u root` asked
    for the password. A rule with no Runas_Spec is root only where no
    runas_default other than root may govern it."""

    @pytest.mark.parametrize("defaults, user, applies", [
        ("Defaults runas_default=daemon\n", "bobesc", True),
        ("Defaults:bobesc runas_default=daemon\n", "bobesc", True),
        ("Defaults:alice runas_default=daemon\n", "bobesc", False),
        ("Defaults:%wheel runas_default=daemon\n", "bobesc", True),      # group: not resolved
        ("Defaults@web1 runas_default=daemon\n", "bobesc", True),        # host: not resolved
        ('Defaults runas_default="root"\n', "bobesc", False),
        ("Defaults env_reset\n", "bobesc", False),
    ])
    def test_which_defaults_apply(self, defaults, user, applies):
        assert fp._runas_default_may_apply(user, fp._runas_default_overrides([defaults])) is applies

    @pytest.mark.parametrize("line, has", [("u ALL = NOPASSWD: /usr/bin/python3", False),
                                           ("u ALL=(root) NOPASSWD: /usr/bin/python3", True),
                                           ("u ALL = (ALL:ALL) NOPASSWD: /usr/bin/python3", True)])
    def test_the_runas_spec(self, line, has):
        assert fp._has_runas_spec(line) is has

    @pytest.mark.parametrize("defaults, flagged", [("Defaults runas_default=daemon\n", False), ("", True)])
    def test_through_the_snapshot(self, monkeypatch, tmp_path, defaults, flagged):
        sudoers = tmp_path / "sudoers"
        sudoers.write_text(defaults + "bobesc ALL = NOPASSWD: /usr/bin/python3\n")
        monkeypatch.setattr(fp, "_sudoers_files", lambda: ([sudoers], True))
        monkeypatch.setattr(fp, "_run", lambda *a, **k: "")
        snap = fp.FilePermsSnapshot.from_system()
        assert bool(snap.nopasswd_root_equivalent) is flagged
        assert snap.sudoers_nopasswd_specific          # still a NOPASSWD rule, said as such
