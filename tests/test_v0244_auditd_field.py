"""v0.24.4 — auditd as the oracle saw it on a Raspberry Pi and on Alpine.

Each case was measured against the audit log itself (a write to /etc/shadow
journals a SYSCALL record under the rule's key) or against ``auditctl -s``:

- A watch on the whole of ``/etc/`` and the syscall form of a watch
  (``-a always,exit … -F path=/etc/shadow -F perm=wa``) both journalled the
  write; BOB said the sensitive files were unwatched (WARN −1 on a server).
- ``-e 2`` locks the rules until the next boot: BOB's fix wrote its rules file,
  ``augenrules --load`` said "immutable mode - exiting with no changes" with
  exit status 0, the finding came back, and the reboot loaded the rules.
- On Alpine (OpenRC, no systemctl), with the rules locked, auditd was running
  and BOB said it was not: the fallback read ``enabled 2`` as stopped. Its fix
  was ``sudo systemctl enable --now auditd`` on a host with neither.
"""

from __future__ import annotations

import pytest

from bob.checks import _run, auditd
from bob.checks.auditd import AuditdSnapshot, _covered, _parse_watched_files, check_auditd
from tests.helpers import _keys, _t

# `auditctl -l` on the Pi (armv6, b32) for the syscall form, verbatim but for the syscall list.
_SYSCALL_FORM = (
    "-a always,exit -F arch=b32 -S open,creat,openat -F path=/etc/passwd -F perm=wa -F key=sens\n"
    "-a always,exit -F arch=b32 -S open,creat,openat -F path=/etc/shadow -F perm=wa -F key=sens\n"
    "-a always,exit -F arch=b32 -S open,creat,openat -F path=/etc/sudoers -F perm=wa -F key=sens\n")
# `auditctl -s` on Alpine 3.24 after `auditctl -e 2`.
_LOCKED_STATUS = "enabled 2\nfailure 1\npid 2825\nrate_limit 0\nbacklog_limit 8192\n"


def _snap(watched, rules=3, **kw):
    return AuditdSnapshot(installed=True, service_active=True, watched_files=set(watched),
                          rule_count=rules, **kw)


class TestCoverage:
    def test_a_directory_watch_covers_the_files_under_it(self):
        assert _parse_watched_files("-w /etc -p wa -k etcdir\n") == {"/etc"}
        result = check_auditd(_snap({"/etc"}, rules=1), t=_t, profile_name="server")
        assert "auditd.sensitive_files_watched" in _keys(result)
        assert not result.deductions

    def test_the_syscall_form_is_a_watch(self):
        assert _parse_watched_files(_SYSCALL_FORM) == {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

    def test_a_dir_field_is_a_watch(self):
        assert _parse_watched_files("-a always,exit -F dir=/etc/sudoers.d/ -F perm=wa\n") == {"/etc/sudoers.d"}

    def test_a_partial_watch_still_names_what_is_missing(self):
        result = check_auditd(_snap({"/etc/shadow"}, rules=1), t=_t, profile_name="server")
        assert "auditd.missing_sensitive_rules" in _keys(result)

    def test_a_shared_prefix_is_not_a_directory(self):
        assert not _covered("/etc/shadow", {"/etc/sha"})


class TestLockedRules:
    def test_the_lock_is_said_and_no_reload_is_handed_out(self):
        result = check_auditd(_snap({"/etc/passwd"}, rules=1, immutable=True), t=_t, profile_name="server")
        assert "auditd.immutable" in _keys(result)
        finding = next(f for f in result.findings if f.key == "auditd.missing_sensitive_rules")
        assert "augenrules --load" not in finding.cmd
        assert "99-sensitive.rules" in finding.cmd

    def test_unlocked_rules_are_reloaded(self):
        result = check_auditd(_snap({"/etc/passwd"}, rules=1), t=_t, profile_name="server")
        finding = next(f for f in result.findings if f.key == "auditd.missing_sensitive_rules")
        assert finding.cmd.endswith("&& sudo augenrules --load")
        assert "auditd.immutable" not in _keys(result)

    def test_no_rules_while_locked(self):
        result = check_auditd(_snap(set(), rules=0, immutable=True), t=_t, profile_name="server")
        finding = next(f for f in result.findings if f.key == "auditd.no_rules")
        assert "augenrules" not in finding.cmd and "hardening.rules" in finding.cmd

    def test_the_detail_says_reboot(self):
        from bob import i18n
        i18n.init("en")
        result = check_auditd(_snap({"/etc/passwd"}, rules=1, immutable=True), t=i18n.t, profile_name="server")
        finding = next(f for f in result.findings if f.key == "auditd.missing_sensitive_rules")
        assert "next boot" in finding.detail


class TestServiceStateWithoutSystemd:
    @pytest.fixture
    def host(self, monkeypatch):
        def build(unit_state, status):
            monkeypatch.setattr(auditd, "_command_exists", lambda c: c == "auditctl")
            monkeypatch.setattr(auditd, "unit_active_state", lambda name: unit_state)
            monkeypatch.setattr(auditd, "_run", lambda *a, **k: status if a[:2] == ("auditctl", "-s") else "")
            monkeypatch.setattr(auditd, "run_result",
                                lambda *a, **k: _run.CommandResult("-w /etc/passwd -p wa -k identity\n", True, "", 0))
            return AuditdSnapshot.from_system()
        return build

    def test_locked_is_running(self, host):
        snap = host(None, _LOCKED_STATUS)
        assert (snap.service_active, snap.immutable) == (True, True)

    def test_openrc_answers_without_systemctl(self, host):
        assert host("active", "").service_active is True

    def test_locked_with_no_daemon_is_stopped(self, host):
        """Measured on a Fedora 43 VM: ``auditctl -e 2``, then auditd killed —
        ``auditctl -s`` still said "enabled 2", with "pid 0"."""
        snap = host(None, "enabled 2\nfailure 1\npid 0\nrate_limit 0\nbacklog_limit 8192\n")
        assert (snap.service_active, snap.immutable) == (False, True)

    def test_an_auditctl_without_a_pid_line_falls_back_on_enabled(self, host):
        assert host(None, "enabled 1\n").service_active is True

    def test_enabled_0_is_stopped(self, host):
        assert host(None, "enabled 0\npid 0\n").service_active is False


class TestTheEnableFixFollowsTheInit:
    @pytest.fixture
    def openrc(self, monkeypatch):
        monkeypatch.setattr(_run, "openrc_available", lambda: True)
        monkeypatch.setattr(_run, "_command_exists", lambda c: c != "systemctl")

    def test_auditd(self, openrc):
        snap = AuditdSnapshot(installed=True, service_active=False)
        finding = next(f for f in check_auditd(snap, t=_t).findings if f.key == "auditd.service_inactive")
        assert finding.cmd == "sudo rc-update add auditd default && sudo rc-service auditd start"

    def test_fail2ban(self, openrc):
        from bob.checks.fail2ban import Fail2banSnapshot, check_fail2ban
        finding = next(f for f in check_fail2ban(Fail2banSnapshot(installed=True, service_active=False), t=_t).findings
                       if f.key == "fail2ban.service_inactive")
        assert finding.cmd.startswith("sudo rc-update add fail2ban default")

    def test_apparmor_uses_the_helper(self):
        import inspect

        from bob.checks import mac_policy
        assert 'cmd=service_enable_cmd("apparmor")' in inspect.getsource(mac_policy)


class TestOnlyRulesThatJournalAWriteCount:
    """Measured on Alpine 3.24 (x86_64), each form applied to the three
    sensitive files, then ``: >> /etc/shadow`` and the audit log counted:
    N1/N2/N3/N6 journalled nothing and BOB had said "watched"; N4/N5 journalled
    the write."""

    @pytest.mark.parametrize("rule", [
        "-w /etc/shadow -p r -k n1",                                                     # N1
        "-a never,exit -F arch=b64 -S open,openat -F path=/etc/shadow -F perm=wa -F key=n2",  # N2
        "-a always,exit -F arch=b32 -S open,openat -F path=/etc/shadow -F perm=wa -F key=n3", # N3
        "-a always,exit -F arch=b64 -S openat -F path=/etc/shadow -F key=n6",            # N6
    ])
    def test_rules_that_journal_nothing_do_not_count(self, rule):
        assert _parse_watched_files(rule + "\n", native_arch="b64") == set()

    @pytest.mark.parametrize("rule", [
        "-a always,exit -F arch=b64 -S open,openat -F path=/etc/shadow -F perm=wa -F key=n4",  # N4
        "-w /etc/shadow -p wa -k n5",                                                    # N5
        "-w /etc/shadow -k n7",                                                          # no -p: rwxa
    ])
    def test_rules_that_journal_the_write_count(self, rule):
        assert _parse_watched_files(rule + "\n", native_arch="b64") == {"/etc/shadow"}

    def test_the_native_arch_follows_the_kernel(self, monkeypatch):
        import os as _os
        monkeypatch.setattr(auditd.os, "uname", lambda: _os.uname_result(("Linux", "h", "6", "#1", "armv6l")))
        assert auditd._native_arch() == "b32"
        monkeypatch.setattr(auditd.os, "uname", lambda: _os.uname_result(("Linux", "h", "6", "#1", "x86_64")))
        assert auditd._native_arch() == "b64"

    def test_the_snapshot_passes_the_arch(self):
        import inspect
        assert "_parse_watched_files(rules_out, _native_arch(), _compat_arch())" in inspect.getsource(AuditdSnapshot.from_system)


class TestBothArchitecturesOnA64BitKernel:
    """Measured on a Fedora 43 x86_64 VM (``CONFIG_IA32_EMULATION=y``): each rule
    set on /etc/shadow, then a write from a 64-bit shell and from a static
    i386 binary (``open(O_WRONLY|O_APPEND)``), the audit log counted:

    ======================================  ======  ======
    rules                                   64-bit  32-bit
    ======================================  ======  ======
    ``-w /etc/shadow -p wa``                1       1
    ``arch=b64`` only                       1       0
    ``arch=b32`` only                       0       1
    ``arch=b64`` and ``arch=b32``           1       1
    ``-S open,openat``, no ``arch``         1       0
    ======================================  ======  ======

    BOB had called the file watched with ``arch=b64`` alone.
    """

    _B64 = "-a always,exit -F arch=b64 -S open,openat -F path=/etc/shadow -F perm=wa -F key=k\n"
    _B32 = _B64.replace("b64", "b32")
    _NO_ARCH = "-a always,exit -S open,openat -F path=/etc/shadow -F perm=wa -F key=k\n"

    @pytest.mark.parametrize("rules, watched", [
        ("-w /etc/shadow -p wa -k k\n", True),
        (_B64, False),
        (_B32, False),
        (_B64 + _B32, True),
        (_NO_ARCH, False),
    ])
    def test_a_kernel_that_runs_32_bit_programs(self, rules, watched):
        assert (_parse_watched_files(rules, native_arch="b64", compat_arch="b32") == {"/etc/shadow"}) is watched

    @pytest.mark.parametrize("rules", [_B64, _NO_ARCH])
    def test_a_kernel_that_does_not(self, rules):
        assert _parse_watched_files(rules, native_arch="b64", compat_arch=None) == {"/etc/shadow"}

    @pytest.fixture
    def kernel(self, monkeypatch):
        import os as _os

        def build(machine="x86_64", config=None, cmdline=""):
            monkeypatch.setattr(auditd.os, "uname", lambda: _os.uname_result(("Linux", "h", "6", "#1", machine)))
            monkeypatch.setattr(auditd, "_kernel_config", lambda: config)
            monkeypatch.setattr(auditd, "read_text_capped", lambda path, **kw: cmdline)
            return auditd._compat_arch()
        return build

    @pytest.mark.parametrize("kw, expected", [
        (dict(config=None), "b32"),                                            # unreadable: not credited
        (dict(config="CONFIG_IA32_EMULATION=y\n"), "b32"),                     # Fedora 43, Ubuntu
        (dict(config="# CONFIG_IA32_EMULATION is not set\n"), None),
        (dict(config="CONFIG_IA32_EMULATION=y\n", cmdline="ro ia32_emulation=0"), None),
        (dict(config="CONFIG_IA32_EMULATION=y\nCONFIG_IA32_EMULATION_DEFAULT_DISABLED=y\n"), None),
        (dict(config="CONFIG_IA32_EMULATION=y\nCONFIG_IA32_EMULATION_DEFAULT_DISABLED=y\n",
              cmdline="ia32_emulation=true"), "b32"),
        (dict(machine="aarch64", config="CONFIG_COMPAT=y\n"), "b32"),           # 32-bit userland on arm64
        (dict(machine="aarch64", config="# CONFIG_COMPAT is not set\n"), None),
        (dict(machine="armv6l", config="CONFIG_COMPAT=y\n"), None),             # a 32-bit kernel has no compat ABI
    ])
    def test_does_this_kernel_run_32_bit_programs(self, kernel, kw, expected):
        assert kernel(**kw) == expected


class TestAFilterThatNarrowsTheRule:
    """Measured on a Fedora 43 VM, path, perm and both arches right, one more
    filter, then a write from a login's root shell (auid 1000) and one from a
    system service (auid unset):

    =============================  =====  =======
    extra filter                   login  service
    =============================  =====  =======
    none                           1      1
    ``success=0``                  0      0
    ``auid>=1000 auid!=unset``     1      0
    ``exe=/usr/bin/vi``            0      0
    =============================  =====  =======

    BOB had called the file watched in every row."""

    @staticmethod
    def _pair(extra):   # `auditctl -l` as printed on the VM
        return "".join(f"-a always,exit -F arch={a} -F path=/etc/shadow -F perm=wa {extra}-F key=f\n"
                       for a in ("b64", "b32"))

    def test_no_extra_filter_counts(self):
        assert _parse_watched_files(self._pair(""), "b64", "b32") == {"/etc/shadow"}

    @pytest.mark.parametrize("extra", ["-F success=0 ", "-F auid>=1000 -F auid!=-1 ", "-F exe=/usr/bin/vi ",
                                       "-C auid!=uid "])
    def test_a_narrowing_filter_does_not_count(self, extra):
        assert _parse_watched_files(self._pair(extra), "b64", "b32") == set()


class TestASyscallListWithPerm:
    """Measured on a Fedora 43 VM: ``-a always,exit -F arch=b64 -S openat
    -F path=/etc/shadow -F perm=wa`` (and its b32 twin) is loaded with the whole
    write/attribute class — ``auditctl -l`` prints the list below whatever ``-S``
    named — and an open for append, a truncate to the same size and a chmod to
    the same mode were each journalled. A ``-S`` beside ``perm`` narrows nothing;
    this pins that BOB reads the loaded rule, as printed, as coverage."""

    _LOADED = ("-a always,exit -F arch={a} -S open,bind,truncate,ftruncate,rename,mkdir,rmdir,creat,link,"
               "unlink,symlink,chmod,fchmod,chown,fchown,lchown,mknod,acct,swapon,quotactl,setxattr,"
               "lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,openat,mkdirat,mknodat,fchownat,"
               "unlinkat,renameat,linkat,symlinkat,fchmodat,fallocate,renameat2,openat2,setxattrat,"
               "removexattrat -F path=/etc/shadow -F perm=wa -F key=sopenat\n")

    def test_the_loaded_rule_counts(self):
        rules = self._LOADED.format(a="b64") + self._LOADED.format(a="b32")
        assert _parse_watched_files(rules, "b64", "b32") == {"/etc/shadow"}
