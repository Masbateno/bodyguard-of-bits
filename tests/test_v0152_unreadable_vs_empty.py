"""v0.15.2 — a command that could not run must never read as "nothing found".

``_run`` returns stdout and drops the exit status, so a refused, absent or
failing binary hands the caller an empty string — exactly what a healthy
command with nothing to report returns. Five checks turned that silence into
an affirmative statement about the host: "0 listening ports detected", "no
IPv6 listeners", "0 established connections", "not actively listening", "no
timers". On a machine with 34 open sockets, removing ``ss`` from PATH was
enough to produce all of them at once.

These tests pin the distinction at the primitive and at each of the five
verdicts that depended on it.
"""

import pytest

from bob.checks._run import CommandResult, _run, run_result


class TestRunResultPrimitive:
    """The primitive that makes failure visible to callers."""

    def test_success_reports_ok(self):
        assert run_result("echo", "hello") == CommandResult("hello\n", True)

    def test_non_zero_exit_is_not_ok(self):
        assert run_result("false").ok is False

    def test_absent_binary_is_not_ok(self):
        result = run_result("bob-no-such-binary-anywhere")
        assert result == CommandResult("", False)

    def test_failure_stdout_is_indistinguishable_from_silence(self):
        """The very ambiguity that motivates the flag: stdout alone cannot tell."""
        assert run_result("false").stdout == run_result("true").stdout == ""

    def test_run_keeps_its_contract(self):
        """`_run` still returns bare stdout — 50-odd call sites depend on it."""
        assert _run("echo", "hi") == "hi\n"
        assert _run("false") == ""
        assert _run("bob-no-such-binary-anywhere") == ""


class TestListeningPortsUnreadable:
    """`ss` absent must not become "0 listening ports detected"."""

    def _snapshot(self, *, readable):
        from bob.checks.ports import PortsSnapshot
        return PortsSnapshot(ports=[], ufw_rules="", ss_output="",
                             ports_readable=readable)

    def test_unreadable_reports_the_gap(self):
        from bob.checks.ports import check_ports
        keys = {f.key for f in check_ports(self._snapshot(readable=False)).findings}
        assert keys == {"ports.unreadable"}

    def test_readable_and_empty_is_not_reported_as_unreadable(self):
        from bob.checks.ports import check_ports
        keys = {f.key for f in check_ports(self._snapshot(readable=True)).findings}
        assert "ports.unreadable" not in keys

    def test_default_assumes_readable(self):
        """Existing constructions keep their meaning."""
        assert self._snapshot(readable=True).ports_readable is True


class TestIPv6ListenersUnknown:
    """"No IPv6 listeners" is a claim; it needs `ss` to have answered."""

    def _snapshot(self, *, readable):
        from bob.checks.ipv6 import IPv6Snapshot
        return IPv6Snapshot(
            kernel_ipv6_enabled=True, ufw_ipv6_enabled=False,
            ipv6_listeners=[], listeners_readable=readable,
        )

    def test_unreadable_does_not_claim_no_listeners(self):
        from bob.checks.ipv6 import check_ipv6
        keys = {f.key for f in check_ipv6(self._snapshot(readable=False)).findings}
        assert "ipv6.ufw_disabled_no_listeners" not in keys
        assert "ipv6.listeners_unknown" in keys

    def test_readable_and_empty_still_says_no_listeners(self):
        from bob.checks.ipv6 import check_ipv6
        keys = {f.key for f in check_ipv6(self._snapshot(readable=True)).findings}
        assert "ipv6.ufw_disabled_no_listeners" in keys


class TestSystemdTimersUnreadable:
    """A refused `list-timers` prints nothing, like a host with no timers."""

    def _snapshot(self, *, readable):
        from bob.checks.systemd_timers import SystemdTimersSnapshot
        return SystemdTimersSnapshot(timer_count=0, systemctl_available=True,
                                     timers_readable=readable)

    def test_unreadable_does_not_claim_no_timers(self):
        from bob.checks.systemd_timers import check_systemd_timers
        keys = {f.key for f in check_systemd_timers(self._snapshot(readable=False)).findings}
        assert "systemd_timers.no_timers" not in keys
        assert "systemd_timers.unreadable" in keys

    def test_readable_and_empty_still_says_no_timers(self):
        from bob.checks.systemd_timers import check_systemd_timers
        keys = {f.key for f in check_systemd_timers(self._snapshot(readable=True)).findings}
        assert "systemd_timers.no_timers" in keys


class TestExposureSummary:
    """The summary box is the line most operators read; it must not tick green."""

    class _Ports:
        def __init__(self, readable):
            self.ports = []
            self.ports_readable = readable

    def _items(self, readable):
        from bob.exposure import compute_exposure
        from bob.scoring import ScoreEngine
        return compute_exposure(
            ScoreEngine(), self._Ports(readable),
            fw_active=True, fw_policy="deny", network_context="local",
            t=lambda k, **kw: k,
        )

    def _open_ports_item(self, readable):
        return next(i for i in self._items(readable)
                    if i.label == "exposure.open_ports")

    def test_unreadable_is_not_a_green_tick(self):
        item = self._open_ports_item(readable=False)
        assert item.icon != "✔"
        assert item.color != "ok"
        assert item.detail == "exposure.open_ports_unknown"

    def test_readable_and_empty_is_still_a_green_tick(self):
        item = self._open_ports_item(readable=True)
        assert item.icon == "✔"
        assert item.color == "ok"


class TestServicesListeningSetUnknown:
    """`None` is the services check's own encoding for "listening set unknown".

    The runner used to hand over an empty set whatever `ss` had done, so every
    registry port was declared "not actively listening" on a host whose sockets
    had never been read.
    """

    def _exposures(self, all_listening_ports):
        """Exposures for one installed service, with the host held out.

        Every system probe is stubbed: the verdict under test must depend on
        `all_listening_ports` alone, not on whether the machine running the
        suite happens to have openssh-server installed.
        """
        from unittest.mock import patch

        from bob.checks.services import ServiceSnapshot, ServiceState
        from bob.registry import Detection, Service

        service = Service(
            id="ssh", label="SSH Server", packages=("openssh-server",),
            services=("ssh",), ports=("22/tcp",), risk="high",
            config_key="fixed",
            detection=Detection(binary=(), snap=(), config_files=()),
        )
        with (
            patch("bob.checks.services._detect_installation",
                  return_value=(True, "dpkg")),
            patch("bob.checks.services._detect_state",
                  return_value=ServiceState.ACTIVE_ENABLED),
            patch("bob.checks.services._resolve_ports",
                  return_value=["22/tcp"]),
        ):
            snap = ServiceSnapshot._build_snapshot(
                service, ufw_rules="", loopback_ports=set(),
                all_listening_ports=all_listening_ports,
            )
        return snap.exposures

    def test_empty_set_means_the_port_is_not_listening(self):
        from bob.checks.services import Exposure
        assert self._exposures(set()).get("22/tcp") is Exposure.NOT_LISTENING

    def test_none_withholds_the_verdict_instead(self):
        from bob.checks.services import Exposure
        assert self._exposures(None).get("22/tcp") is not Exposure.NOT_LISTENING


class TestLocaleParity:
    """Every new key exists in both locales — the bracketed-fallback guard."""

    @pytest.mark.parametrize("dotted", [
        "ports.unreadable",
        "ports.unreadable_detail",
        "ipv6.listeners_unknown",
        "ipv6.listeners_unknown_detail",
        "network_context.connections_unknown",
        "exposure.open_ports_unknown",
        "systemd_timers.unreadable",
        "systemd_timers.unreadable_detail",
    ])
    def test_key_present_in_both_locales(self, dotted):
        import json
        from pathlib import Path
        for locale in ("en", "fr"):
            data = json.loads(
                (Path("bob/locales") / f"{locale}.json").read_text(encoding="utf-8")
            )
            node = data
            for part in dotted.split("."):
                assert part in node, f"{locale}.json is missing {dotted}"
                node = node[part]
            assert isinstance(node, str) and node.strip()


# ---------------------------------------------------------------------------
# The same class, three angles the first sweep did not cover:
#   1. the alarm direction — a blinded tool inventing a problem
#   2. a command that succeeds but says nothing usable
#   3. files, not commands
# ---------------------------------------------------------------------------

class TestUnitStatePrimitive:
    """`is_unit_active` collapsed "inactive" with "could not ask systemd"."""

    def test_reports_a_real_state(self):
        from unittest.mock import patch

        from bob.checks import _run as mod
        with patch.object(mod, "run_result",
                          return_value=CommandResult("active\n", True)):
            assert mod.unit_active_state("whatever") == "active"

    def test_inactive_is_an_answer_despite_the_non_zero_exit(self):
        """`systemctl is-active` exits non-zero to *report* an inactive unit."""
        from unittest.mock import patch

        from bob.checks import _run as mod
        with patch.object(mod, "run_result",
                          return_value=CommandResult("inactive\n", False)):
            assert mod.unit_active_state("whatever") == "inactive"

    def test_no_output_is_not_an_answer(self):
        from unittest.mock import patch

        from bob.checks import _run as mod
        with patch.object(mod, "run_result", return_value=CommandResult("", False)):
            assert mod.unit_active_state("whatever") is None

    def test_output_systemd_would_never_print_is_not_an_answer(self):
        """A wrapper, a stub or a mangled stream is not a state."""
        from unittest.mock import patch

        from bob.checks import _run as mod
        with patch.object(mod, "run_result",
                          return_value=CommandResult("\xc3(  garbage\n", True)):
            assert mod.unit_active_state("whatever") is None

    def test_is_unit_active_keeps_its_contract(self):
        from unittest.mock import patch

        from bob.checks import _run as mod
        for out, expected in (("active", True), ("inactive", False), ("", False)):
            with patch.object(mod, "run_result",
                              return_value=CommandResult(out, out == "active")):
                assert mod.is_unit_active("whatever") is expected


class TestSSHServiceStateUnknown:
    """A running sshd was warned about as "installed but not running"."""

    def _findings(self, *, known, active):
        from bob.checks.ssh import SSHSnapshot, check_ssh
        snap = SSHSnapshot(sshd_installed=True, sshd_active=active,
                           sshd_active_known=known)
        return {f.key for f in check_ssh(snap).findings}

    def test_unknown_state_does_not_warn(self):
        keys = self._findings(known=False, active=False)
        assert "ssh.not_active" not in keys
        assert "ssh.active_unknown" in keys

    def test_known_inactive_still_warns(self):
        assert "ssh.not_active" in self._findings(known=True, active=False)

    def test_known_active_still_reports_ok(self):
        assert "ssh.active" in self._findings(known=True, active=True)


class TestFirewallDriversGarbage:
    """Exit status alone let unparseable output earn a clean bill of health."""

    def _keys(self, input_out):
        from bob.checks.firewall_stack import FirewallStackSnapshot, check_firewall_stack
        snap = FirewallStackSnapshot(rules_readable=bool(input_out))
        return {f.key for f in check_firewall_stack(snap).findings}

    def test_chain_header_is_what_makes_a_listing_readable(self):
        from bob.checks.firewall_stack import _IPTABLES_CHAIN_RE
        assert _IPTABLES_CHAIN_RE.search("Chain INPUT (policy ACCEPT)\n")
        assert not _IPTABLES_CHAIN_RE.search("\xc3(  garbage\n=== unexpected ===\n")
        assert not _IPTABLES_CHAIN_RE.search("")

    def test_unreadable_withholds_the_all_clear(self):
        keys = self._keys(input_out="")
        assert "firewall_drivers.no_issues" not in keys
        assert "firewall_drivers.rules_unreadable" in keys


class TestSudoersUnreadable:
    """"No risky sudo rule" is a claim about a file that must have been read."""

    def _keys(self, *, readable):
        from bob.checks.file_perms import FilePermsSnapshot, check_file_perms
        return {f.key for f in
                check_file_perms(FilePermsSnapshot(sudoers_readable=readable)).findings}

    def test_unreadable_is_reported_and_suppresses_the_all_clear(self):
        keys = self._keys(readable=False)
        assert "file_perms.sudoers_unreadable" in keys
        assert "file_perms.ok" not in keys

    def test_readable_and_clean_still_reports_all_clear(self):
        assert "file_perms.ok" in self._keys(readable=True)


class TestPasswdUnreadable:
    """The UID 0 scan finding nothing must mean it looked."""

    def _keys(self, *, readable):
        from bob.checks.user_accounts import UserAccountsSnapshot, check_user_accounts
        snap = UserAccountsSnapshot(passwd_readable=readable, shadow_readable=True)
        return {f.key for f in check_user_accounts(snap).findings}

    def test_unreadable_is_reported_and_suppresses_the_all_clear(self):
        keys = self._keys(readable=False)
        assert "user_accounts.no_passwd" in keys
        assert "user_accounts.ok" not in keys

    def test_readable_and_clean_still_reports_all_clear(self):
        assert "user_accounts.ok" in self._keys(readable=True)


class TestUmaskSourcesUnreadable:
    """umask files are last-one-wins; one that never opened may hold the value."""

    def _keys(self, unreadable):
        from bob.checks.umask import UmaskSnapshot, check_umask
        snap = UmaskSnapshot(umask_value="022", source="/etc/login.defs",
                             all_sources={"/etc/login.defs": "022"},
                             unreadable_sources=unreadable)
        return {f.key for f in check_umask(snap).findings}

    def test_an_unreadable_source_withholds_the_ok(self):
        keys = self._keys(["/etc/profile"])
        assert "umask.ok" not in keys
        assert "umask.sources_unreadable" in keys

    def test_all_sources_read_still_reports_ok(self):
        assert "umask.ok" in self._keys([])


class TestSshdConfigUnreadable:
    """Unread directives fall back to OpenSSH's defaults, not to this host."""

    def _keys(self, *, readable):
        from bob.checks.ssh import SSHSnapshot, check_ssh
        snap = SSHSnapshot(sshd_installed=True, sshd_active=True,
                           sshd_active_known=True, sshd_config={},
                           sshd_config_readable=readable)
        return {f.key for f in check_ssh(snap).findings}

    def test_unreadable_config_asserts_nothing_about_root_login(self):
        keys = self._keys(readable=False)
        assert "ssh.config_unreadable" in keys
        assert "ssh.permit_root_login_restricted" not in keys
        assert "ssh.permit_root_login" not in keys

    def test_readable_config_still_applies_the_defaults(self):
        """An empty but readable config genuinely means OpenSSH's defaults."""
        assert "ssh.permit_root_login_restricted" in self._keys(readable=True)


class TestExposureSshUnknown:
    """The summary box must not tick green off unread directives."""

    def _ssh_item(self, keys):
        """Drive compute_exposure off a real engine carrying *keys* as INFO."""
        from bob.exposure import compute_exposure
        from bob.scoring import CheckResult, ScoreEngine

        class _Ports:
            ports = []
            ports_readable = True

        result = CheckResult()
        for key in keys:
            result.info(message=key, key=key)
        engine = ScoreEngine()
        engine.apply(result)
        items = compute_exposure(
            engine, _Ports(), fw_active=True, fw_policy="deny",
            network_context="local", t=lambda k, **kw: k,
        )
        return next(i for i in items if i.label == "exposure.ssh")

    def test_unreadable_config_is_not_a_green_tick(self):
        item = self._ssh_item({"ssh.config_unreadable"})
        assert item.icon != "✔"
        assert item.detail == "exposure.ssh_config_unknown"


class TestNewLocaleKeys:
    @pytest.mark.parametrize("dotted", [
        "ssh.active_unknown", "ssh.active_unknown_detail",
        "ssh.config_unreadable", "ssh.config_unreadable_detail",
        "file_perms.sudoers_unreadable", "file_perms.sudoers_unreadable_detail",
        "user_accounts.no_passwd", "user_accounts.no_passwd_detail",
        "umask.sources_unreadable", "umask.sources_unreadable_detail",
        "exposure.ssh_config_unknown",
    ])
    def test_key_present_in_both_locales(self, dotted):
        import json
        from pathlib import Path
        for locale in ("en", "fr"):
            data = json.loads(
                (Path("bob/locales") / f"{locale}.json").read_text(encoding="utf-8")
            )
            node = data
            for part in dotted.split("."):
                assert part in node, f"{locale}.json is missing {dotted}"
                node = node[part]
            assert isinstance(node, str) and node.strip()


# ---------------------------------------------------------------------------
# Found by enumerating every config path the checks read, rather than by
# picking a handful by hand — which is how the first pass missed these.
# ---------------------------------------------------------------------------

class TestSambaConfigParserSilentSkip:
    """`RawConfigParser.read` skips a file it cannot open, and says nothing.

    samba.py already had a `conf_readable` flag and a check guarding on it, but
    the guard was inert: the parser never raised, so an unreadable smb.conf
    became an empty config, every setting fell back to its default, and the
    host was told SMB1 was disabled by a parser that had read nothing.
    """

    def test_unreadable_file_raises_instead_of_parsing_to_nothing(self, tmp_path):
        from bob.checks.samba import _read_smb_conf
        missing = tmp_path / "not-there.conf"
        with pytest.raises(OSError):
            _read_smb_conf(missing)

    def test_a_real_file_still_parses(self, tmp_path):
        from bob.checks.samba import _read_smb_conf
        conf = tmp_path / "smb.conf"
        conf.write_text("[global]\n   min protocol = SMB2\n")
        assert _read_smb_conf(conf)["global"]["min protocol"] == "SMB2"

    def test_check_withholds_every_verdict_when_conf_unread(self):
        from bob.checks.samba import SambaSnapshot, check_samba
        snap = SambaSnapshot(installed=True, daemon_installed=True,
                             conf_readable=False)
        keys = {f.key for f in check_samba(snap).findings}
        assert "samba.conf_unreadable" in keys
        assert "samba.smb1_disabled" not in keys
        assert "samba.null_passwords_ok" not in keys


class TestProfileConfigParserSilentSkip:
    """The same parser trap in profiles.py: a profile that quietly empties."""

    def test_unreadable_profile_raises(self, tmp_path):
        from bob.profiles import _load_from_path
        with pytest.raises(OSError):
            _load_from_path(tmp_path / "not-there.conf", depth=0)

    def test_load_profile_falls_back_rather_than_crashing(self):
        """`load_profile` catches everything — the raise must not escape."""
        from bob.profiles import load_profile
        assert load_profile("definitely-not-a-real-profile") is not None


class TestCronFilesUnreadable:
    """A cron file that never opened cannot support "no risky cron job"."""

    def _keys(self, unreadable):
        from bob.checks.cron_audit import CronAuditSnapshot, check_cron_audit
        snap = CronAuditSnapshot(unreadable_files=unreadable)
        return {f.key for f in check_cron_audit(snap).findings}

    def test_unreadable_file_withholds_the_all_clear(self):
        keys = self._keys(["/etc/cron.d/something"])
        assert "cron.unreadable_files" in keys
        assert "cron.ok" not in keys

    def test_everything_read_still_reports_all_clear(self):
        assert "cron.ok" in self._keys([])

    def test_a_security_skip_is_not_a_read_failure(self, tmp_path):
        """`_read_cron_file` reports success for a path it declines to follow."""
        from unittest.mock import patch

        from bob.checks import cron_audit as mod
        target = tmp_path / "whatever"
        target.write_text("* * * * * root true\n")
        out: list = []
        with patch.object(mod, "_is_safe_config_path", return_value=False):
            assert mod._read_cron_file(target, out) is True
        assert out == []


class TestJournaldConfUnreadable:
    """Storage='' means "unset", which journald reads as its persistent default."""

    def _keys(self, *, readable, storage=""):
        from bob.checks.log_rotation import LogRotationSnapshot, check_log_rotation
        snap = LogRotationSnapshot(
            journald_active=True, journald_storage=storage,
            journal_persistent=True, journald_conf_readable=readable,
        )
        return {f.key for f in check_log_rotation(snap).findings}

    def test_unread_conf_does_not_certify_persistence(self):
        keys = self._keys(readable=False)
        assert "log_rotation.journald_persistent" not in keys
        assert "log_rotation.journald_conf_unreadable" in keys

    def test_read_conf_with_storage_unset_still_certifies(self):
        assert "log_rotation.journald_persistent" in self._keys(readable=True)

    def test_an_explicit_value_is_trusted_even_if_the_file_reread_fails(self):
        """A value already parsed is knowledge; only the inferred default is not."""
        keys = self._keys(readable=False, storage="persistent")
        assert "log_rotation.journald_persistent" in keys


class TestBatchThreeLocaleKeys:
    @pytest.mark.parametrize("dotted", [
        "cron.unreadable_files", "cron.unreadable_files_detail",
        "log_rotation.journald_conf_unreadable",
        "log_rotation.journald_conf_unreadable_detail",
    ])
    def test_key_present_in_both_locales(self, dotted):
        import json
        from pathlib import Path
        for locale in ("en", "fr"):
            data = json.loads(
                (Path("bob/locales") / f"{locale}.json").read_text(encoding="utf-8")
            )
            node = data
            for part in dotted.split("."):
                assert part in node, f"{locale}.json is missing {dotted}"
                node = node[part]
            assert isinstance(node, str) and node.strip()


# ---------------------------------------------------------------------------
# Directories, and the exists() trap underneath them
# ---------------------------------------------------------------------------

class TestPathExistsNeverRaises:
    """`Path.exists()` looks total but re-raises EACCES.

    It swallows only ENOENT, ENOTDIR, EBADF and ELOOP. A config file under a
    directory the auditor cannot traverse therefore raised PermissionError —
    and from an unguarded core collection (a service's port auto-detection)
    that aborted the entire audit: no report, no findings, exit 3.
    """

    def test_absent_path_is_false(self, tmp_path):
        from bob.checks._run import path_exists
        assert path_exists(tmp_path / "nope") is False

    def test_present_path_is_true(self, tmp_path):
        from bob.checks._run import path_exists
        target = tmp_path / "yes"
        target.write_text("")
        assert path_exists(target) is True

    def test_permission_error_is_false_rather_than_an_exception(self):
        from pathlib import Path
        from unittest.mock import patch

        from bob.checks._run import path_exists
        target = Path("/nonexistent/whatever")
        with patch.object(Path, "exists", side_effect=PermissionError(13, "denied")):
            assert path_exists(target) is False

    def test_the_bare_call_really_does_raise(self):
        """Pin the stdlib behaviour this helper exists for."""
        import errno
        from pathlib import Path
        from unittest.mock import patch

        with patch.object(Path, "exists",
                          side_effect=PermissionError(errno.EACCES, "denied")):
            with pytest.raises(PermissionError):
                Path("/whatever").exists()

    def test_no_check_calls_bare_exists(self):
        """A regression guard: every check goes through the helper.

        One bare call under an unreadable directory is enough to lose the whole
        audit, so this is enforced rather than reviewed.
        """
        import re
        from pathlib import Path

        offenders = []
        for path in sorted(Path("bob/checks").rglob("*.py")):
            if path.name == "_run.py":
                continue  # defines the helper, and wraps the one real call
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("*"):
                    continue
                if re.search(r"\.exists\(\)", line) and "``" not in line:
                    offenders.append(f"{path}:{number}")
        assert not offenders, (
            "these call Path.exists() directly instead of path_exists(); "
            "EACCES there aborts the audit: " + ", ".join(offenders)
        )


class TestSshConfigProbeSeparatesThreeCases:
    """absent / unreadable / readable are three different answers."""

    def test_absent_config_leaves_the_defaults_trusted(self, tmp_path, monkeypatch):
        from bob.checks.ssh import _snapshot as mod
        monkeypatch.setattr(mod, "_SSHD_CONFIG_PATH", tmp_path / "absent")
        monkeypatch.setattr(mod, "_command_exists", lambda name: False)
        snap = mod.SSHSnapshot.from_system()
        # sshd really would run on its compiled-in defaults here.
        assert snap.sshd_config_readable is True
        assert snap.sshd_config == {}

    def test_unreadable_config_is_marked_as_such(self, tmp_path, monkeypatch):
        from bob.checks.ssh import _snapshot as mod
        target = tmp_path / "sshd_config"
        target.write_text("PermitRootLogin yes\n")
        target.chmod(0o000)
        monkeypatch.setattr(mod, "_SSHD_CONFIG_PATH", target)
        monkeypatch.setattr(mod, "_command_exists", lambda name: False)
        try:
            if target.open("rb"):  # running as root defeats the mode bits
                pytest.skip("euid can read a 0000 file; mode-based denial N/A")
        except OSError:
            pass
        snap = mod.SSHSnapshot.from_system()
        assert snap.sshd_config_readable is False
        assert snap.sshd_config == {}

    def test_readable_config_is_parsed(self, tmp_path, monkeypatch):
        from bob.checks.ssh import _snapshot as mod
        target = tmp_path / "sshd_config"
        target.write_text("PermitRootLogin yes\n")
        monkeypatch.setattr(mod, "_SSHD_CONFIG_PATH", target)
        monkeypatch.setattr(mod, "_command_exists", lambda name: False)
        snap = mod.SSHSnapshot.from_system()
        assert snap.sshd_config_readable is True
        assert snap.sshd_config.get("permitrootlogin") == "yes"


class TestLogrotateDirectoryUnlistable:
    """A directory that will not list counts zero rules, like an empty one."""

    def _keys(self, *, listed, count=0):
        from bob.checks.log_rotation import LogRotationSnapshot, check_log_rotation
        snap = LogRotationSnapshot(logrotate_installed=True,
                                   logrotate_rule_count=count,
                                   logrotate_dir_listed=listed)
        return {f.key for f in check_log_rotation(snap).findings}

    def test_unlistable_is_not_reported_as_no_rules(self):
        keys = self._keys(listed=False)
        assert "log_rotation.logrotate_no_rules" not in keys
        assert "log_rotation.logrotate_dir_unreadable" in keys

    def test_listed_and_empty_still_reports_no_rules(self):
        assert "log_rotation.logrotate_no_rules" in self._keys(listed=True)

    def test_listed_with_rules_reports_ok(self):
        assert "log_rotation.logrotate_ok" in self._keys(listed=True, count=12)


class TestBatchFourLocaleKeys:
    @pytest.mark.parametrize("dotted", [
        "log_rotation.logrotate_dir_unreadable",
        "log_rotation.logrotate_dir_unreadable_detail",
    ])
    def test_key_present_in_both_locales(self, dotted):
        import json
        from pathlib import Path
        for locale in ("en", "fr"):
            data = json.loads(
                (Path("bob/locales") / f"{locale}.json").read_text(encoding="utf-8")
            )
            node = data
            for part in dotted.split("."):
                assert part in node, f"{locale}.json is missing {dotted}"
                node = node[part]
            assert isinstance(node, str) and node.strip()
