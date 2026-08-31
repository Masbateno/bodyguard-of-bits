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
