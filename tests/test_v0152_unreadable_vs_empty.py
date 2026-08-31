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
