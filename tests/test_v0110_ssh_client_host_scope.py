"""v0.11.0 M-3 — ssh ~/.ssh/config Host scope semantics.

Pre-v0.11.0 ``_check_client_config`` flattened every entry: a directive
inside a restricted ``Host pattern`` block fired exactly as if it were
global (``Host *``). This contradicted BOB's own remediation advice for
``ForwardX11`` / ``ForwardAgent`` ("restrict it per-Host block") — an
operator who followed that advice still got WARNed with a point
deduction, as if they had done nothing.

v0.11.0 makes the two forwarding directives scope-aware:

  - ``forwardx11`` / ``forwardagent`` scoped to a non-``*`` Host →
    INFO note, NO deduction (the operator scoped it; acknowledge it).
  - same directives at global scope (``Host *`` or no Host block) →
    WARN + deduction (unchanged from v0.10.x).

The two host-key-verification directives stay ALERT in ANY scope —
disabling host-key checking is a MITM exposure even for a single host:

  - ``stricthostkeychecking no`` → ALERT + deduction, any scope.
  - ``userknownhostsfile /dev/null`` → ALERT + deduction, any scope.

BREAKING: an operator with a scoped ``ForwardX11 yes`` / ``ForwardAgent
yes`` previously lost 1 point (WARN); now they get an INFO with no
deduction, so the score goes up.
"""

from __future__ import annotations

import pytest

from bob.checks.ssh import ClientConfigEntry, check_ssh
from bob.scoring import FindingLevel

from tests.test_ssh import base_snapshot  # reuse the shared snapshot factory


def _snap(entries):
    return base_snapshot(
        ssh_dir_exists=True,
        ssh_dir_perms=0o700,
        client_config_exists=True,
        client_config_entries=entries,
    )


def _keys(result):
    return [f.key for f in result.findings]


def _deduction_keys(result):
    return [d.key for d in result.deductions]


def _info_keys(result):
    return [f.key for f in result.findings if f.level == FindingLevel.INFO]


class TestForwardX11Scope:
    def test_global_forwardx11_warns_with_deduction(self):
        entries = [ClientConfigEntry(host="*", key="forwardx11", value="yes")]
        result = check_ssh(_snap(entries))
        assert "ssh.x11.forwarding.client" in _deduction_keys(result)

    def test_scoped_forwardx11_is_info_no_deduction(self):
        entries = [
            ClientConfigEntry(host="trusted-jumpbox.internal", key="forwardx11", value="yes")
        ]
        result = check_ssh(_snap(entries))
        # INFO surfaced, NO deduction.
        assert "ssh.x11.forwarding.client_scoped" in _info_keys(result)
        assert "ssh.x11.forwarding.client_scoped" not in _deduction_keys(result)
        assert "ssh.x11.forwarding.client" not in _deduction_keys(result)

    def test_scoped_forwardx11_message_includes_host(self):
        entries = [
            ClientConfigEntry(host="trusted-jumpbox.internal", key="forwardx11", value="yes")
        ]
        result = check_ssh(_snap(entries))
        msg = next(
            f.message for f in result.findings
            if f.key == "ssh.x11.forwarding.client_scoped"
        )
        assert "trusted-jumpbox.internal" in msg


class TestForwardAgentScope:
    def test_global_forwardagent_warns_with_deduction(self):
        entries = [ClientConfigEntry(host="*", key="forwardagent", value="yes")]
        result = check_ssh(_snap(entries))
        assert "ssh.client_forward_agent" in _deduction_keys(result)

    def test_scoped_forwardagent_is_info_no_deduction(self):
        entries = [
            ClientConfigEntry(host="git.example.com", key="forwardagent", value="yes")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.client_forward_agent_scoped" in _info_keys(result)
        assert "ssh.client_forward_agent_scoped" not in _deduction_keys(result)
        assert "ssh.client_forward_agent" not in _deduction_keys(result)


class TestHostKeyDirectivesDangerousAnyScope:
    """StrictHostKeyChecking no + UserKnownHostsFile /dev/null stay ALERT
    regardless of Host scope — MITM exposure is not mitigated by scoping."""

    def test_scoped_strict_host_no_still_alerts(self):
        entries = [
            ClientConfigEntry(host="ci-runner.internal", key="stricthostkeychecking", value="no")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.client_strict_host_no" in _deduction_keys(result)

    def test_scoped_known_hosts_devnull_still_alerts(self):
        entries = [
            ClientConfigEntry(host="ci-runner.internal", key="userknownhostsfile", value="/dev/null")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.client_known_hosts_devnull" in _deduction_keys(result)


class TestMultiPatternHostLine:
    """v0.11.0 pre-ship audit I-1: a ``Host`` line listing several patterns
    that INCLUDES a bare ``*`` is globally effective in OpenSSH (``*``
    matches every host). It must NOT be treated as scoped — otherwise
    ``Host gitlab *`` would silently dodge the deduction."""

    def test_multi_pattern_host_with_star_is_global(self):
        entries = [
            ClientConfigEntry(host="bastion *", key="forwardx11", value="yes")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.x11.forwarding.client" in _deduction_keys(result)
        assert "ssh.x11.forwarding.client_scoped" not in _info_keys(result)

    def test_star_first_multi_pattern_is_global(self):
        entries = [
            ClientConfigEntry(host="* gitlab.example.com", key="forwardagent", value="yes")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.client_forward_agent" in _deduction_keys(result)

    def test_subdomain_wildcard_stays_scoped(self):
        """A bounded subdomain wildcard (no bare ``*`` token) is genuinely
        scoped — it does not match every host."""
        entries = [
            ClientConfigEntry(host="*.example.com", key="forwardx11", value="yes")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.x11.forwarding.client_scoped" in _info_keys(result)
        assert "ssh.x11.forwarding.client" not in _deduction_keys(result)


class TestMixedScopes:
    def test_global_and_scoped_forwardx11_both_surface(self):
        """A global ForwardX11 (WARN+deduction) and a scoped one (INFO) in
        the same config both surface with the right severity."""
        entries = [
            ClientConfigEntry(host="*", key="forwardx11", value="yes"),
            ClientConfigEntry(host="trusted.internal", key="forwardx11", value="yes"),
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.x11.forwarding.client" in _deduction_keys(result)
        assert "ssh.x11.forwarding.client_scoped" in _info_keys(result)

    def test_only_scoped_forwarding_suppresses_blanket_ok(self):
        """A scoped INFO counts as 'found something', so the blanket
        client_config_ok must not also fire."""
        entries = [
            ClientConfigEntry(host="trusted.internal", key="forwardx11", value="yes")
        ]
        result = check_ssh(_snap(entries))
        assert "ssh.client_config_ok" not in _keys(result)
