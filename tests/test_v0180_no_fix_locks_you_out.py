"""An unattended fix must not cut the operator off from the machine.

Stress pass 4, measured on an Arch VM. `bob --fix --apply --yes` ran::

    sudo iptables -P INPUT DROP

and left the host with loopback broken and outbound broken. In the same audit,
BOB reported `firewall_iptables.no_loopback` and `firewall_iptables.no_conntrack`
— it applied a policy whose prerequisites it knows about and does not install.
On a remote host that policy ends the session that started it.

The same run also offered, in this order::

    sudo ufw enable
    sudo ufw allow 22

with sshd listening on 22. Applied unattended on a remote host, the first line
removes the way back in and the second never reaches anyone. BOB already knew
to allow the port; it simply did it second.

Both are the same defect wearing different clothes: a fix BOB runs by itself
that can take the machine away from the person running it.

(What broke the Arch box's loopback turned out to be ufw's own doing — `ufw
enable` there sets `-P INPUT DROP`, creates its chains, and never wires INPUT
into them. That is not BOB's defect, and BOB detects the result. What is BOB's
is applying a default-deny policy unattended in the first place.)
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from bob import fixes as fx
from bob.fixes import _can_apply_unattended


class TestADefaultDenyPolicyIsNeverRunUnattended:
    @pytest.mark.parametrize("cmd", [
        "sudo iptables -P INPUT DROP",
        "sudo iptables -P FORWARD DROP",
        "iptables -P INPUT DROP",
        "sudo ip6tables -P INPUT DROP",
        "sudo nft chain inet filter input '{ policy drop; }'",
    ])
    def test_it_is_refused(self, cmd):
        assert _can_apply_unattended(cmd) is False, (
            f"{cmd!r} would run unattended; measured on Arch, it left the host "
            "with loopback and outbound broken"
        )

    @pytest.mark.parametrize("cmd", [
        "sudo ufw allow 22",
        "sudo ufw --force delete 3",
        "sudo systemctl restart sshd",
        "sudo iptables -P OUTPUT ACCEPT",
        "sudo iptables -A INPUT -i lo -j ACCEPT",
    ])
    def test_ordinary_commands_still_apply(self, cmd):
        assert _can_apply_unattended(cmd) is True, (
            "refusing a policy change must not refuse everything near it"
        )

    def test_the_command_is_still_shown(self):
        """Refusing to run it is not refusing to say it."""
        from tests.test_fixes import make_engine, make_finding, make_config, _t
        finding = make_finding(message="INPUT ACCEPT",
                               cmd="sudo iptables -P INPUT DROP")
        buf = io.StringIO()
        with patch("builtins.input", return_value="n"), redirect_stdout(buf):
            fx.run_fixes(make_engine(finding), make_config(), _t)
        out = buf.getvalue()
        assert "iptables -P INPUT DROP" in out
        assert "fixes.diagnostic_items_title" in out


class TestAccessIsGrantedBeforeItIsWithdrawn:
    def _applied_order(self, *findings):
        from tests.test_fixes import make_engine, make_config, _t
        ran: list = []

        def record(argv, timeout):
            ran.append(" ".join(argv))
            return "ok", 0, b""

        with patch.object(fx, "_run_fix_command", side_effect=record), \
             patch("builtins.input", return_value="y"), \
             redirect_stdout(io.StringIO()):
            fx.run_fixes(make_engine(*findings), make_config(), _t)
        return ran

    def test_the_measured_arch_case(self):
        """BOB offered enable, then allow, with sshd listening."""
        from tests.test_fixes import make_finding
        order = self._applied_order(
            make_finding(message="firewall inactive", cmd="sudo ufw enable"),
            make_finding(message="port 22 exposed", cmd="sudo ufw allow 22"),
        )
        assert order.index("sudo ufw allow 22") < order.index("sudo ufw enable"), (
            "enabling a default-deny firewall before opening the port the "
            "operator is connected on ends the session that started the fix"
        )

    def test_default_deny_comes_after_the_allow_too(self):
        from tests.test_fixes import make_finding
        order = self._applied_order(
            make_finding(message="policy", cmd="sudo ufw default deny incoming"),
            make_finding(message="allow", cmd="sudo ufw allow 22"),
        )
        assert order[0] == "sudo ufw allow 22"

    def test_unrelated_fixes_keep_their_place_between_the_two(self):
        from tests.test_fixes import make_finding
        order = self._applied_order(
            make_finding(message="enable", cmd="sudo ufw enable"),
            make_finding(message="other", cmd="sudo systemctl restart sshd"),
            make_finding(message="allow", cmd="sudo ufw allow 22"),
        )
        assert order.index("sudo ufw allow 22") == 0
        assert order.index("sudo ufw enable") == len(order) - 1

    def test_ufw_deletes_still_run_first_and_descending(self):
        """The v0.16.x ordering must survive the new phase."""
        from tests.test_fixes import make_finding
        order = self._applied_order(
            make_finding(message="d1", cmd="sudo ufw --force delete 1"),
            make_finding(message="d3", cmd="sudo ufw --force delete 3"),
            make_finding(message="allow", cmd="sudo ufw allow 22"),
        )
        assert order[:2] == ["sudo ufw --force delete 3",
                             "sudo ufw --force delete 1"], (
            "deleting by number has to go high-to-low or the numbers shift "
            "under the next delete"
        )
