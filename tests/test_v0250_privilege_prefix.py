"""v0.25.0 — the privilege prefix of the fixes BOB prints is the host's.

Every printed fix began with ``sudo``. Alpine ships ``doas`` and no sudo, so a
fix pasted there failed on its first word. The prefix is now chosen once from
what the host has, and applied where a finding is recorded.
"""

from __future__ import annotations

import pytest

from bob import _privilege
from bob._privilege import privilege_prefix, with_privilege
from tests.helpers import _t


@pytest.fixture
def host(monkeypatch):
    def build(*binaries):
        monkeypatch.setattr(_privilege.shutil, "which", lambda name: f"/usr/bin/{name}" if name in binaries else None)
        privilege_prefix.cache_clear()
    yield build
    privilege_prefix.cache_clear()


class TestWhichPrefix:
    @pytest.mark.parametrize("binaries, prefix", [
        (("sudo",), "sudo"),
        (("sudo", "doas"), "sudo"),       # both: sudo, as BOB always wrote
        (("doas",), "doas"),              # Alpine
        ((), "sudo"),                     # neither: nothing better to name
    ])
    def test_the_prefix(self, host, binaries, prefix):
        host(*binaries)
        assert privilege_prefix() == prefix


class TestTheCommandWords:
    def test_every_sudo_word_in_a_chain(self, host):
        host("doas")
        assert with_privilege("sudo ufw allow 22/tcp && sudo ufw enable") == "doas ufw allow 22/tcp && doas ufw enable"

    def test_a_pipe_into_sudo(self, host):
        host("doas")
        assert with_privilege("printf 'x' | sudo tee /etc/x") == "printf 'x' | doas tee /etc/x"

    @pytest.mark.parametrize("cmd", ["sudo visudo -c", "sudo chmod 0440 /etc/sudoers",
                                     "sudo ls /etc/sudoers.d/"])
    def test_words_that_only_contain_sudo_are_left(self, host, cmd):
        host("doas")
        out = with_privilege(cmd)
        assert out.startswith("doas ") and out.count("sudo") == cmd.count("sudo") - 1

    def test_a_sudo_host_is_untouched(self, host):
        host("sudo")
        assert with_privilege("sudo ufw enable") == "sudo ufw enable"


def test_a_finding_carries_the_hosts_prefix(host):
    from bob.checks.firewall import FirewallStatus, check_firewall
    host("doas")
    status = FirewallStatus(installed=True, active=False, incoming_policy="unknown",
                            ufw_output="", numbered_output="", ipv6_ufw_enabled=True)
    finding = next(f for f in check_firewall(status, t=_t, ssh_ports=[22]).findings if f.key == "firewall.inactive")
    assert finding.cmd == "doas ufw allow 22/tcp && doas ufw enable"


def test_apply_recognises_a_doas_ufw_delete():
    """--fix --apply orders ufw deletes by number; the doas form must be one too."""
    import inspect
    import re
    from bob import fixes
    src = inspect.getsource(fixes)
    pattern = re.search(r'_UFW_DELETE_RE = re\.compile\(r"(.+?)"\)', src).group(1)
    assert re.match(pattern, "doas ufw --force delete 3")
    assert re.match(pattern, "sudo ufw --force delete 3")
