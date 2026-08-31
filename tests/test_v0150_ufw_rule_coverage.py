"""
v0.15.0 — `ufw allow OpenSSH` left port 22 looking unprotected.

`ufw status numbered` was matched with one regex that read the first number of
the To column and stopped:

    r"^\\s*\\[\\s*\\d+\\]\\s+(\\d+)(?:/(tcp|udp))?\\b"

Three ordinary rule forms defeated it, all confirmed against ufw's own source
(`backend_iptables.get_status`) and its shipped profiles in
`/etc/ufw/applications.d`:

* **Application profiles.** In non-verbose mode — the mode BOB reads — ufw
  prints the profile *name* in the To column and no port at all. `ufw allow
  OpenSSH` is what Ubuntu's own documentation tells you to run, so a correctly
  configured host was told its SSH port had no firewall rule.
* **Ranges.** `6000:6007/tcp` matched only "6000", and without its protocol,
  so 6001-6007 read as uncovered *and* 6000/udp read as covered — wrong in
  both directions from a single rule.
* **Lists.** `80,443/tcp` behaved identically: 443 uncovered, 80/udp covered.

The profile map is collected in `from_system` rather than read inside the
check, because `check_xxx` is pure by contract.
"""

from __future__ import annotations

import pytest

from bob.checks.ports import (
    _expand_port_spec,
    _is_covered_by_ufw,
    _parse_ufw_covered_ports,
    _read_ufw_app_profiles,
)

_STATUS = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] OpenSSH                    ALLOW IN    Anywhere
[ 3] 6000:6007/tcp              ALLOW IN    Anywhere
[ 4] 80,443/tcp                 ALLOW IN    Anywhere
[ 5] 8080                       DENY IN     Anywhere
[ 6] 53                         ALLOW IN    Anywhere
[ 7] 25/tcp on eth0             ALLOW IN    Anywhere
[ 8] Samba                      ALLOW IN    192.168.1.0/24
[ 9] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[10] Anywhere                   ALLOW IN    192.168.1.22
"""

_APPS = {
    "OpenSSH": ["22/tcp"],
    "Samba": ["137,138/udp", "139,445/tcp"],
    "CUPS": ["631"],
}


@pytest.fixture
def covered():
    return _parse_ufw_covered_ports(_STATUS, _APPS)


class TestApplicationProfiles:
    def test_ufw_allow_openssh_covers_port_22(self, covered):
        """The documented way to open SSH on Ubuntu."""
        assert _is_covered_by_ufw(22, "tcp", covered)

    @pytest.mark.parametrize("port,proto", [(137, "udp"), (138, "udp"),
                                            (139, "tcp"), (445, "tcp")])
    def test_a_profile_with_several_specs_covers_all_of_them(
            self, covered, port, proto):
        """Samba ships `137,138/udp|139,445/tcp` — two specs, four ports."""
        assert _is_covered_by_ufw(port, proto, covered)

    def test_a_profile_does_not_cross_protocols(self, covered):
        assert not _is_covered_by_ufw(139, "udp", covered)

    def test_an_unknown_profile_name_covers_nothing(self):
        cov = _parse_ufw_covered_ports("[ 1] Nextcloud  ALLOW IN  Anywhere\n", {})
        assert cov == []


class TestRangesAndLists:
    @pytest.mark.parametrize("port", [6000, 6001, 6003, 6007])
    def test_every_port_of_a_range_is_covered(self, covered, port):
        assert _is_covered_by_ufw(port, "tcp", covered)

    @pytest.mark.parametrize("port", [5999, 6008])
    def test_the_range_does_not_leak(self, covered, port):
        assert not _is_covered_by_ufw(port, "tcp", covered)

    def test_a_range_keeps_its_protocol(self, covered):
        """The old parser dropped it, so 6000/udp read as covered."""
        assert not _is_covered_by_ufw(6000, "udp", covered)

    @pytest.mark.parametrize("port", [80, 443])
    def test_both_ports_of_a_list_are_covered(self, covered, port):
        assert _is_covered_by_ufw(port, "tcp", covered)

    def test_a_list_keeps_its_protocol(self, covered):
        assert not _is_covered_by_ufw(80, "udp", covered)


class TestUnchangedBehaviour:
    def test_a_plain_rule_still_works(self, covered):
        assert _is_covered_by_ufw(22, "tcp", covered)

    def test_a_rule_without_a_protocol_covers_both(self, covered):
        assert _is_covered_by_ufw(53, "tcp", covered)
        assert _is_covered_by_ufw(53, "udp", covered)

    def test_a_deny_rule_counts_as_handled(self, covered):
        """The question this answers is "is there a rule", and a DENY is one."""
        assert _is_covered_by_ufw(8080, "tcp", covered)

    def test_an_interface_scoped_rule_is_read(self, covered):
        assert _is_covered_by_ufw(25, "tcp", covered)

    def test_a_port_inside_a_source_address_is_not_a_target(self, covered):
        """`ALLOW IN 192.168.1.22` must not make port 192 or 22 look covered
        by *that* rule — the anchor on the rule number is what prevents it."""
        assert not _is_covered_by_ufw(192, "tcp", covered)

    def test_raw_text_is_still_accepted(self):
        assert _is_covered_by_ufw(22, "tcp", "[ 1] 22/tcp ALLOW IN Anywhere\n")


class TestExpandPortSpec:
    @pytest.mark.parametrize("spec,expected", [
        ("22/tcp",       [(22, 22, "tcp")]),
        ("631",          [(631, 631, None)]),
        ("6000:6007/tcp", [(6000, 6007, "tcp")]),
        ("80,443/tcp",   [(80, 80, "tcp"), (443, 443, "tcp")]),
        ("137,138/udp",  [(137, 137, "udp"), (138, 138, "udp")]),
        ("nonsense",     []),
        ("",             []),
    ])
    def test_expand(self, spec, expected):
        assert _expand_port_spec(spec) == expected


class TestProfileReading:
    def test_sections_and_ports_are_paired(self, tmp_path):
        (tmp_path / "postfix").write_text(
            "[Postfix]\ntitle=x\nports=25/tcp\n\n"
            "[Postfix Submission]\ntitle=y\nports=587/tcp\n")
        apps = _read_ufw_app_profiles(tmp_path)
        assert apps == {"Postfix": ["25/tcp"], "Postfix Submission": ["587/tcp"]}

    def test_the_pipe_separator_splits_specs(self, tmp_path):
        (tmp_path / "samba").write_text("[Samba]\nports=137,138/udp|139,445/tcp\n")
        assert _read_ufw_app_profiles(tmp_path)["Samba"] == \
            ["137,138/udp", "139,445/tcp"]

    def test_a_missing_directory_is_not_an_error(self, tmp_path):
        assert _read_ufw_app_profiles(tmp_path / "absent") == {}

    def test_the_real_directory_parses(self):
        """Reads whatever this host ships; asserts the shape, not the content."""
        apps = _read_ufw_app_profiles()
        assert all(isinstance(k, str) and isinstance(v, list)
                   for k, v in apps.items())
