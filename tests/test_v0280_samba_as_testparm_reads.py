"""v0.28.0 — smb.conf read as samba reads it.

The 0.19.0 note left "the samba parser's own divergence from testparm on
duplicates/continuations" for later. Measured on Debian 13 (testparm 4.22.11,
25 October 2026), `server min protocol = NT1` was NT1 for testparm in every
case below; configparser (BOB until 0.27.0) read nothing when the line was
indented deeper than the one before (it took it for a continuation), raised a
parsing error on a backslash continuation, and did not recognise `Server  Min
Protocol`. testparm also showed that samba has no inline comment: `workgroup =
WORKGROUP # inline comment` is that whole value, and `null passwords = yes #
c` is not a boolean — samba refuses to load the file.
"""

from __future__ import annotations

import pytest

from bob.checks import samba as sm

CASES = {
    "plain": "[global]\n   server min protocol = NT1\n",
    "duplicate-last-wins": "[global]\n   server min protocol = SMB2\n   server min protocol = NT1\n",
    "deeper-indent": "[global]\nworkgroup = X\n    server min protocol = NT1\n",
    "backslash": "[global]\n   server min protocol = \\\nNT1\n",
    "two-globals": "[global]\n   server min protocol = SMB2\n[share]\n   path = /tmp\n[global]\n   server min protocol = NT1\n",
    "name-spacing": "[GLOBAL]\n   Server  Min   Protocol = NT1\n",
    # measured: testparm kept NT1 from the first [global] and OTHER from the second
    "merged-globals": "[global]\n   server min protocol = NT1\n[share]\n   path = /tmp\n[global]\n   workgroup = OTHER\n",
    "no-spaces": "[global]\n   serverminprotocol = NT1\n",
}


@pytest.mark.parametrize("name", CASES)
def test_testparms_value(tmp_path, name):
    conf = tmp_path / "smb.conf"
    conf.write_text(CASES[name], encoding="utf-8")
    glb = sm._read_smb_conf(conf)["global"]
    assert sm._section_get(glb, "server min protocol", "min protocol") == "NT1"


@pytest.mark.parametrize("name", ["deeper-indent", "backslash", "name-spacing"])
def test_smb1_is_seen_through_the_snapshot(tmp_path, monkeypatch, name):
    conf = tmp_path / "smb.conf"
    conf.write_text(CASES[name], encoding="utf-8")
    monkeypatch.setattr(sm, "_SMB_CONF_PATH", conf)
    monkeypatch.setattr(sm, "_command_exists", lambda c: c == "smbd")
    assert sm.SambaSnapshot.from_system().smb1_enabled is True


def test_no_inline_comment(tmp_path):
    conf = tmp_path / "smb.conf"
    conf.write_text("[global]\n   workgroup = WORKGROUP  # inline comment\n   ; whole-line comment\n",
                    encoding="utf-8")
    glb = sm._read_smb_conf(conf)["global"]
    assert glb["workgroup"] == "WORKGROUP  # inline comment"
    assert len(glb) == 1


class TestInclude:
    """Measured with testparm: `include = /tmp/inc.conf` inside [global], the
    included file holding `server min protocol = NT1` then a [pub] guest share:
    NT1, [pub] guest ok = Yes, and the [after] section that follows the include
    kept its path. A missing include was skipped (SMB2 read after it), and a
    %m path expanded per client."""

    def _conf(self, tmp_path, main, inc=None):
        if inc is not None:
            (tmp_path / "inc.conf").write_text(inc, encoding="utf-8")
        conf = tmp_path / "smb.conf"
        conf.write_text(main.replace("INC", str(tmp_path / "inc.conf")), encoding="utf-8")
        return sm._read_smb_conf(conf)

    def test_read_in_place(self, tmp_path):
        conf = self._conf(tmp_path, "[global]\n   workgroup = X\n   include = INC\n[after]\n   path = /tmp\n",
                          "   server min protocol = NT1\n[pub]\n   path = /srv/pub\n   guest ok = yes\n")
        assert conf["global"]["server min protocol"] == "NT1"
        assert conf["pub"]["guest ok"] == "yes"
        assert conf["after"]["path"] == "/tmp"

    def test_a_missing_one_is_skipped(self, tmp_path):
        conf = self._conf(tmp_path, "[global]\n   include = INC\n   server min protocol = SMB2\n")
        assert conf["global"]["server min protocol"] == "SMB2"

    def test_a_per_client_path_is_not_followed(self, tmp_path):
        assert self._conf(tmp_path, "[global]\n   include = /tmp/%m.conf\n")["global"] == {}

    def test_a_loop_ends(self, tmp_path):
        conf = self._conf(tmp_path, "[global]\n   include = INC\n",
                          f"   include = {tmp_path / 'inc.conf'}\n   workgroup = Y\n")
        assert conf["global"]["workgroup"] == "Y"


def test_an_underscored_name_is_not_a_parameter(tmp_path):
    """Measured with testparm 4.22.11: `server_min_protocol = NT1` was ignored
    (SMB2_02, the default) while `serverminprotocol = NT1` read NT1. Spaces do
    not matter in a name; underscores do."""
    conf = tmp_path / "smb.conf"
    conf.write_text("[global]\n   server_min_protocol = NT1\n", encoding="utf-8")
    glb = sm._read_smb_conf(conf)["global"]
    assert sm._section_get(glb, "server min protocol", "min protocol") == ""
