"""v0.30.0 — smb.conf's includes: the fix reaches them, %h is followed, a per-client file is said.

0.29.0 wrote the limit: "--fix writes smb.conf, not a file it includes; a
%-substituted include is not followed". Measured on Debian 13 (samba 4.22,
testparm and the fix commands BOB printed, 31 October 2026,
`~/.cache/bob-fieldtest/sudoesc/p6bench.sh`):

- with `server min protocol = NT1`, `server signing = disabled` or `map to
  guest = bad user` in a file [global] includes, the 0.29.0 fix left the value
  in force (testparm: NT1, No, Bad User) — the included line, read after the
  inserted one, won; now the fix deletes it there too (SMB2, required, Never);
- `include = /etc/samba/inc-%h.conf`: testparm read inc-<hostname>.conf and
  its NT1, which BOB missed (no finding); now BOB reads it and flags SMB1;
- `include = /etc/samba/inc-%m.conf`: the file depends on the client (testparm,
  with none, read inc-.conf); now said — samba.include_per_client, a ceiling.
"""

from __future__ import annotations

import pytest

from bob import i18n
from bob.checks import samba as sb
from bob.checks.samba import SambaSnapshot, check_samba
from bob.visibility import is_visibility_key


@pytest.fixture
def conf(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "smbbench")

    def write(main, **files):
        for name, text in files.items():
            (tmp_path / name).write_text(text)
        path = tmp_path / "smb.conf"
        path.write_text(main.replace("@", str(tmp_path) + "/"))
        included, per_client = [], []
        parsed = sb._read_smb_conf(path, included=included, per_client=per_client)
        return parsed, included, per_client, tmp_path
    return write


class TestTheReader:

    def test_h_is_the_hosts_name(self, conf):
        parsed, included, per_client, d = conf("[global]\n   include = @inc-%h.conf\n",
                                               **{"inc-smbbench.conf": "   server min protocol = NT1\n"})
        assert parsed["global"]["server min protocol"] == "NT1"
        assert included == [f"{d}/inc-smbbench.conf"] and per_client == []

    @pytest.mark.parametrize("include", ["@inc-%m.conf", "@inc-%h-%U.conf", "@%I/extra.conf"])
    def test_a_file_per_client_is_said_not_followed(self, conf, include):
        parsed, included, per_client, d = conf(f"[global]\n   include = {include}\n",
                                               **{"inc-.conf": "   server min protocol = NT1\n"})
        assert "server min protocol" not in parsed["global"]
        assert included == [] and per_client == [f"include = {include.replace('@', str(d) + '/')}"]

    def test_a_plain_include_is_recorded(self, conf):
        parsed, included, per_client, d = conf("[global]\n   include = @inc.conf\n",
                                               **{"inc.conf": "   map to guest = bad user\n"})
        assert parsed["global"]["map to guest"] == "bad user" and included == [f"{d}/inc.conf"]

    def test_a_missing_include_is_not_recorded(self, conf):
        _parsed, included, _pc, _d = conf("[global]\n   include = @nowhere.conf\n")
        assert included == []


class TestTheFix:

    def test_the_delete_reaches_every_file_read(self):
        cmd = sb._global_directive_cmd("min protocol = SMB2", "min protocol", "server min protocol",
                                       files=["/etc/samba/inc.conf", "/etc/samba/a b.conf"])
        delete, insert = cmd.split(" && ")
        assert delete.endswith("/etc/samba/smb.conf /etc/samba/inc.conf '/etc/samba/a b.conf'")
        assert insert.endswith("/etc/samba/smb.conf") and "inc.conf" not in insert

    @pytest.mark.parametrize("snap_kw, key", [
        ({"smb1_enabled": True}, "samba.smb1_enabled"),
        ({"server_signing": "disabled"}, "samba.server_signing_disabled"),
        ({"map_to_guest": "bad user"}, "samba.map_to_guest"),
    ])
    def test_each_global_finding_carries_it(self, snap_kw, key):
        snap = SambaSnapshot(installed=True, daemon_installed=True, conf_readable=True,
                             conf_included=["/etc/samba/inc.conf"], **snap_kw)
        res = check_samba(snap, t=lambda k, **kw: k)
        f = next(f for f in res.findings if f.key == key)
        assert "/etc/samba/smb.conf /etc/samba/inc.conf" in f.cmd

    def test_the_snapshot_reads_them(self):
        import inspect
        src = inspect.getsource(SambaSnapshot.from_system)
        assert "included=snap.conf_included, per_client=snap.conf_per_client)" in src


class TestWhatIsSaid:

    def test_a_per_client_include_is_a_ceiling(self):
        snap = SambaSnapshot(installed=True, daemon_installed=True, conf_readable=True,
                             conf_per_client=["include = /etc/samba/inc-%m.conf"])
        res = check_samba(snap, t=lambda k, **kw: k)
        assert "samba.include_per_client" in {f.key for f in res.findings}
        assert is_visibility_key("samba.include_per_client") and not res.deductions

    def test_none_without_one(self):
        snap = SambaSnapshot(installed=True, daemon_installed=True, conf_readable=True)
        assert "samba.include_per_client" not in {f.key for f in check_samba(snap, t=lambda k, **kw: k).findings}

    @pytest.mark.parametrize("lang, words", [
        ("en", "what samba applies to a given client is not established"),
        ("fr", "ce que samba applique à un client donné n'est pas établi"),
    ])
    def test_the_text(self, lang, words):
        i18n.init(lang)
        try:
            assert words in i18n.t("samba.include_per_client", lines="include = /etc/samba/inc-%m.conf")
        finally:
            i18n.init(lang="en")
