"""v0.15.3 — `server min protocol` is the name a current smb.conf uses.

Samba renamed `min protocol` to `server min protocol` and kept the short form
as a deprecated synonym. BOB read only the short one, so a host that had
explicitly enabled SMB1 — the EternalBlue and WannaCry vector, which BOB itself
raises as an ALERT with a two-point deduction — was reported as having it
disabled.

The signature of this campaign once more: the more current the configuration,
the likelier the miss. Verified against `testparm`, samba's own parser, which
resolves both spellings to the same effective protocol; seven configurations
agreed, four SMB1-enabling and three not.
"""

import pytest

from bob.checks.samba import SambaSnapshot, _section_get, check_samba


class TestSectionGetTriesEverySpelling:
    def test_the_first_present_name_wins(self):
        assert _section_get({"server min protocol": "NT1"},
                            "server min protocol", "min protocol") == "NT1"

    def test_it_falls_back_to_the_deprecated_name(self):
        assert _section_get({"min protocol": "NT1"},
                            "server min protocol", "min protocol") == "NT1"

    def test_the_modern_name_takes_precedence(self):
        """Both present is a misconfiguration; samba applies the current name."""
        opts = {"server min protocol": "SMB3", "min protocol": "NT1"}
        assert _section_get(opts, "server min protocol", "min protocol") == "SMB3"

    def test_an_empty_value_is_not_a_value(self):
        opts = {"server min protocol": "   ", "min protocol": "NT1"}
        assert _section_get(opts, "server min protocol", "min protocol") == "NT1"

    def test_absent_everywhere_is_empty(self):
        assert _section_get({}, "server min protocol", "min protocol") == ""


def _snapshot(tmp_path, monkeypatch, **globals_):
    """Drive the real `from_system` against a written smb.conf.

    Deliberately not a reimplementation of the detection: an earlier draft of
    this file rebuilt the logic locally, and reinjecting the defect into
    samba.py killed nothing — the tests were asserting their own copy. Writing
    the file and letting `from_system` parse it is what makes them bite.
    """
    conf = tmp_path / "smb.conf"
    body = "[global]\n" + "".join(f"   {k} = {v}\n" for k, v in globals_.items())
    conf.write_text(body, encoding="utf-8")
    monkeypatch.setattr("bob.checks.samba._SMB_CONF_PATH", conf)
    monkeypatch.setattr("bob.checks.samba._command_exists", lambda name: True)
    return SambaSnapshot.from_system()


class TestSmb1IsSeenUnderBothSpellings:
    """Each row was confirmed against `testparm` on a real samba install."""

    @pytest.mark.parametrize("options,expected", [
        ({"min protocol": "NT1"},         True),   # deprecated name
        ({"server min protocol": "NT1"},  True),   # current name — was missed
        ({"max protocol": "NT1"},         True),
        ({"server max protocol": "NT1"},  True),   # current name — was missed
        ({"server min protocol": "SMB3"}, False),
        ({"min protocol": "SMB2"},        False),
        ({"server max protocol": "SMB3"}, False),
    ])
    def test_detection(self, options, expected, tmp_path, monkeypatch):
        snap = _snapshot(tmp_path, monkeypatch, **options)
        assert snap.conf_readable is True, "the config was not parsed at all"
        assert snap.smb1_enabled is expected

    def test_the_alert_and_its_deduction_reach_the_report(self, tmp_path, monkeypatch):
        result = check_samba(
            _snapshot(tmp_path, monkeypatch, **{"server min protocol": "NT1"})
        )
        keys = {f.key for f in result.findings}
        assert "samba.smb1_enabled" in keys
        assert [(d.key, d.points) for d in result.deductions] == [
            ("samba.smb1_enabled", 2)
        ]

    def test_a_modern_config_still_reports_smb1_disabled(self, tmp_path, monkeypatch):
        result = check_samba(
            _snapshot(tmp_path, monkeypatch, **{"server min protocol": "SMB3"})
        )
        keys = {f.key for f in result.findings}
        assert "samba.smb1_disabled" in keys
        assert "samba.smb1_enabled" not in keys


class TestTheClientSideIsNotTheServerVerdict:
    """`client min protocol` governs what this host speaks *to* a server."""

    def test_a_client_only_setting_does_not_raise_the_server_alert(self, tmp_path,
                                                                   monkeypatch):
        snap = _snapshot(tmp_path, monkeypatch, **{"client min protocol": "NT1"})
        assert snap.smb1_enabled is False
