"""
v0.15.0 — valid JSON that is not an object crashed the Docker checks.

`/etc/docker/daemon.json` was read with `json.loads` and then used as a mapping,
catching only `json.JSONDecodeError`. But `[]`, `"text"` and `null` are all valid
JSON and none of them has `.get()`, so each raised `AttributeError` out of
`DockerSnapshot.from_system()` and `_read_userns_remap()`.

Since the v0.15.0 core barrier that no longer kills the audit — it degrades the
Docker section — but the section is still lost, and the moment an operator runs
an audit is precisely the moment daemon.json is broken, because Docker refuses
to start on such a file.

The distinction that matters is preserved: a file that is genuinely readable and
says `{"iptables": false}` still reports Docker bypassing the firewall.
"""

from __future__ import annotations

import pytest

import bob.checks.docker as d
import bob.checks.docker_audit as da


@pytest.fixture
def daemon_json(tmp_path, monkeypatch):
    def _write(content: str):
        p = tmp_path / "daemon.json"
        p.write_text(content)
        monkeypatch.setattr(d, "DAEMON_JSON_PATH", p)
        monkeypatch.setattr(da, "_DAEMON_JSON", p)
        return p
    return _write


_NON_OBJECTS = ["[]", '["a", "b"]', '"text"', "null", "42", "true"]


class TestDockerIptablesFlag:
    @pytest.mark.parametrize("content", _NON_OBJECTS)
    def test_valid_json_that_is_not_an_object_does_not_raise(self, daemon_json, content):
        daemon_json(content)
        assert d._check_daemon_json() == (True, False)

    def test_a_real_bypass_is_still_reported(self, daemon_json):
        daemon_json('{"iptables": false}')
        assert d._check_daemon_json() == (True, True)

    @pytest.mark.parametrize("content", ['{"iptables": true}', "{}",
                                         '{"log-driver": "json-file"}'])
    def test_an_ordinary_config_is_not_a_bypass(self, daemon_json, content):
        daemon_json(content)
        assert d._check_daemon_json() == (True, False)

    def test_malformed_json_is_still_handled(self, daemon_json):
        daemon_json("{not json")
        assert d._check_daemon_json() == (True, False)

    def test_a_missing_file_is_reported_as_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(d, "DAEMON_JSON_PATH", tmp_path / "absent.json")
        assert d._check_daemon_json() == (False, False)

    def test_the_string_false_is_not_the_boolean(self, daemon_json):
        """Docker rejects a string here; only a JSON false disables iptables."""
        daemon_json('{"iptables": "false"}')
        assert d._check_daemon_json() == (True, False)


class TestUsernsRemap:
    @pytest.mark.parametrize("content", _NON_OBJECTS)
    def test_valid_json_that_is_not_an_object_does_not_raise(self, daemon_json, content):
        daemon_json(content)
        assert da._read_userns_remap() is False

    def test_a_configured_remap_is_seen(self, daemon_json):
        daemon_json('{"userns-remap": "default"}')
        assert da._read_userns_remap() is True

    @pytest.mark.parametrize("content", ["{}", '{"userns-remap": ""}'])
    def test_an_absent_or_empty_remap_is_false(self, daemon_json, content):
        daemon_json(content)
        assert da._read_userns_remap() is False

    def test_malformed_json_is_still_handled(self, daemon_json):
        daemon_json("{not json")
        assert da._read_userns_remap() is False
