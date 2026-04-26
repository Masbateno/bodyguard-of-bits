"""
Unit tests for bob.config module.

Uses a temporary directory for all file operations —
never touches the real ~/.config/bob/config.conf.

Run with: python -m pytest tests/test_config.py -v
"""

import pytest
from pathlib import Path
from bob.config import UserConfig


@pytest.fixture
def tmp_config(tmp_path) -> UserConfig:
    """Return a UserConfig backed by a temporary file."""
    config_path = tmp_path / "config.conf"
    return UserConfig.load(path=config_path)


class TestLoad:
    def test_load_missing_file_returns_empty(self, tmp_path):
        config = UserConfig.load(path=tmp_path / "nonexistent.conf")
        assert config.all_keys() == []

    def test_load_existing_file_parses_values(self, tmp_path):
        config_path = tmp_path / "config.conf"
        config_path.write_text("ssh_port=2222\nnginx_port=8080\n")
        config = UserConfig.load(path=config_path)
        assert config.get("ssh_port") == "2222"
        assert config.get("nginx_port") == "8080"

    def test_load_skips_comment_lines(self, tmp_path):
        config_path = tmp_path / "config.conf"
        config_path.write_text("# this is a comment\nssh_port=22\n")
        config = UserConfig.load(path=config_path)
        assert config.get("ssh_port") == "22"
        assert len(config.all_keys()) == 1

    def test_load_skips_empty_lines(self, tmp_path):
        config_path = tmp_path / "config.conf"
        config_path.write_text("\n\nssh_port=22\n\n")
        config = UserConfig.load(path=config_path)
        assert config.all_keys() == ["ssh_port"]

    def test_load_skips_malformed_lines(self, tmp_path):
        config_path = tmp_path / "config.conf"
        config_path.write_text("malformed_no_equals\nssh_port=22\n")
        config = UserConfig.load(path=config_path)
        assert config.get("malformed_no_equals") is None
        assert config.get("ssh_port") == "22"

    def test_load_creates_directory(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "config.conf"
        config = UserConfig.load(path=deep_path)
        assert deep_path.parent.exists()

    def test_load_value_with_equals_sign(self, tmp_path):
        """Values containing '=' should be preserved correctly."""
        config_path = tmp_path / "config.conf"
        config_path.write_text("key=value=with=equals\n")
        config = UserConfig.load(path=config_path)
        assert config.get("key") == "value=with=equals"


class TestGet:
    def test_get_existing_key(self, tmp_config):
        tmp_config.set("ssh_port", "2222")
        assert tmp_config.get("ssh_port") == "2222"

    def test_get_missing_key_returns_none(self, tmp_config):
        assert tmp_config.get("nonexistent") is None


class TestSet:
    def test_set_persists_to_disk(self, tmp_config):
        tmp_config.set("ssh_port", "2222")
        reloaded = UserConfig.load(path=tmp_config.path)
        assert reloaded.get("ssh_port") == "2222"

    def test_set_overwrites_existing_key(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.set("ssh_port", "2222")
        assert tmp_config.get("ssh_port") == "2222"

    def test_set_multiple_keys(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.set("nginx_port", "80")
        assert tmp_config.get("ssh_port") == "22"
        assert tmp_config.get("nginx_port") == "80"

    def test_set_writes_sorted_keys(self, tmp_config):
        tmp_config.set("z_port", "1")
        tmp_config.set("a_port", "2")
        lines = tmp_config.path.read_text().splitlines()
        assert lines[0].startswith("a_port")
        assert lines[1].startswith("z_port")


class TestDelete:
    def test_delete_removes_key(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.delete("ssh_port")
        assert tmp_config.get("ssh_port") is None

    def test_delete_persists_to_disk(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.delete("ssh_port")
        reloaded = UserConfig.load(path=tmp_config.path)
        assert reloaded.get("ssh_port") is None

    def test_delete_missing_key_is_noop(self, tmp_config):
        tmp_config.delete("nonexistent")  # should not raise
        assert tmp_config.all_keys() == []

    def test_delete_leaves_other_keys_intact(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.set("nginx_port", "80")
        tmp_config.delete("ssh_port")
        assert tmp_config.get("nginx_port") == "80"


class TestClear:
    def test_clear_removes_all_keys(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.set("nginx_port", "80")
        tmp_config.clear()
        assert tmp_config.all_keys() == []

    def test_clear_persists_empty_file(self, tmp_config):
        tmp_config.set("ssh_port", "22")
        tmp_config.clear()
        reloaded = UserConfig.load(path=tmp_config.path)
        assert reloaded.all_keys() == []


class TestAllKeys:
    def test_all_keys_sorted(self, tmp_config):
        tmp_config.set("z_key", "1")
        tmp_config.set("a_key", "2")
        tmp_config.set("m_key", "3")
        assert tmp_config.all_keys() == ["a_key", "m_key", "z_key"]

    def test_all_keys_empty(self, tmp_config):
        assert tmp_config.all_keys() == []


class TestExists:
    def test_exists_false_before_any_write(self, tmp_path):
        config = UserConfig(path=tmp_path / "config.conf")
        assert not config.exists()

    def test_exists_true_after_set(self, tmp_path):
        config = UserConfig.load(path=tmp_path / "config.conf")
        config.set("key", "value")
        assert config.exists()


class TestPath:
    def test_path_property(self, tmp_path):
        config_path = tmp_path / "config.conf"
        config = UserConfig(path=config_path)
        assert config.path == config_path
