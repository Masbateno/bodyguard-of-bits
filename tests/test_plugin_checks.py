"""
Unit tests for bob.plugin_checks module.

Tests cover: loading, validation, error isolation, run() contract,
and edge cases. Real .py files are written to tmp_path fixtures.

Run with: python -m pytest tests/test_plugin_checks.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bob.plugin_checks import PluginCheck, _load_one, load_plugin_checks
from bob.scoring import CheckResult
from tests.helpers import _t


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_plugin(directory: Path, name: str, content: str) -> Path:
    """Write a plugin file and return its path."""
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


VALID_PLUGIN = """\
from bob.scoring import CheckResult

CHECK_NAME = "MY CUSTOM CHECK"

def run_check(t=None):
    result = CheckResult()
    result.ok("all good")
    return result
"""

PLUGIN_NO_NAME = """\
from bob.scoring import CheckResult

def run_check(t=None):
    result = CheckResult()
    result.info("info")
    return result
"""

PLUGIN_WITH_WARN = """\
from bob.scoring import CheckResult

def run_check(t=None):
    result = CheckResult()
    result.warn("something wrong", nature="improvement")
    result.add_deduction("something wrong", points=1, context="local")
    return result
"""

PLUGIN_NO_RUN_CHECK = """\
def helper():
    pass
"""

PLUGIN_RAISES = """\
from bob.scoring import CheckResult

def run_check(t=None):
    raise RuntimeError("plugin exploded")
"""

PLUGIN_WRONG_RETURN = """\
def run_check(t=None):
    return 42
"""

PLUGIN_SYNTAX_ERROR = """\
def run_check(t=None)
    pass
"""

PLUGIN_IMPORT_FAIL = """\
raise RuntimeError("boom at import time")
"""

PLUGIN_PARTIAL_IMPORT = """\
CHECK_NAME = "PARTIAL"

raise RuntimeError("module explodes mid-import")
"""

PLUGIN_T_RECEIVED = """\
from bob.scoring import CheckResult

received_t = None

def run_check(t=None):
    global received_t
    received_t = t
    result = CheckResult()
    result.ok("ok")
    return result
"""


# ---------------------------------------------------------------------------
# load_plugin_checks — directory handling
# ---------------------------------------------------------------------------

class TestLoadPluginChecks:
    def test_returns_empty_when_dir_missing(self, tmp_path):
        missing = tmp_path / "nonexistent"
        assert load_plugin_checks(plugin_dir=missing) == []

    def test_returns_empty_when_dir_has_no_py_files(self, tmp_path):
        (tmp_path / "readme.txt").write_text("hello")
        assert load_plugin_checks(plugin_dir=tmp_path) == []

    def test_loads_valid_plugin(self, tmp_path):
        write_plugin(tmp_path, "my_check.py", VALID_PLUGIN)
        plugins = load_plugin_checks(plugin_dir=tmp_path)
        assert len(plugins) == 1

    def test_loads_multiple_plugins_sorted(self, tmp_path):
        write_plugin(tmp_path, "b_check.py", VALID_PLUGIN)
        write_plugin(tmp_path, "a_check.py", VALID_PLUGIN)
        plugins = load_plugin_checks(plugin_dir=tmp_path)
        assert len(plugins) == 2
        assert plugins[0].path.name == "a_check.py"
        assert plugins[1].path.name == "b_check.py"

    def test_skips_invalid_plugin_continues_loading(self, tmp_path):
        write_plugin(tmp_path, "bad_check.py", PLUGIN_NO_RUN_CHECK)
        write_plugin(tmp_path, "good_check.py", VALID_PLUGIN)
        plugins = load_plugin_checks(plugin_dir=tmp_path)
        assert len(plugins) == 1
        assert plugins[0].path.name == "good_check.py"

    def test_skips_syntax_error_plugin(self, tmp_path):
        write_plugin(tmp_path, "syntax_err.py", PLUGIN_SYNTAX_ERROR)
        write_plugin(tmp_path, "good.py", VALID_PLUGIN)
        plugins = load_plugin_checks(plugin_dir=tmp_path)
        assert len(plugins) == 1

    def test_ignores_non_py_files(self, tmp_path):
        (tmp_path / "not_a_plugin.txt").write_text(VALID_PLUGIN)
        assert load_plugin_checks(plugin_dir=tmp_path) == []

    def test_skips_plugin_that_raises_at_import(self, tmp_path):
        """A top-level raise in the plugin file must be caught and skipped."""
        write_plugin(tmp_path, "boom.py", PLUGIN_IMPORT_FAIL)
        assert load_plugin_checks(plugin_dir=tmp_path) == []

    def test_skips_partial_import_plugin_continues_loading(self, tmp_path):
        """Module that defines CHECK_NAME then raises must be skipped; others loaded."""
        write_plugin(tmp_path, "bad.py", PLUGIN_PARTIAL_IMPORT)
        write_plugin(tmp_path, "good.py", VALID_PLUGIN)
        plugins = load_plugin_checks(plugin_dir=tmp_path)
        assert len(plugins) == 1
        assert plugins[0].path.name == "good.py"


# ---------------------------------------------------------------------------
# _load_one — individual file loading
# ---------------------------------------------------------------------------

class TestLoadOne:
    def test_returns_plugin_check_on_valid_file(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", VALID_PLUGIN)
        pc = _load_one(path)
        assert pc is not None
        assert isinstance(pc, PluginCheck)

    def test_uses_check_name_from_module(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", VALID_PLUGIN)
        pc = _load_one(path)
        assert pc is not None
        assert pc.name == "MY CUSTOM CHECK"

    def test_derives_name_from_filename_when_no_check_name(self, tmp_path):
        path = write_plugin(tmp_path, "my_custom_check.py", PLUGIN_NO_NAME)
        pc = _load_one(path)
        assert pc is not None
        assert pc.name == "MY CUSTOM CHECK"

    def test_skips_file_without_run_check(self, tmp_path):
        path = write_plugin(tmp_path, "bad.py", PLUGIN_NO_RUN_CHECK)
        assert _load_one(path) is None

    def test_skips_syntax_error(self, tmp_path):
        path = write_plugin(tmp_path, "syntax.py", PLUGIN_SYNTAX_ERROR)
        assert _load_one(path) is None

    def test_skips_oversized_file(self, tmp_path):
        path = tmp_path / "big.py"
        # Write a file slightly over 64 KB
        path.write_bytes(b"x" * (64 * 1024 + 1))
        assert _load_one(path) is None

    def test_accepts_file_at_exactly_max_size(self, tmp_path):
        path = write_plugin(tmp_path, "exact.py", VALID_PLUGIN)
        # Pad to exactly 64 KB with comments
        content = VALID_PLUGIN + "\n# " + "x" * (64 * 1024 - len(VALID_PLUGIN) - 3)
        path.write_text(content, encoding="utf-8")
        pc = _load_one(path)
        assert pc is not None

    def test_path_stored_on_result(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", VALID_PLUGIN)
        pc = _load_one(path)
        assert pc is not None
        assert pc.path == path


# ---------------------------------------------------------------------------
# PluginCheck.run — execution and error isolation
# ---------------------------------------------------------------------------

class TestPluginCheckRun:
    def test_run_returns_check_result(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", VALID_PLUGIN)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run(_t)
        assert isinstance(result, CheckResult)

    def test_run_ok_finding_present(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", VALID_PLUGIN)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run(_t)
        levels = [f.level.value for f in result.findings]
        assert "ok" in levels

    def test_run_warn_and_deduction(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", PLUGIN_WITH_WARN)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run(_t)
        levels = [f.level.value for f in result.findings]
        assert "warn" in levels
        assert sum(d.points for d in result.deductions) == 1

    def test_run_exception_returns_warn_result(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", PLUGIN_RAISES)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run(_t)
        assert isinstance(result, CheckResult)
        levels = [f.level.value for f in result.findings]
        assert "warn" in levels

    def test_run_wrong_return_type_returns_warn(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", PLUGIN_WRONG_RETURN)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run(_t)
        levels = [f.level.value for f in result.findings]
        assert "warn" in levels

    def test_run_passes_t_to_plugin(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", PLUGIN_T_RECEIVED)
        pc = _load_one(path)
        assert pc is not None
        pc.run(_t)
        # Access the module attribute set by the plugin
        assert pc._module.received_t is _t

    def test_run_without_t_arg(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", VALID_PLUGIN)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run()   # no t argument
        assert isinstance(result, CheckResult)

    def test_exception_does_not_propagate(self, tmp_path):
        path = write_plugin(tmp_path, "check.py", PLUGIN_RAISES)
        pc = _load_one(path)
        assert pc is not None
        # Must not raise
        result = pc.run(_t)
        assert result is not None

    def test_error_message_contains_filename(self, tmp_path):
        path = write_plugin(tmp_path, "my_broken.py", PLUGIN_RAISES)
        pc = _load_one(path)
        assert pc is not None
        result = pc.run(_t)
        messages = " ".join(f.message for f in result.findings)
        assert "my_broken.py" in messages


# ---------------------------------------------------------------------------
# Name derivation edge cases
# ---------------------------------------------------------------------------

class TestNameDerivation:
    def test_empty_check_name_falls_back_to_filename(self, tmp_path):
        content = 'CHECK_NAME = ""\n' + PLUGIN_NO_NAME
        path = write_plugin(tmp_path, "fallback_check.py", content)
        pc = _load_one(path)
        assert pc is not None
        assert pc.name == "FALLBACK CHECK"

    def test_whitespace_only_check_name_falls_back(self, tmp_path):
        content = 'CHECK_NAME = "   "\n' + PLUGIN_NO_NAME
        path = write_plugin(tmp_path, "ws_check.py", content)
        pc = _load_one(path)
        assert pc is not None
        assert pc.name == "WS CHECK"

    def test_non_string_check_name_falls_back(self, tmp_path):
        content = "CHECK_NAME = 42\n" + PLUGIN_NO_NAME
        path = write_plugin(tmp_path, "int_name.py", content)
        pc = _load_one(path)
        assert pc is not None
        assert pc.name == "INT NAME"

    def test_ansi_sequences_stripped_from_check_name(self, tmp_path):
        content = 'CHECK_NAME = "\\033[31mHACKED\\033[0m"\n' + PLUGIN_NO_NAME
        path = write_plugin(tmp_path, "ansi_check.py", content)
        pc = _load_one(path)
        assert pc is not None
        assert "\033" not in pc.name
        assert "HACKED" in pc.name  # printable text preserved

    def test_control_only_check_name_falls_back_to_filename(self, tmp_path):
        content = 'CHECK_NAME = "\\x01\\x02\\x03"\n' + PLUGIN_NO_NAME
        path = write_plugin(tmp_path, "ctrl_check.py", content)
        pc = _load_one(path)
        assert pc is not None
        assert pc.name == "CTRL CHECK"
