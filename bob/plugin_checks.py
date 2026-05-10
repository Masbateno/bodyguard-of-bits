"""
Plugin check loader for BOB.

Scans ~/.config/bob/checks.d/ for Python files that implement a
custom audit check and runs them as part of the audit pipeline.

Plugin contract
---------------
Each plugin is a Python file that must expose:

    def run_check(t=None) -> CheckResult:
        ...

The optional ``t`` argument is the active translation function.
Plugins typically write their own message strings — ``t`` is provided
for consistency and is safe to ignore.

Plugins may optionally define a module-level string to override the
section title shown in the report:

    CHECK_NAME = "MY CUSTOM CHECK"

Security note
-------------
Plugins run as root (BOB requires root).  Only place files in
checks.d/ that you trust.  BOB validates the file size and the
presence of ``run_check`` before loading, but does not sandbox execution.

Example plugin (~/.config/bob/checks.d/motd_check.py)
-------------------------------------------------------------
    from bob.scoring import CheckResult

    CHECK_NAME = "MOTD BANNER CHECK"

    def run_check(t=None):
        result = CheckResult()
        from pathlib import Path
        banner = Path("/etc/motd").read_text() if Path("/etc/motd").exists() else ""
        if banner.strip():
            result.ok("Custom banner found")
        else:
            result.info("No MOTD banner configured")
        return result
"""

from __future__ import annotations

import importlib.util
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bob.checks._run import TranslationFunc
from bob.scoring import CheckResult
from bob.sysinfo import get_user_home

logger = logging.getLogger(__name__)

_PLUGIN_CHECKS_DIR = get_user_home() / ".config" / "bob" / "checks.d"
_MAX_PLUGIN_SIZE   = 64 * 1024   # 64 KB — technical limit, not a security boundary

# Full ANSI CSI escape sequences (e.g. \x1b[31m) — must run before control-char filter
_ANSI_ESC_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
# Remaining control / non-printable characters
_CONTROL_RE   = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _sanitize_check_name(name: str) -> str:
    """Strip ANSI escape sequences and control characters from a plugin name."""
    name = _ANSI_ESC_RE.sub("", name)
    name = _CONTROL_RE.sub("", name)
    return name.strip()


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class PluginCheck:
    """
    A validated, loaded plugin check ready to run.

    Args:
        name:    Section title for display (from CHECK_NAME or filename stem).
        path:    Absolute path to the plugin source file.
        _module: Loaded Python module.
    """
    name:    str
    path:    Path
    _module: Any

    def run(self, t: TranslationFunc | None = None) -> CheckResult:
        """
        Execute the plugin's run_check() function.

        Catches all exceptions so a buggy plugin never aborts the audit.
        On error, returns a CheckResult with a single WARN finding.

        Args:
            t: Translation function (passed through to the plugin).

        Returns:
            CheckResult from the plugin, or an error CheckResult.
        """
        try:
            result = self._module.run_check(t)
            if not isinstance(result, CheckResult):
                raise TypeError(
                    f"run_check() must return a CheckResult, "
                    f"got {type(result).__name__!r}"
                )
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("Plugin %s raised an exception", self.path.name)
            error_result = CheckResult()
            error_result.warn(
                message=f"Plugin {self.path.name!r} error: {exc}",
                nature="structural",
            )
            return error_result


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_plugin_checks(
    plugin_dir: Path | None = None,
) -> list[PluginCheck]:
    """
    Scan the plugin checks directory and load all valid *.py files.

    Invalid files (too large, missing run_check, import errors) are
    logged and skipped — they never abort the audit.

    Args:
        plugin_dir: Override the default ~/.config/bob/checks.d/.
                    Useful in tests.

    Returns:
        List of PluginCheck objects in filename-sorted order.
    """
    directory = plugin_dir or _PLUGIN_CHECKS_DIR
    try:
        if not directory.is_dir():
            return []
        plugin_paths = sorted(directory.glob("*.py"))
    except PermissionError:
        # Directory exists but is not readable (e.g. owned by root from a sudo run).
        return []

    plugins: list[PluginCheck] = []
    for plugin_path in plugin_paths:
        check = _load_one(plugin_path)
        if check is not None:
            plugins.append(check)

    return plugins


def _load_one(plugin_path: Path) -> PluginCheck | None:
    """
    Attempt to load a single plugin file.

    Returns:
        PluginCheck on success, None if the file should be skipped.
    """
    # --- Size check ---
    try:
        size = plugin_path.stat().st_size
    except OSError as exc:
        logger.warning("Plugin %s: cannot stat: %s — skipped", plugin_path.name, exc)
        return None

    if size > _MAX_PLUGIN_SIZE:
        logger.warning(
            "Plugin %s: exceeds %d KB — skipped",
            plugin_path.name, _MAX_PLUGIN_SIZE // 1024,
        )
        return None

    # --- Load module ---
    # Include path hash to avoid sys.modules name collision when two plugins
    # share the same stem (e.g. symlinks or reloads during testing).
    module_name = f"bob_plugin_{plugin_path.stem}_{abs(hash(plugin_path))}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, plugin_path)
        if spec is None or spec.loader is None:
            raise ImportError("spec_from_file_location returned None")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Plugin %s: failed to load: %s — skipped", plugin_path.name, exc)
        return None

    # --- Validate interface ---
    if not callable(getattr(module, "run_check", None)):
        logger.warning(
            "Plugin %s: missing callable 'run_check' — skipped",
            plugin_path.name,
        )
        return None

    # --- Derive section title ---
    check_name = getattr(module, "CHECK_NAME", None)
    if not isinstance(check_name, str) or not check_name.strip():
        check_name = plugin_path.stem.upper().replace("_", " ")
    else:
        # Strip ANSI/control sequences a plugin could inject into the terminal
        check_name = _sanitize_check_name(check_name)
        if not check_name:
            check_name = plugin_path.stem.upper().replace("_", " ")

    logger.debug("Loaded plugin check %r from %s", check_name, plugin_path.name)
    return PluginCheck(name=check_name, path=plugin_path, _module=module)
