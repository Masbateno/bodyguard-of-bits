"""
Plugin check loader for BOB.

Scans ``~/.config/bob/checks.d/`` for Python files that implement a custom
audit check and runs them as part of the audit pipeline.

Plugin contract
---------------
Each plugin is a Python file that must expose:

    def run_check(t=None) -> CheckResult:
        ...

Plugins may optionally define a module-level string to override the
section title shown in the report:

    CHECK_NAME = "MY CUSTOM CHECK"

Security model (v0.7.0 Phase 3)
-------------------------------
Since v0.7.0, plugins run in a **restricted sandbox** by default:

  - Process isolation via ``multiprocessing.get_context("spawn")``.
  - Import allowlist (``bob.scoring`` + safe stdlib only).
  - ``open()`` wrapper that rejects write/append/exclusive modes.
  - ``pathlib.Path`` write methods stubbed.
  - ``os`` dangerous attributes (``system``, ``popen``, ``exec*``, ``fork``,
    ``putenv``…) stripped.
  - 256 MiB virtual memory cap + 5s wall-clock timeout per run.
  - Restricted ``__builtins__`` (no ``eval`` / ``exec`` / ``compile`` /
    ``__import__`` / ``input``).

The module body of the plugin is **never** loaded into the parent BOB
process — it executes only in the sandboxed child. This defeats top-level
malicious code (no ``import subprocess`` at module load time can pwn the
audit).

For the migration window, ``BOB_SANDBOX_LEGACY=1`` opts out of the sandbox
entirely and runs the plugin in the parent process with full builtins. A
flashy WARNING is printed to stderr at runner instantiation. This trap door
is deprecated immediately and will be removed in v0.8.0.

See ``bob/_sandbox.py`` for the runner implementation and
``tests/plugins_adversarial/`` for the known-bad attack patterns the
runner blocks.

Example plugin (``~/.config/bob/checks.d/motd_check.py``)
---------------------------------------------------------
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

import ast
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from bob._sandbox import SandboxRejected, SandboxRunner, has_run_check
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


def _extract_check_name_from_source(source: str) -> str | None:
    """Parse the plugin AST and extract the module-level ``CHECK_NAME``.

    Does NOT execute any plugin code — the AST walk is a pure read. Only
    string literals assigned directly to ``CHECK_NAME`` at module level are
    accepted; complex expressions are ignored (the loader falls back to
    deriving the name from the filename).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "CHECK_NAME"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return node.value.value
    return None


# ---------------------------------------------------------------------------
# Runner singleton — instantiated once so the BOB_SANDBOX_LEGACY warning
# prints once at first plugin load rather than once per plugin.
# ---------------------------------------------------------------------------

_runner: SandboxRunner | None = None


def _get_runner() -> SandboxRunner:
    global _runner
    if _runner is None:
        _runner = SandboxRunner(timeout_seconds=5.0)
    return _runner


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class PluginCheck:
    """
    A validated plugin check ready to be executed by the sandbox runner.

    Note: prior to v0.7.0, this dataclass also held a loaded Python module
    (``_module: Any``). That field was removed when plugin execution moved
    to the sandbox — the parent process never loads the plugin code, which
    defeats top-level malicious imports.

    Args:
        name: Section title for display (from ``CHECK_NAME`` or filename stem).
        path: Absolute path to the plugin source file. The runner reads the
              source from this path each time ``run()`` is called.
    """
    name: str
    path: Path

    def run(self, t: TranslationFunc | None = None) -> CheckResult:
        """
        Execute the plugin in the sandbox and return its CheckResult.

        The translation function ``t`` is accepted for API compatibility with
        the pre-v0.7.0 contract but is NOT passed to the plugin — the
        sandbox cannot carry over the parent's i18n state across the
        spawn'd subprocess. Plugins are expected to write their own message
        strings (the original contract has always documented ``t`` as "safe
        to ignore").

        M-4 (v0.7.4): ``t`` is now forwarded into the runner so the
        sandbox-side WARN messages (timeout / no_result / bad_payload /
        error) are translated. The plugin's *own* messages still come
        directly from its run_check body.

        Returns the plugin's CheckResult on success, or a WARN-only
        CheckResult on any runtime error / timeout / sandbox rejection so a
        single buggy plugin can never abort the audit. Each WARN carries a
        stable ``key=`` so ``bob --ignore plugin.sandbox.timeout`` works.
        """
        runner = _get_runner()
        try:
            return runner.run(self.path, t=t)
        except SandboxRejected as exc:
            r = CheckResult()
            r.warn(
                message=_warn_msg(
                    t, "plugin.sandbox.rejected",
                    f"Plugin {self.path.name!r} rejected: {exc}",
                    plugin=repr(self.path.name), error=exc,
                ),
                key="plugin.sandbox.rejected",
                nature="structural",
            )
            return r
        except Exception as exc:  # noqa: BLE001 — defence in depth
            logger.exception(
                "Plugin %s: sandbox runner raised unexpectedly", self.path.name,
            )
            r = CheckResult()
            r.warn(
                message=_warn_msg(
                    t, "plugin.sandbox.runner_error",
                    f"Plugin {self.path.name!r} runner error: {exc}",
                    plugin=repr(self.path.name), error=exc,
                ),
                key="plugin.sandbox.runner_error",
                nature="structural",
            )
            return r


# M-4 (v0.7.4): mirror of _sandbox._sandbox_msg for the wrapper layer.
def _warn_msg(t, locale_key: str, fallback: str, **fmt) -> str:
    if t is None:
        return fallback
    try:
        translated = t(locale_key, **fmt)
    except Exception:  # noqa: BLE001
        return fallback
    if translated in (locale_key, f"[{locale_key}]"):
        return fallback
    return translated


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_plugin_checks(
    plugin_dir: Path | None = None,
) -> list[PluginCheck]:
    """
    Scan the plugin checks directory and load all valid ``*.py`` files.

    Invalid files (too large, missing run_check, syntax error) are logged
    and skipped — they never abort the audit.

    Args:
        plugin_dir: Override the default ``~/.config/bob/checks.d/``.
                    Useful in tests.

    Returns:
        List of ``PluginCheck`` objects in filename-sorted order.
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
    Validate a single plugin file WITHOUT executing it.

    Pre-v0.7.0 this used ``importlib.util.spec_from_file_location`` +
    ``exec_module`` to load the plugin into the parent process. The new
    sandbox model defers all execution to the spawn'd child, so this
    function only:

      - Caps file size at ``_MAX_PLUGIN_SIZE`` (technical limit).
      - Confirms the source parses without ``SyntaxError``.
      - Confirms the source defines a ``run_check`` function (AST walk).
      - Extracts ``CHECK_NAME`` via AST (no exec).

    Returns ``PluginCheck`` on success, ``None`` if the file should be
    skipped.
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

    # --- Read source (no exec) ---
    try:
        source = plugin_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Plugin %s: cannot read: %s — skipped", plugin_path.name, exc)
        return None

    # --- Syntax check (AST parse only, no exec) ---
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        logger.warning(
            "Plugin %s: syntax error: %s — skipped",
            plugin_path.name, exc,
        )
        return None

    # --- run_check presence check ---
    # Accepts both ``def run_check`` and ``run_check = ...`` assignments
    # via the shared helper. Matches the sandbox runner's gate exactly
    # so a plugin that passes one passes the other (I-3).
    if not has_run_check(source):
        logger.warning(
            "Plugin %s: missing 'run_check' at module level (no def or assignment) — skipped",
            plugin_path.name,
        )
        return None

    # --- Derive section title ---
    raw_name = _extract_check_name_from_source(source)
    if isinstance(raw_name, str) and raw_name.strip():
        check_name = _sanitize_check_name(raw_name)
        if not check_name:
            check_name = plugin_path.stem.upper().replace("_", " ")
    else:
        check_name = plugin_path.stem.upper().replace("_", " ")

    logger.debug("Loaded plugin check %r from %s", check_name, plugin_path.name)
    return PluginCheck(name=check_name, path=plugin_path)
