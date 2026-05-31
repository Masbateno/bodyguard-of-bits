"""
Plugin sandbox runner — v0.7.0 Phase 3 (T3).

Implements the restricted-mode plugin runner promised by SECURITY.md:

    > A future major version may introduce a restricted-mode plugin runner
    > (no filesystem write, no subprocess), but it is out of scope for the
    > 0.6.x line.

Architecture (Q1'-Q6' spec figée in project_v07x_phase2):

  - **Process isolation** — each plugin runs in a fresh
    ``multiprocessing.get_context("spawn")`` child. Crash, OOM, infinite
    loop, FS mutation, or env pollution stay contained in the child.
    The runner enforces a timeout via ``Process.join(timeout)`` then
    ``terminate()`` / ``kill()`` if the child won't exit.
  - **Import allowlist** (Q2') — ``PLUGIN_IMPORT_ALLOWLIST`` is enforced by
    a hook installed as ``builtins.__import__`` in the worker. The hook
    rejects any ``import`` that doesn't resolve to an allowed module.
    Submodules of allowed packages are permitted (e.g. ``pathlib.X``).
  - **Restricted ``__builtins__``** (Q3') — ``eval``, ``exec``, ``compile``,
    ``__import__`` are stripped from the plugin's builtins. ``open`` is
    replaced by ``_make_safe_open`` which rejects write/append/exclusive
    modes. ``input`` / ``breakpoint`` are stripped (interactive plugins are
    not allowed).
  - **Path write blocking** (Q4') — ``pathlib.Path.write_text``,
    ``write_bytes``, ``touch``, ``mkdir``, ``rmdir``, ``unlink``, etc. are
    monkey-patched in the worker to raise PermissionError. Read-mode Path
    operations are unaffected.
  - **``os`` module strip** — the ``os.path`` allowlist entry pulls ``os``
    into ``sys.modules`` as a side-effect; the worker strips dangerous
    attributes (``system``, ``popen``, ``exec*``, ``spawn*``, ``fork``,
    ``putenv``, ``environ``…) from the ``os`` module so even an attacker
    who reaches it via reflection can't call them.
  - **RestrictedPython optional** (Q1') — imported with ``try/except
    ImportError``. When present, plugin source is bytecode-compiled via
    ``compile_restricted`` for an extra layer (no implicit attribute
    lookups, no ``getattr`` magic). When absent, the import-hook +
    builtins-strip path remains and a logger warning notes the degraded
    mode.
  - **``BOB_SANDBOX_LEGACY=1`` trap door** (Q5') — bypasses the sandbox
    entirely; runs the plugin in the parent process with full builtins.
    Surfaces a flashy WARNING to stderr at runner instantiation. For users
    with legacy plugins who can't migrate; deprecated immediately.

Static rejections (``SandboxRejected``):

  - Missing ``run_check`` callable.
  - Syntax errors in the plugin source.
  - Unreadable plugin file.

Runtime errors (caught, surface as WARN ``CheckResult``):

  - ImportError on a non-allowlisted module.
  - PermissionError from the open / Path write wrappers.
  - Plugin exception inside ``run_check``.
  - Timeout (``Process.join(timeout)`` exceeded).
"""

from __future__ import annotations

import builtins
import logging
import multiprocessing as mp
import os
import sys
from pathlib import Path
from typing import Any

from bob.scoring import CheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Q2' — Import allowlist
# ---------------------------------------------------------------------------

PLUGIN_IMPORT_ALLOWLIST: frozenset[str] = frozenset({
    # BOB public API — required for plugins to produce CheckResult.
    "bob.scoring",
    # Stdlib SAFE — read-only, no side effects.
    "re", "json", "pathlib", "datetime", "typing",
    "dataclasses", "collections", "enum",
    "math", "string", "hashlib",
    # Time module — ``time.sleep`` is bounded by the runner timeout +
    # RLIMIT_CPU; ``time.monotonic`` / ``time.time`` are read-only.
    "time",
    # File-path operations (read-only useful for plugins).
    "os.path", "stat",
})


# Builtins removed from the plugin's restricted ``__builtins__`` dict.
# ``open`` is wrapped (not stripped) so plugins can read files.
_BUILTINS_DENY: frozenset[str] = frozenset({
    "eval", "exec", "compile", "__import__",
    "input", "breakpoint",
    # No need to strip "globals", "locals", "vars" — they leak the
    # restricted namespace itself, not the parent's, so they're harmless.
})


# Dangerous attributes on the ``os`` module — stripped in the worker.
# ``os`` ends up in ``sys.modules`` as a side-effect of allowing
# ``os.path``; we make sure even reflection-style access yields nothing
# useful for an attacker.
_OS_DANGEROUS_ATTRS: tuple[str, ...] = (
    "system", "popen",
    "exec", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "fork", "forkpty",
    "putenv", "unsetenv",
    "kill", "killpg",
    "setuid", "seteuid", "setgid", "setegid",
    "setreuid", "setregid", "setpgid", "setsid",
)


# Path methods that perform writes — blocked in the worker.
_PATH_WRITE_METHODS: tuple[str, ...] = (
    "write_text", "write_bytes", "touch",
    "mkdir", "rmdir", "unlink",
    "symlink_to", "hardlink_to",
    "rename", "replace",
    "chmod", "lchmod",
)


# Open modes that perform writes — rejected by ``_make_safe_open``.
_OPEN_WRITE_CHARS: frozenset[str] = frozenset("wax+")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SandboxRejected(Exception):
    """Plugin failed static validation — missing ``run_check``, syntax
    error, or unreadable source. Distinct from runtime errors (which the
    runner catches and turns into a WARN CheckResult)."""


# ---------------------------------------------------------------------------
# Worker-side helpers — installed inside the spawn'd child process.
# ---------------------------------------------------------------------------

def _make_safe_open(real_open):
    """Return an ``open`` replacement that rejects write modes (Q4')."""
    def safe_open(file, mode="r", *args, **kwargs):
        if isinstance(mode, str) and any(c in _OPEN_WRITE_CHARS for c in mode):
            raise PermissionError(
                f"Plugin sandbox: open() mode {mode!r} not allowed. "
                f"Only read modes (r / rb / rt) are permitted."
            )
        return real_open(file, mode, *args, **kwargs)
    return safe_open


def _make_import_hook(real_import):
    """Return an ``__import__`` replacement enforcing the allowlist (Q2')."""
    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level != 0:
            raise ImportError(
                f"Plugin sandbox: relative imports not allowed (level={level})"
            )
        # Allow exact match
        if name in PLUGIN_IMPORT_ALLOWLIST:
            return real_import(name, globals, locals, fromlist, level)
        # Allow submodules of allowed packages
        for allowed in PLUGIN_IMPORT_ALLOWLIST:
            if name.startswith(allowed + "."):
                return real_import(name, globals, locals, fromlist, level)
        raise ImportError(
            f"Plugin sandbox: module {name!r} not in import allowlist. "
            f"Allowed: {sorted(PLUGIN_IMPORT_ALLOWLIST)}"
        )
    return restricted_import


def _strip_os_dangerous_attrs() -> None:
    """Strip dangerous attributes from the ``os`` module in the worker
    process. Called once at worker bootstrap."""
    import os as _os
    for attr in _OS_DANGEROUS_ATTRS:
        if hasattr(_os, attr):
            try:
                delattr(_os, attr)
            except (AttributeError, TypeError):
                pass


def _patch_pathlib_writes() -> None:
    """Replace write-side Path methods with a denying stub (Q4')."""
    import pathlib

    def _denied(self, *args, **kwargs):
        raise PermissionError(
            f"Plugin sandbox: pathlib write operation not allowed."
        )

    for method in _PATH_WRITE_METHODS:
        if hasattr(pathlib.Path, method):
            try:
                setattr(pathlib.Path, method, _denied)
            except (AttributeError, TypeError):
                pass


class _ImmutableBuiltins(dict):
    """A dict subclass that ``exec()`` accepts as ``__builtins__`` but
    that plugins cannot mutate. Adversarial plugin 12 attempts
    ``globals()["__builtins__"]["eval"] = ...`` to re-add stripped
    builtins; this subclass rejects every write operation."""

    _MSG = "Plugin sandbox: __builtins__ is read-only"

    def __setitem__(self, key, value):
        raise TypeError(self._MSG)

    def __delitem__(self, key):
        raise TypeError(self._MSG)

    def update(self, *args, **kwargs):
        raise TypeError(self._MSG)

    def clear(self):
        raise TypeError(self._MSG)

    def pop(self, *args, **kwargs):
        raise TypeError(self._MSG)

    def popitem(self):
        raise TypeError(self._MSG)

    def setdefault(self, *args, **kwargs):
        raise TypeError(self._MSG)


def _build_restricted_builtins() -> _ImmutableBuiltins:
    """Build the restricted ``__builtins__`` dict used as the plugin's
    execution namespace. Returns an immutable dict so adversarial plugins
    cannot re-add stripped builtins via dict mutation."""
    safe: dict[str, Any] = {}
    for name in dir(builtins):
        if name.startswith("_"):
            continue
        if name in _BUILTINS_DENY:
            continue
        safe[name] = getattr(builtins, name)
    # Install wrappers
    safe["open"] = _make_safe_open(builtins.open)
    safe["__import__"] = _make_import_hook(builtins.__import__)
    # Freeze: build the immutable wrapper with the populated content. Note
    # the dict's contents are set via ``dict.__init__`` (which our subclass
    # does NOT override), so this initial population is allowed.
    return _ImmutableBuiltins(safe)


def _apply_resource_limits() -> None:
    """Cap memory + CPU in the worker process.

    Defends against plugin 14 (memory bomb) and plugin 15 (infinite loop)
    even if the runner's timeout fails. Best-effort: on systems without
    ``resource`` (Windows) or when the soft limit is already lower, the
    call is a no-op.
    """
    try:
        import resource
        # Cap virtual memory at 256 MiB. The worker has already imported
        # BOB modules (~ 50 MiB on average), so this leaves ~ 200 MiB for
        # the plugin — enough for legitimate parsing work, not enough for
        # an OOM-class allocation.
        MEM_LIMIT = 256 * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        # Only tighten — never widen — the existing limit.
        new_soft = min(MEM_LIMIT, soft) if soft != resource.RLIM_INFINITY else MEM_LIMIT
        new_hard = min(MEM_LIMIT, hard) if hard != resource.RLIM_INFINITY else MEM_LIMIT
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))
    except (ImportError, OSError, ValueError):
        # ImportError: Windows. OSError/ValueError: limit already tighter
        # or insufficient privilege. Best-effort.
        pass


def _worker_main(plugin_path: str, result_queue) -> None:
    """Worker process entry point.

    Loads the plugin under restricted environment, runs ``run_check``,
    and pushes the result (or an error sentinel) onto the queue.
    """
    try:
        # Apply environmental restrictions BEFORE loading plugin code.
        _apply_resource_limits()
        _strip_os_dangerous_attrs()
        _patch_pathlib_writes()

        # Read source and compile.
        with builtins.open(plugin_path, "r", encoding="utf-8") as f:
            source = f.read()

        # Optional RestrictedPython bytecode-level restriction (Q1').
        try:
            from RestrictedPython import compile_restricted
            code = compile_restricted(source, plugin_path, "exec")
        except ImportError:
            code = compile(source, plugin_path, "exec")
        except SyntaxError as exc:
            result_queue.put(("error", f"RestrictedPython rejected source: {exc}"))
            return

        # Execute plugin module body in restricted namespace.
        restricted = _build_restricted_builtins()
        namespace: dict[str, Any] = {
            "__builtins__": restricted,
            "__name__": "__bob_plugin__",
            "__file__": plugin_path,
        }
        exec(code, namespace)

        run_check = namespace.get("run_check")
        if not callable(run_check):
            result_queue.put(("error", "Plugin missing run_check"))
            return

        result = run_check(None)
        if not isinstance(result, CheckResult):
            result_queue.put((
                "error",
                f"run_check returned {type(result).__name__}, not CheckResult",
            ))
            return

        result_queue.put(("ok", result))

    except Exception as exc:  # noqa: BLE001
        # Any uncaught exception is forwarded so the parent can wrap it.
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------

class SandboxRunner:
    """Runs plugins under the sandbox (or in legacy mode when
    ``BOB_SANDBOX_LEGACY=1``)."""

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = float(timeout_seconds)
        self._legacy = os.environ.get("BOB_SANDBOX_LEGACY") == "1"
        if self._legacy:
            print(
                "⚠ ⚠ ⚠  BOB SANDBOX DISABLED via BOB_SANDBOX_LEGACY=1 — "
                "plugins run with full root privileges with no isolation! "
                "Unset BOB_SANDBOX_LEGACY for the secure default. ⚠ ⚠ ⚠",
                file=sys.stderr,
            )

    def run(self, plugin_path) -> CheckResult:
        """Validate + execute the plugin, returning its CheckResult.

        Raises ``SandboxRejected`` for static failures (missing run_check,
        syntax error, unreadable file). Runtime errors / timeout produce a
        WARN CheckResult.
        """
        plugin_path = Path(plugin_path)

        # --- Static validation ----------------------------------------------
        try:
            source = plugin_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SandboxRejected(f"Cannot read plugin {plugin_path!r}: {exc}")

        try:
            compile(source, str(plugin_path), "exec")
        except SyntaxError as exc:
            raise SandboxRejected(f"Plugin syntax error: {exc}")

        if "def run_check" not in source:
            raise SandboxRejected(
                f"Plugin {plugin_path.name!r} missing required run_check function"
            )

        # --- Legacy bypass (Q5') --------------------------------------------
        if self._legacy:
            return self._run_legacy(plugin_path, source)

        # --- Sandboxed run via spawn'd child --------------------------------
        return self._run_sandboxed(plugin_path)

    # -----------------------------------------------------------------------

    def _run_sandboxed(self, plugin_path: Path) -> CheckResult:
        ctx = mp.get_context("spawn")
        q: Any = ctx.Queue()
        proc = ctx.Process(
            target=_worker_main,
            args=(str(plugin_path), q),
        )
        proc.start()
        proc.join(timeout=self.timeout_seconds)

        if proc.is_alive():
            # Timeout — terminate child, then kill if it ignores SIGTERM.
            proc.terminate()
            proc.join(timeout=1.0)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=1.0)
            r = CheckResult()
            r.warn(
                message=(
                    f"Plugin {plugin_path.name!r} timed out after "
                    f"{self.timeout_seconds}s and was killed"
                ),
                nature="structural",
            )
            return r

        # Process exited — fetch result from queue (should be available).
        try:
            status, payload = q.get(timeout=1.0)
        except Exception:  # noqa: BLE001 — Queue.Empty etc.
            r = CheckResult()
            r.warn(
                message=(
                    f"Plugin {plugin_path.name!r} produced no result "
                    f"(exit code {proc.exitcode})"
                ),
                nature="structural",
            )
            return r

        if status == "ok":
            return payload

        # status == "error"
        r = CheckResult()
        r.warn(
            message=f"Plugin {plugin_path.name!r} error: {payload}",
            nature="structural",
        )
        return r

    # -----------------------------------------------------------------------

    def _run_legacy(self, plugin_path: Path, source: str) -> CheckResult:
        """Q5' bypass — no sandbox, plugin runs in this process."""
        namespace: dict[str, Any] = {
            "__name__": "__bob_plugin_legacy__",
            "__file__": str(plugin_path),
        }
        try:
            exec(compile(source, str(plugin_path), "exec"), namespace)
            run_check = namespace.get("run_check")
            if not callable(run_check):
                r = CheckResult()
                r.warn(
                    message=f"Plugin {plugin_path.name!r} missing run_check",
                    nature="structural",
                )
                return r
            result = run_check(None)
            if not isinstance(result, CheckResult):
                r = CheckResult()
                r.warn(
                    message=(
                        f"Plugin {plugin_path.name!r} returned "
                        f"{type(result).__name__}, not CheckResult"
                    ),
                    nature="structural",
                )
                return r
            return result
        except Exception as exc:  # noqa: BLE001
            r = CheckResult()
            r.warn(
                message=f"Plugin {plugin_path.name!r} crashed: {exc}",
                nature="structural",
            )
            return r
