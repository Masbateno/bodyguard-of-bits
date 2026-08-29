"""
Plugin sandbox runner — v0.7.0 Phase 3 (T3).

==============================================================================
THREAT MODEL — read this first
==============================================================================

**In-process Python sandboxing is NOT a security boundary.** This module is
*defence-in-depth*, not adversarial protection. The Python community converged
on this position around 2012 (see PEP 416, retracted): a determined attacker
who controls plugin code can always reach the unrestricted builtins via the
``__globals__`` chain of any allowlisted stdlib module
(``json.dumps.__globals__["__builtins__"]``) — no Python-only mitigation can
close that fundamental escape without breaking legitimate use of those same
modules. RestrictedPython hardens *bytecode-level* attribute lookups, but the
``__globals__`` chain uses public attributes and dict access only, so even
RestrictedPython doesn't catch it.

What this sandbox **does** protect against:

  - **Accidents** — a buggy plugin that calls ``os.unlink`` by mistake,
    runs an infinite loop, allocates 2 GiB, or leaks a file handle.
  - **Naïve attacks** — a plugin that does ``import subprocess`` at module
    level or calls ``os.system(...)`` directly.
  - **Confused-deputy reads** — a plugin that opens ``/etc/shadow`` because
    the user forgot BOB runs as root.

What it does **NOT** protect against:

  - A determined attacker who has a Python escape playbook (5-line bypass).
  - Side-channel attacks via timing, scheduling, or shared memory.
  - Attacks that exploit BOB's own input-parsing surface (e.g. malicious
    ``sshd_config`` BOB tries to audit).

**Real adversarial isolation requires an OS-level boundary.** BOB ships an
AppArmor profile that enforces filesystem + capability restrictions on the
BOB process itself; this is the actual boundary against malicious plugins.
Distros that ship BOB in confined mode (snap, flatpak, container) inherit
their runtime's isolation. Users running BOB unconfined under ``sudo`` are
trusted-code-only — code review your plugins before installing them.

==============================================================================
Implementation overview (Q1'-Q6' spec from project_v07x_phase2)
==============================================================================

  - **Process isolation** — each plugin runs in a fresh
    ``multiprocessing.get_context("spawn")`` child. Crash, OOM, infinite
    loop, FS mutation, or env pollution stay contained in the child.
    The runner enforces a timeout via ``Process.join(timeout)`` then
    ``terminate()`` / ``kill()`` if the child won't exit.
  - **Import allowlist** (Q2') — ``PLUGIN_IMPORT_ALLOWLIST`` is enforced by
    a hook installed as ``__import__`` in the plugin's restricted builtins.
    The hook rejects any ``import`` that doesn't resolve to an allowed
    module. Submodules of allowed packages are permitted (e.g.
    ``pathlib.X``). **Known limitation**: stdlib modules pulled in
    transitively expose their own ``__globals__["__builtins__"]`` which
    is the real (un-restricted) dict.
  - **Restricted ``__builtins__``** (Q3') — ``eval``, ``exec``, ``compile``,
    ``__import__``, ``input``, ``breakpoint`` are stripped. The restricted
    mapping is an ``_ImmutableBuiltins`` dict subclass whose
    ``__setitem__``/etc. raise TypeError, blocking the natural-Python
    mutation path ``bins["eval"] = ...`` (plugin 12 globals_pollute). A
    determined attacker can bypass via ``dict.__setitem__(bins, ...)``
    unbound; this is a known limitation (I-1, kept on the defense-in-depth
    side because every fully-immutable alternative — ``MappingProxyType``,
    ``frozendict``, custom C type — breaks the C-level dict fast paths
    that ``exec()`` requires on Py 3.10/3.11/3.13/3.14, observed as
    ``SystemError`` from ``Objects/dictobject.c`` in v0.7.0b3 CI).
  - **Path + open wrappers** (Q4'+I-5) — ``open()`` rejects write modes
    and denies reads on a small list of well-known-secret paths
    (``/etc/shadow``, ``~/.ssh/id_*``, ``/dev/mem``…).
    ``pathlib.Path`` write methods are monkey-patched to raise.
  - **``os`` module strip** — the ``os.path`` allowlist pulls ``os`` into
    ``sys.modules``; the worker strips an extensive list of dangerous
    attributes (subprocess/spawn, raw fd ops, FS writes, privilege
    changes, env mutations). The list grew in v0.7.0b3 after a PoC
    showed ``from pathlib import os; os.open + os.write`` writing to
    arbitrary paths (C-1).
  - **Resource limits** — ``RLIMIT_AS = 256 MiB`` cap defends against
    memory bombs; ``RLIMIT_CPU = 10 s`` defends against infinite loops
    that ignore ``SIGTERM`` (M-4).
  - **JSON round-trip transport** (C-2, v0.7.0b3) — the worker
    serializes the plugin's CheckResult to a JSON-safe dict via
    ``_serialize_check_result`` BEFORE pushing onto the queue. The
    parent rebuilds a fresh CheckResult from the dict — never unpickles
    plugin-controlled objects. This closes the pickle-RCE path where a
    malicious ``__reduce__`` attached to ``template_vars`` could call
    ``eval`` in the parent process.
  - **Queue cleanup** (I-2, v0.7.0b3) — every ``_run_sandboxed`` body
    closes the queue and joins its feeder thread in a ``finally``
    block so file descriptors and threads don't leak across many
    plugin runs.
  - **RestrictedPython optional** (Q1') — imported with ``try/except
    ImportError``. When present, plugin source is bytecode-compiled via
    ``compile_restricted`` for an extra layer (no implicit attribute
    lookups, no ``getattr`` magic). When absent, the import-hook +
    builtins-strip path remains.
  - **``BOB_SANDBOX_LEGACY=1`` trap door** (Q5') — bypasses the sandbox
    entirely; runs the plugin in the parent process with full builtins.
    Surfaces a CRITICAL-level log entry AND a flashy stderr WARNING on
    every run that actually enters legacy mode (not just at runner
    construction). Will be removed in v0.8.0.

Static rejections (``SandboxRejected``):

  - Missing ``run_check`` (checked via AST — accepts ``def run_check``
    and ``run_check = ...`` forms; I-3).
  - Syntax errors in the plugin source.
  - Unreadable plugin file.

Runtime errors (caught, surface as WARN ``CheckResult``):

  - ImportError on a non-allowlisted module.
  - PermissionError from the open / Path write wrappers.
  - AttributeError on stripped os attributes.
  - Plugin exception inside ``run_check``.
  - Timeout (``Process.join(timeout)`` exceeded).
  - MemoryError from RLIMIT_AS hitting the cap.
"""

from __future__ import annotations

import ast
import builtins
import logging
import multiprocessing as mp
from pathlib import Path
from typing import Any

from bob.scoring import CheckResult, VALID_CONTEXTS as VALID_DEDUCTION_CONTEXTS

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
#
# IMPORTANT — this list is best-effort defence-in-depth, NOT a security
# boundary. A determined attacker can re-acquire any os attribute via the
# stdlib ``__globals__["__builtins__"]`` chain — see SECURITY.md and the
# module docstring "Threat model" section. The intent here is to defeat
# *accidental* misuse (a buggy plugin calls ``os.unlink``) and *naïve*
# attacks, not adversarial code.
_OS_DANGEROUS_ATTRS: tuple[str, ...] = (
    # --- Subprocess / process spawn -------------------------------------
    "system", "popen", "startfile",
    "exec", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
    "fork", "forkpty", "openpty",
    # --- Process control / signals --------------------------------------
    "kill", "killpg", "_exit", "abort",
    "wait", "wait3", "wait4", "waitpid", "waitid", "waitstatus_to_exitcode",
    "nice", "setpriority", "getpriority",
    # --- Privilege changes ---------------------------------------------
    "setuid", "seteuid", "setgid", "setegid",
    "setreuid", "setregid", "setpgid", "setsid", "setresuid", "setresgid",
    "setgroups", "initgroups",
    # --- Raw fd I/O (bypasses our open() wrapper) -----------------------
    "open", "read", "write", "close", "lseek",
    "pread", "pwrite", "preadv", "pwritev",
    "dup", "dup2", "dup3", "pipe", "pipe2",
    "fdopen", "ftruncate", "truncate",
    # --- Filesystem writes ---------------------------------------------
    "unlink", "remove", "rename", "replace", "removedirs",
    "mkdir", "makedirs", "rmdir",
    "chmod", "chown", "fchmod", "fchown", "lchmod", "lchown",
    "fchmodat", "fchownat", "chflags", "lchflags",
    "symlink", "link",
    "mkfifo", "mknod",
    "utime", "utimensat", "lutimes",
    # --- xattr writes --------------------------------------------------
    "setxattr", "removexattr", "lsetxattr", "lremovexattr",
    "fsetxattr", "fremovexattr",
    # --- Process / environment state ------------------------------------
    "chdir", "fchdir", "chroot", "umask",
    "putenv", "unsetenv", "environ", "environb",
    # --- Windows-specific (best-effort) ---------------------------------
    "add_dll_directory",
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


# Read-side paths denied even in read mode. The sandbox runs with the
# parent's UID; under ``sudo bob -d`` that's root, which can read every
# secret on the system. This deny-list is small and curated — it blocks
# the obviously-sensitive paths without a full read allowlist (which
# would break legitimate hardening checks reading e.g. /etc/ssh/sshd_config).
#
# Like ``_OS_DANGEROUS_ATTRS`` this is defence-in-depth, not a boundary.
_OPEN_READ_DENY_SUBSTRINGS: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers.d/",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/.ssh/id_",   # user private keys (id_rsa, id_ed25519, id_ecdsa, ...)
    "/.gnupg/",
    "/proc/kcore",
    "/proc/kmem",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SandboxRejected(Exception):
    """Plugin failed static validation — missing ``run_check``, syntax
    error, or unreadable source. Distinct from runtime errors (which the
    runner catches and turns into a WARN CheckResult)."""


def has_run_check(source: str) -> bool:
    """Return True if ``source`` defines ``run_check`` at module level.

    Accepts both ``def run_check(...)`` / ``async def run_check(...)``
    and the assignment form ``run_check = ...`` / ``run_check: Callable = ...``.
    Pure AST inspection — no exec, no substring match (so a stray
    comment ``# run_check`` doesn't cause a false-positive).

    Shared between ``plugin_checks._load_one`` and
    ``SandboxRunner.run`` so the two static gates agree (I-3).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run_check":
            return True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "run_check":
                    return True
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "run_check":
                return True
    return False


# ---------------------------------------------------------------------------
# Worker-side helpers — installed inside the spawn'd child process.
# ---------------------------------------------------------------------------

def _make_safe_open(real_open):
    """Return an ``open`` replacement that rejects write modes (Q4') and
    denies reads on known-sensitive paths (I-5).

    The path check converts ``file`` to ``str`` via ``os.fspath`` semantics
    and substring-matches against ``_OPEN_READ_DENY_SUBSTRINGS``. False
    positives on legitimate audit paths are accepted — plugins shouldn't
    need to read /etc/shadow.
    """
    def safe_open(file, mode="r", *args, **kwargs):
        if isinstance(mode, str) and any(c in _OPEN_WRITE_CHARS for c in mode):
            raise PermissionError(
                f"Plugin sandbox: open() mode {mode!r} not allowed. "
                f"Only read modes (r / rb / rt) are permitted."
            )
        # Reject reads on known-sensitive paths even in read mode.
        try:
            path_str = file if isinstance(file, (str, bytes)) else str(file)
            if isinstance(path_str, bytes):
                path_str = path_str.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — pathological __fspath__
            path_str = ""
        if any(deny in path_str for deny in _OPEN_READ_DENY_SUBSTRINGS):
            raise PermissionError(
                f"Plugin sandbox: open() on sensitive path {path_str!r} denied"
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
            "Plugin sandbox: pathlib write operation not allowed."
        )

    for method in _PATH_WRITE_METHODS:
        if hasattr(pathlib.Path, method):
            try:
                setattr(pathlib.Path, method, _denied)
            except (AttributeError, TypeError):
                pass


class _ImmutableBuiltins(dict):
    """A dict subclass that ``exec()`` accepts as ``__builtins__`` (CPython
    requires the builtins object to BE a dict, not just dict-like — a
    ``MappingProxyType`` triggers ``SystemError`` from the C-level dict
    fast-paths on Python 3.10 / 3.11 / 3.13 / 3.14, see v0.7.0b3→b4
    hotfix).

    Plugin 12 ("globals_pollute") tries to re-add stripped builtins via
    ``globals()["__builtins__"]["eval"] = real_eval`` — that goes through
    ``__setitem__``'s virtual dispatch and hits the override here, raising
    TypeError.

    KNOWN LIMITATION (I-1) — an attacker can bypass this override via
    ``dict.__setitem__(globals()["__builtins__"], "eval", real_eval)``
    (unbound base-class method skips the override). This is **not** closed
    because every fully-immutable alternative (MappingProxyType,
    ``frozendict``, custom C extension) breaks the C-level dict fast-path
    that ``exec()`` requires. The I-1 bypass is documented in
    ``SECURITY.md`` alongside the architectural escape — both fall on the
    "defence-in-depth, not a security boundary" side of the threat model.
    """

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
    execution namespace.

    Returns an ``_ImmutableBuiltins`` instance — a dict subclass whose
    ``__setitem__``/etc. raise TypeError. This blocks the
    ``globals()["__builtins__"]["eval"] = ...`` style mutation (plugin
    12), but is bypassable via ``dict.__setitem__(...)`` unbound — see
    the subclass docstring for the rationale.

    NOTE — like every other restriction in this module, this is
    defence-in-depth, NOT a security boundary: a plugin can still reach
    the unrestricted builtins via any allowlisted stdlib module's
    ``__globals__["__builtins__"]`` chain (see SECURITY.md threat model).
    """
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
    # ``dict.__init__`` populates without going through our override.
    return _ImmutableBuiltins(safe)


def _apply_resource_limits() -> None:
    """Cap memory + CPU in the worker process.

    Defends against plugin 14 (memory bomb) and plugin 15 (infinite loop)
    even if the runner's timeout fails. Best-effort: on systems without
    ``resource`` (Windows) or when the soft limit is already lower, the
    call is a no-op.

    Limits applied:
      - ``RLIMIT_AS = 256 MiB`` virtual memory cap. The worker has imported
        BOB modules (~ 50 MiB), leaving ~ 200 MiB for plugin work — enough
        for legitimate parsing, not enough for an OOM-class allocation.
      - ``RLIMIT_CPU = 10 seconds`` wall-clock CPU cap. Higher than the
        5s runner timeout so a normally-finishing plugin is never killed by
        CPU limit; only a runaway plugin that resists ``SIGTERM`` (e.g.
        long synchronous syscall) hits this and gets ``SIGKILL`` from
        the kernel.
    """
    try:
        import resource
    except ImportError:
        # Windows — no POSIX resource module.
        return

    # --- Memory cap -----------------------------------------------------
    try:
        MEM_LIMIT = 256 * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_soft = min(MEM_LIMIT, soft) if soft != resource.RLIM_INFINITY else MEM_LIMIT
        new_hard = min(MEM_LIMIT, hard) if hard != resource.RLIM_INFINITY else MEM_LIMIT
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))
    except (OSError, ValueError):
        # Limit already tighter or insufficient privilege. Best-effort.
        pass

    # --- CPU cap (defends against infinite loops that ignore SIGTERM) ---
    try:
        CPU_LIMIT = 10  # seconds — > 5s runner timeout
        soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        new_soft = min(CPU_LIMIT, soft) if soft != resource.RLIM_INFINITY else CPU_LIMIT
        new_hard = min(CPU_LIMIT, hard) if hard != resource.RLIM_INFINITY else CPU_LIMIT
        resource.setrlimit(resource.RLIMIT_CPU, (new_soft, new_hard))
    except (OSError, ValueError):
        pass


def _sanitize_for_transport(value):
    """Reduce ``value`` to JSON-primitive types (str/int/float/bool/None/list/dict).

    Non-primitive values are coerced via ``str()`` (called inside the
    worker — the parent never unpickles arbitrary objects). This is the
    core mitigation against the C-2 pickle-RCE escape: a malicious plugin
    cannot attach an ``Evil`` instance with a custom ``__reduce__`` to a
    ``template_vars`` dict and have the parent's ``Queue.get()``
    unpickle it; by the time the queue receives the payload, every leaf
    has been flattened to a primitive.
    """
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, list):
        return [_sanitize_for_transport(v) for v in value]
    if isinstance(value, tuple):
        return [_sanitize_for_transport(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _sanitize_for_transport(v) for k, v in value.items()}
    try:
        return str(value)
    except Exception:  # noqa: BLE001 — pathological __str__
        return "<unserializable>"


def _serialize_check_result(result: CheckResult) -> dict:
    """Convert a CheckResult to a JSON-safe dict for queue transport (C-2 mitigation).

    Only primitive types and lists/dicts thereof cross the
    parent/worker boundary, so an attacker cannot smuggle a custom
    ``__reduce__`` object through ``mp.Queue`` pickling.
    """
    return {
        "deductions": [
            {
                "reason":        str(d.reason),
                "points":        int(d.points),
                "context":       str(d.context),
                "key":           str(d.key),
                "template_vars": _sanitize_for_transport(d.template_vars)
                                 if isinstance(d.template_vars, dict) else {},
            }
            for d in result.deductions
        ],
        "findings": [
            {
                "level":         f.level.value if hasattr(f.level, "value") else str(f.level),
                "message":       str(f.message),
                "detail":        str(f.detail),
                "nature":        str(f.nature),
                "cmd":           str(f.cmd),
                "cmd_type":      str(f.cmd_type),
                "note":          str(f.note),
                "key":           str(f.key),
                "template_vars": _sanitize_for_transport(f.template_vars)
                                 if isinstance(f.template_vars, dict) else {},
            }
            for f in result.findings
        ],
        "open_ports": [str(p) for p in result.open_ports],
        "caps": [
            {
                "maximum": int(c.maximum),
                "reason":  str(c.reason),
                "key":     str(c.key),
            }
            for c in result.caps
        ],
    }


def _deserialize_check_result(data: dict) -> CheckResult:
    """Rebuild a CheckResult from the sanitized dict produced by the worker.

    Defensive against malformed payloads — missing fields fall back to
    safe defaults rather than raising. Invalid enum values for
    FindingLevel and invalid Deduction.context values fall back to
    INFO / 'local' so a buggy plugin cannot break the parent's
    rendering loop.
    """
    from bob.scoring import FindingLevel, Finding, Deduction, ScoreCap

    r = CheckResult()

    for d in data.get("deductions", []) or []:
        context = d.get("context", "local")
        if context not in VALID_DEDUCTION_CONTEXTS:
            context = "local"
        try:
            r.deductions.append(Deduction(
                reason=str(d.get("reason", "")),
                points=int(d.get("points", 0)),
                context=context,
                key=str(d.get("key", "")),
                template_vars=dict(d.get("template_vars") or {}),
            ))
        except (ValueError, TypeError):
            # Skip malformed deductions rather than abort the whole result.
            continue

    for f in data.get("findings", []) or []:
        try:
            level = FindingLevel(f.get("level", "info"))
        except ValueError:
            level = FindingLevel.INFO
        r.findings.append(Finding(
            level=level,
            message=str(f.get("message", "")),
            detail=str(f.get("detail", "")),
            nature=str(f.get("nature", "")),
            cmd=str(f.get("cmd", "")),
            cmd_type=str(f.get("cmd_type", "fix")),
            note=str(f.get("note", "")),
            key=str(f.get("key", "")),
            template_vars=dict(f.get("template_vars") or {}),
        ))

    for p in data.get("open_ports", []) or []:
        r.open_ports.append(str(p))

    for c in data.get("caps", []) or []:
        try:
            r.caps.append(ScoreCap(
                maximum=int(c.get("maximum", 10)),
                reason=str(c.get("reason", "")),
                key=str(c.get("key", "")),
            ))
        except (ValueError, TypeError):
            continue

    return r


def _worker_main(plugin_path: str, result_queue) -> None:
    """Worker process entry point.

    Loads the plugin under the restricted environment, runs ``run_check``,
    serializes the CheckResult to a JSON-safe dict, and pushes it on the
    queue. The dict-based protocol (rather than pickled CheckResult)
    closes the C-2 parent-process RCE: an attacker who manages to attach
    an ``Evil`` object with a custom ``__reduce__`` to e.g.
    ``findings[0].template_vars`` cannot have it survive the
    ``_sanitize_for_transport`` flattening pass.
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

        # C-2 mitigation: ship a sanitized dict, not the pickled CheckResult.
        try:
            payload = _serialize_check_result(result)
        except Exception as exc:  # noqa: BLE001 — pathological plugin output
            result_queue.put((
                "error",
                f"failed to serialize plugin result: {type(exc).__name__}: {exc}",
            ))
            return

        result_queue.put(("ok", payload))

    except Exception as exc:  # noqa: BLE001
        # Any uncaught exception is forwarded so the parent can wrap it.
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------

class SandboxRunner:
    """Runs plugins under the spawn'd-subprocess sandbox.

    v0.9.0 TD-1: the ``BOB_SANDBOX_LEGACY=1`` trap door (announced for
    retrait in v0.7.0 + v0.8.0 SECURITY.md notes) is removed. There is no
    longer a way to opt out of the sandbox via env var; plugins always
    execute in the spawn'd-subprocess context. If a plugin needs unrestricted
    builtins, it must be reworked to use the sandbox-allowed API surface
    or run outside ``bob`` entirely (e.g. as a separate cron job).
    """

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = float(timeout_seconds)

    def run(self, plugin_path, t=None) -> CheckResult:
        """Validate + execute the plugin, returning its CheckResult.

        Raises ``SandboxRejected`` for static failures (missing run_check,
        syntax error, unreadable file). Runtime errors / timeout produce a
        WARN CheckResult.

        M-4 (v0.7.4): the optional ``t`` parameter localises the runtime-error
        WARN messages so French audits don't surface English plugin errors.
        Defaults to None (English fallback) for back-compat.
        """
        plugin_path = Path(plugin_path)

        # --- Static validation ----------------------------------------------
        try:
            source = plugin_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # from exc: which OSError (EACCES? ENOENT?) is exactly what a plugin
            # author needs to see under BOB_DEBUG.
            raise SandboxRejected(f"Cannot read plugin {plugin_path!r}: {exc}") from exc

        try:
            compile(source, str(plugin_path), "exec")
        except SyntaxError as exc:
            raise SandboxRejected(f"Plugin syntax error: {exc}") from exc

        # AST-based presence check — accepts ``def run_check`` AND
        # ``run_check = ...`` (I-3). Shared with plugin_checks._load_one
        # via the module-level ``has_run_check`` helper so the two
        # gates agree.
        if not has_run_check(source):
            raise SandboxRejected(
                f"Plugin {plugin_path.name!r} missing required run_check function"
            )

        # v0.9.0 TD-1: the BOB_SANDBOX_LEGACY=1 bypass is removed. Plugins
        # always run in the spawn'd-subprocess sandbox.
        return self._run_sandboxed(plugin_path, t=t)

    # -----------------------------------------------------------------------

    def _run_sandboxed(self, plugin_path: Path, t=None) -> CheckResult:
        ctx = mp.get_context("spawn")
        q: Any = ctx.Queue()
        proc = ctx.Process(
            target=_worker_main,
            args=(str(plugin_path), q),
        )
        try:
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
                    message=_sandbox_msg(
                        t, "plugin.sandbox.timeout",
                        f"Plugin {plugin_path.name!r} timed out after "
                        f"{self.timeout_seconds}s and was killed",
                        plugin=repr(plugin_path.name),
                        seconds=self.timeout_seconds,
                    ),
                    key="plugin.sandbox.timeout",
                    nature="structural",
                )
                return r

            # Process exited — fetch result from queue (should be available).
            try:
                status, payload = q.get(timeout=1.0)
            except Exception as exc:  # noqa: BLE001 — Queue.Empty / pickle err
                logger.debug(
                    "Sandbox queue.get failed for %s: %s",
                    plugin_path.name, type(exc).__name__,
                )
                r = CheckResult()
                r.warn(
                    message=_sandbox_msg(
                        t, "plugin.sandbox.no_result",
                        f"Plugin {plugin_path.name!r} produced no result "
                        f"(exit code {proc.exitcode})",
                        plugin=repr(plugin_path.name),
                        exit_code=proc.exitcode,
                    ),
                    key="plugin.sandbox.no_result",
                    nature="structural",
                )
                return r

            if status == "ok":
                # Worker sent a JSON-safe dict — rebuild CheckResult in
                # the parent. See _serialize_check_result for the C-2
                # mitigation rationale.
                if isinstance(payload, dict):
                    return _deserialize_check_result(payload)
                # Back-compat / defensive: if a pre-fix worker shipped a
                # CheckResult instance, accept it (only safe because we
                # also control the worker code; future workers should
                # never reach this branch).
                if isinstance(payload, CheckResult):
                    return payload
                r = CheckResult()
                r.warn(
                    message=_sandbox_msg(
                        t, "plugin.sandbox.bad_payload",
                        f"Plugin {plugin_path.name!r} returned unexpected "
                        f"payload type: {type(payload).__name__}",
                        plugin=repr(plugin_path.name),
                        payload_type=type(payload).__name__,
                    ),
                    key="plugin.sandbox.bad_payload",
                    nature="structural",
                )
                return r

            # status == "error"
            r = CheckResult()
            r.warn(
                message=_sandbox_msg(
                    t, "plugin.sandbox.error",
                    f"Plugin {plugin_path.name!r} error: {payload}",
                    plugin=repr(plugin_path.name),
                    error=payload,
                ),
                key="plugin.sandbox.error",
                nature="structural",
            )
            return r
        finally:
            # I-2: explicitly close the queue and join its feeder thread
            # so file descriptors and the background thread don't leak
            # across many plugin runs.
            try:
                q.close()
                q.join_thread()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass

    # -----------------------------------------------------------------------

    # v0.9.0 TD-1: ``_run_legacy`` removed alongside the BOB_SANDBOX_LEGACY=1
    # trap door. Pre-v0.9.0 this method exec'd the plugin in the parent
    # process namespace; in v0.9.0+ every plugin runs in the spawn'd
    # subprocess via ``_run_sandboxed``.


# M-4 (v0.7.4): tiny i18n helper for sandbox WARN messages. Resolves
# ``locale_key`` via ``t`` if provided AND the lookup succeeds; otherwise
# falls back to the English ``fallback`` string. Keeps the call sites tight.
def _sandbox_msg(t, locale_key: str, fallback: str, **fmt: Any) -> str:
    if t is None:
        return fallback
    try:
        translated = t(locale_key, **fmt)
    except Exception:  # noqa: BLE001 — never let i18n abort a sandbox error path
        return fallback
    # Unknown keys: bob.i18n.t returns ``"[key]"`` or ``key`` verbatim — both
    # are useless as user-facing messages, fall back to English.
    if translated in (locale_key, f"[{locale_key}]"):
        return fallback
    return translated
