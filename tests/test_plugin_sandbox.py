"""
Plugin sandbox runner — integration tests.

These tests drive the implementation of ``bob/_sandbox.py`` (T3 Step 2).
Before Step 2 lands, the entire suite fails at import time because
``bob._sandbox`` does not exist yet. After Step 2, the suite must pass.

Strategy: integration-first per project_v07x_phase1 rule 1. The known-bad
plugin suite under ``tests/plugins_adversarial/`` is the contract; each
plugin attempts one well-known escape vector and the test asserts the
sandbox blocked it.

T3 Phase 0 spec figée (decisions Q1'-Q6' from project_v07x_phase2):

  Q1' — RestrictedPython optional + warning (graceful degradation to D-only).
  Q2' — Import allowlist: bob.scoring, re, json, pathlib, datetime, typing,
        dataclasses, collections, enum, math, string, hashlib, os.path, stat.
  Q3' — Subprocess prevention: allowlist + restricted builtins + open wrapper.
  Q4' — FS access: read libre, write/append/exclusive modes blocked by open
        wrapper.
  Q5' — Plugin contract v2: ``BOB_SANDBOX_LEGACY=1`` env var trap door with
        flashy WARNING at startup.
  Q6' — Known-bad suite: 15 patterns in tests/plugins_adversarial/.

Run with: python -m pytest tests/test_plugin_sandbox.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# T3 integration-first signal: this whole file skips cleanly until Step 2
# lands ``bob/_sandbox.py``. Using ``importorskip`` avoids breaking the CI
# matrix between Step 1 (this commit) and Step 2 (next commit). When the
# module appears, the tests below drive its contract.
_sandbox = pytest.importorskip(
    "bob._sandbox",
    reason="T3 sandbox runner not yet implemented (Step 2 pending)",
)
SandboxRunner = _sandbox.SandboxRunner
SandboxRejected = _sandbox.SandboxRejected
PLUGIN_IMPORT_ALLOWLIST = _sandbox.PLUGIN_IMPORT_ALLOWLIST

from bob.scoring import CheckResult, FindingLevel


_ADVERSARIAL_DIR = Path(__file__).parent / "plugins_adversarial"

_ALL_ADVERSARIAL = sorted(
    p for p in _ADVERSARIAL_DIR.glob("*.py")
    if p.name not in {"__init__.py"}
)


@pytest.fixture
def runner() -> SandboxRunner:
    """Default-configured runner. Tests that need a custom config build
    their own instance directly."""
    return SandboxRunner(timeout_seconds=5.0)


# ===========================================================================
# Sanity — suite is well-formed
# ===========================================================================

class TestAdversarialSuiteShape:
    """The 15 known-bad plugins must all be present and well-formed."""

    def test_exactly_15_plugins_exist(self):
        assert len(_ALL_ADVERSARIAL) == 15, (
            f"Expected 15 adversarial plugins per Q6' spec, found "
            f"{len(_ALL_ADVERSARIAL)}: {[p.name for p in _ALL_ADVERSARIAL]}"
        )

    def test_each_plugin_has_run_check(self):
        """Each plugin must expose run_check — otherwise it can't even be
        loaded, which would not constitute a valid sandbox test."""
        for plugin in _ALL_ADVERSARIAL:
            content = plugin.read_text(encoding="utf-8")
            assert "def run_check(" in content, (
                f"{plugin.name} missing run_check() — invalid adversarial plugin"
            )


# ===========================================================================
# Allowlist contract — Q2'
# ===========================================================================

class TestImportAllowlist:
    """The allowlist exposed by the sandbox module must match the Q2' spec."""

    EXPECTED_ALLOWED = frozenset({
        "bob.scoring",
        "re", "json", "pathlib", "datetime", "typing",
        "dataclasses", "collections", "enum",
        "math", "string", "hashlib",
        "time",
        "os.path", "stat",
    })

    EXPECTED_BLOCKED = frozenset({
        "subprocess", "os", "sys", "socket", "ctypes",
        "multiprocessing", "threading", "asyncio",
        "urllib", "http", "ftplib", "smtplib",
        "shutil",
    })

    def test_allowlist_matches_spec(self):
        assert set(PLUGIN_IMPORT_ALLOWLIST) == self.EXPECTED_ALLOWED

    def test_blocked_modules_not_in_allowlist(self):
        leaked = self.EXPECTED_BLOCKED & set(PLUGIN_IMPORT_ALLOWLIST)
        assert not leaked, (
            f"Blocked modules leaked into allowlist: {leaked}. "
            f"Each leak is a sandbox escape vector."
        )


# ===========================================================================
# Each adversarial plugin runs to completion AND fails to escape — Q6'
# ===========================================================================

class TestAdversarialPluginsBlocked:
    """For every known-bad plugin: the runner returns a CheckResult (not a
    raised exception), and the destructive side-effect did NOT happen."""

    @pytest.mark.parametrize(
        "plugin_path", _ALL_ADVERSARIAL, ids=lambda p: p.name,
    )
    def test_plugin_runs_without_crashing_audit(self, runner, plugin_path):
        """The runner must catch all plugin-level exceptions and return a
        CheckResult so a single buggy plugin can't abort the audit."""
        result = runner.run(plugin_path)
        assert isinstance(result, CheckResult), (
            f"{plugin_path.name} crashed the runner instead of returning "
            f"a CheckResult. Got: {type(result).__name__}"
        )

    # Patterns that indicate the sandbox blocked the attack — either the
    # plugin's own OK message says "blocked", or the runner's wrapping
    # WARN message reflects a sandbox-effect (timeout, kill, ImportError
    # from the import hook, PermissionError from open / Path patches,
    # MemoryError from RLIMIT_AS, immutable builtins error).
    _SANDBOX_EFFECT_PATTERNS = (
        "blocked",
        "timed out",
        "killed",
        "memoryerror",
        "permissionerror",
        "not in import allowlist",
        "not allowed",
        "read-only",
        "sandbox",
    )

    @pytest.mark.parametrize(
        "plugin_path", _ALL_ADVERSARIAL, ids=lambda p: p.name,
    )
    def test_plugin_attack_did_not_succeed(self, runner, plugin_path, tmp_path):
        """The plugin's PLUGIN_TARGET (when defined) must NOT exist after
        the run. For attacks without a filesystem target, the plugin's own
        OK/WARN result is the signal we read."""
        # Clean potential leftover from a prior test run
        target = None
        content = plugin_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.startswith("PLUGIN_TARGET"):
                target = line.split("=", 1)[1].strip().strip('"\'')
                break
        if target and os.path.exists(target):
            os.unlink(target)

        result = runner.run(plugin_path)

        if target:
            assert not os.path.exists(target), (
                f"{plugin_path.name} successfully created {target!r} — "
                f"sandbox escape!"
            )
        # The plugin's OK finding signals the sandbox blocked it; a WARN
        # finding (other than the runner's own "plugin error" wrapper) means
        # the attack ran further than expected.
        ok_findings = [f for f in result.findings if f.level == FindingLevel.OK]
        if not target:
            # Network / threading / fork / globals / OOM / loop attacks do
            # not have a fs target; the runner's WARN wrapping (timeout,
            # ImportError) or the plugin's own OK finding signals the
            # sandbox effect.
            combined = "".join(f.message.lower() for f in result.findings)
            blocked = any(
                p in combined for p in self._SANDBOX_EFFECT_PATTERNS
            )
            assert ok_findings or blocked, (
                f"{plugin_path.name} produced no sandbox-effect signal "
                f"(OK 'blocked' finding nor warn with timeout/permission/"
                f"importerror/memory pattern) and has no filesystem target — "
                f"sandbox effect unverifiable. Findings: "
                f"{[(f.level.value, f.message) for f in result.findings]}"
            )


# ===========================================================================
# Q5' — BOB_SANDBOX_LEGACY=1 env var trap door
# ===========================================================================

class TestLegacyTrapDoor:
    """When BOB_SANDBOX_LEGACY=1 is set, plugins run un-sandboxed (legacy
    behaviour) but the runner must emit a flashy WARNING."""

    def test_legacy_mode_runs_without_restrictions(
            self, tmp_path, monkeypatch, capsys,
    ):
        # A plugin that simply imports subprocess — would be blocked under
        # sandbox, but in legacy mode it's allowed.
        plugin = tmp_path / "legacy_check.py"
        plugin.write_text(
            "from bob.scoring import CheckResult\n"
            "def run_check(t=None):\n"
            "    import subprocess\n"
            "    r = CheckResult()\n"
            "    r.ok(message=f'subprocess loaded: {subprocess.__name__}')\n"
            "    return r\n"
        )
        monkeypatch.setenv("BOB_SANDBOX_LEGACY", "1")
        runner_legacy = SandboxRunner(timeout_seconds=5.0)
        result = runner_legacy.run(plugin)
        # Under legacy: the subprocess import worked
        assert any(
            "subprocess" in f.message
            for f in result.findings
            if f.level == FindingLevel.OK
        )

    def test_legacy_mode_emits_warning(self, monkeypatch, capsys):
        monkeypatch.setenv("BOB_SANDBOX_LEGACY", "1")
        SandboxRunner(timeout_seconds=5.0)
        captured = capsys.readouterr()
        # Flashy WARNING must surface to stderr at instantiation
        assert "SANDBOX" in captured.err.upper()
        assert "LEGACY" in captured.err.upper()


# ===========================================================================
# Q4' — open() wrapper allows read, blocks write/append/exclusive
# ===========================================================================

class TestOpenWrapper:
    """A sandboxed plugin can read existing files but cannot create / mutate
    them. Pinned via a quick in-process plugin built ad-hoc."""

    def test_read_mode_allowed(self, runner, tmp_path):
        readable = tmp_path / "input.txt"
        readable.write_text("hello sandbox")
        plugin = tmp_path / "read_check.py"
        plugin.write_text(
            "from bob.scoring import CheckResult\n"
            f"def run_check(t=None):\n"
            f"    with open({str(readable)!r}, 'r') as f:\n"
            f"        content = f.read()\n"
            f"    r = CheckResult()\n"
            f"    r.ok(message=content)\n"
            f"    return r\n"
        )
        result = runner.run(plugin)
        assert any(
            "hello sandbox" in f.message
            for f in result.findings
        )

    @pytest.mark.parametrize("mode", ["w", "a", "x", "r+", "w+", "a+"])
    def test_write_modes_blocked(self, runner, tmp_path, mode):
        target = tmp_path / f"out_{mode.replace('+', 'p')}.txt"
        plugin = tmp_path / "write_check.py"
        plugin.write_text(
            "from bob.scoring import CheckResult\n"
            f"def run_check(t=None):\n"
            f"    r = CheckResult()\n"
            f"    try:\n"
            f"        with open({str(target)!r}, {mode!r}) as f:\n"
            f"            f.write('bypassed')\n"
            f"        r.warn(message='ATTACK SUCCEEDED')\n"
            f"    except PermissionError:\n"
            f"        r.ok(message='blocked')\n"
            f"    return r\n"
        )
        result = runner.run(plugin)
        assert not target.exists(), (
            f"open() in {mode!r} mode let the plugin create {target!r}"
        )


# ===========================================================================
# Timeout handling — Q6' pattern 15
# ===========================================================================

class TestRunnerTimeout:
    """A plugin that runs past the timeout must be killed and produce a
    clean WARN finding rather than crashing the audit."""

    def test_short_timeout_kills_long_plugin(self, tmp_path):
        plugin = tmp_path / "slow.py"
        plugin.write_text(
            "from bob.scoring import CheckResult\n"
            "import time\n"
            "def run_check(t=None):\n"
            "    time.sleep(30)\n"
            "    r = CheckResult()\n"
            "    r.warn(message='ran to completion')\n"
            "    return r\n"
        )
        runner_fast = SandboxRunner(timeout_seconds=0.5)
        result = runner_fast.run(plugin)
        # Plugin should NOT have reached its own WARN — the runner times
        # out and surfaces its OWN WARN finding instead.
        completed = [
            f for f in result.findings
            if "ran to completion" in f.message
        ]
        assert not completed, "Plugin survived past the timeout"


# ===========================================================================
# SandboxRejected — plugins that fail static validation
# ===========================================================================

class TestStaticRejection:
    """A plugin that doesn't expose run_check or that is syntactically
    invalid must be rejected up-front via SandboxRejected, not run."""

    def test_missing_run_check_rejected(self, runner, tmp_path):
        plugin = tmp_path / "no_check.py"
        plugin.write_text("# just a comment, no run_check\n")
        with pytest.raises(SandboxRejected):
            runner.run(plugin)

    def test_syntax_error_rejected(self, runner, tmp_path):
        plugin = tmp_path / "broken.py"
        plugin.write_text("def run_check(t=None\n    return None\n")
        with pytest.raises(SandboxRejected):
            runner.run(plugin)


# ===========================================================================
# v0.7.0b3 hardening pins — sub-agent + 3 PoC findings (C-1/C-2/I-1/I-2)
# ===========================================================================

class TestHardeningPins:
    """Tests that pin the v0.7.0b3 fixes derived from the sub-agent
    adversarial review (2026-05-31) + 3 confirmed PoC.

    These tests are NOT in the original Q6' 15-plugin suite — they
    document NEW contracts discovered during T3 Step 4 audit. See
    SECURITY.md "Threat model" + project_v070_t3_sandbox_threat_model
    memory for the full context.
    """

    def test_c1_pathlib_os_smuggle_blocked(self, runner, tmp_path):
        """C-1: ``from pathlib import os`` no longer yields a usable
        ``os.open`` / ``os.write`` etc. — the extended strip list
        removes raw fd primitives so the smuggled reference fails on
        attribute access."""
        sentinel = tmp_path / "c1_escape_evidence"
        plugin = tmp_path / "c1.py"
        plugin.write_text(f"""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    try:
        from pathlib import os as smug
        fd = smug.open({str(sentinel)!r}, smug.O_WRONLY | smug.O_CREAT, 0o644)
        smug.write(fd, b"escaped")
        smug.close(fd)
        r.warn(message="C-1 ATTACK SUCCEEDED")
    except Exception as exc:
        r.ok(message=f"blocked: {{type(exc).__name__}}")
    return r
""")
        result = runner.run(plugin)
        assert not sentinel.exists(), (
            "C-1 escape: pathlib.os smuggling allowed file write"
        )
        ok = any(f.level.value == "ok" and "blocked" in f.message for f in result.findings)
        assert ok, f"C-1 plugin should have reported blocked, got: {[f.message for f in result.findings]}"

    def test_c2_pickle_evil_template_vars_neutralized(self, runner, tmp_path):
        """C-2: a malicious ``__reduce__``-bearing object attached to
        ``CheckResult.findings[0].template_vars`` must NOT trigger code
        execution in the parent process. The worker's
        ``_serialize_check_result`` flattens all template_vars values
        to JSON-safe primitives before queue.put, so the parent's
        Queue.get returns a plain dict — no pickle-RCE opportunity."""
        sentinel = tmp_path / "c2_parent_pwned"
        plugin = tmp_path / "c2.py"
        plugin.write_text(f"""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    r.ok(message="legit")
    try:
        import json
        bins = json.dumps.__globals__["__builtins__"]
        eval_ref = bins.get("eval") if isinstance(bins, dict) else getattr(bins, "eval", None)
        def evil_reduce(self):
            return (eval_ref, ("__import__('os').system('touch {sentinel}')",))
        Evil = type("Evil", (object,), {{"__reduce__": evil_reduce}})
        r.findings[0].template_vars = {{"payload": Evil()}}
    except Exception as exc:
        r.info(message=f"setup: {{type(exc).__name__}}")
    return r
""")
        result = runner.run(plugin)
        # The unpickle path is closed: no parent-side code execution.
        assert not sentinel.exists(), (
            "C-2 escape: pickle RCE via template_vars succeeded in parent"
        )
        # The CheckResult still arrives — but the Evil object is stringified.
        assert any(f.message == "legit" for f in result.findings)
        # Verify template_vars was sanitized: the payload value is a str repr.
        first = result.findings[0]
        if "payload" in first.template_vars:
            assert isinstance(first.template_vars["payload"], str), (
                "C-2: template_vars payload should be flattened to str"
            )

    def test_i1_immutablebuiltins_no_dict_setitem_bypass(self, runner, tmp_path):
        """I-1: MappingProxyType replaces the dict-subclass approach so
        the classic ``dict.__setitem__(unbound_method, builtins, k, v)``
        bypass (which works against a dict subclass because the override
        is virtual-dispatched only) raises TypeError on the proxy."""
        plugin = tmp_path / "i1.py"
        plugin.write_text("""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    bins = globals()["__builtins__"]
    bypassed = False
    try:
        dict.__setitem__(bins, "smoke_evil", 42)
        bypassed = True
    except TypeError:
        pass
    if bypassed:
        r.warn(message="I-1 ATTACK SUCCEEDED — dict.__setitem__ mutated proxy")
    else:
        r.ok(message="I-1 blocked: mapping proxy rejected dict.__setitem__")
    return r
""")
        result = runner.run(plugin)
        ok = any(f.level.value == "ok" and "I-1 blocked" in f.message for f in result.findings)
        assert ok, f"I-1: expected blocked, got: {[(f.level.value, f.message) for f in result.findings]}"

    def test_i5_etc_shadow_read_denied(self, runner, tmp_path):
        """I-5: even in read mode, opening known-sensitive paths must
        raise PermissionError. ``/etc/shadow`` is the canonical case."""
        plugin = tmp_path / "i5.py"
        plugin.write_text("""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    try:
        open("/etc/shadow", "r")
        r.warn(message="I-5 ATTACK SUCCEEDED — /etc/shadow readable")
    except PermissionError:
        r.ok(message="I-5 blocked: /etc/shadow read denied")
    except FileNotFoundError:
        r.info(message="/etc/shadow does not exist on this system")
    return r
""")
        result = runner.run(plugin)
        # On a system where /etc/shadow exists, the deny-list must fire.
        # On a system where it doesn't, FileNotFoundError is acceptable.
        for f in result.findings:
            assert "I-5 ATTACK SUCCEEDED" not in f.message

    def test_i2_runner_supports_many_consecutive_runs(self, runner, tmp_path):
        """I-2: queue+thread cleanup means the runner can be reused
        across many plugins without leaking file descriptors. We don't
        directly count fds (platform-dependent), but a tight loop that
        would have leaked the queue's feeder thread before the fix
        must now complete cleanly."""
        plugin = tmp_path / "i2.py"
        plugin.write_text("""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    r.ok(message="ok")
    return r
""")
        # 20 consecutive runs — pre-fix this would leak 20 feeder threads
        # and 40 fds. Post-fix it cleans up after each.
        for _ in range(20):
            result = runner.run(plugin)
            assert isinstance(result, CheckResult)


# ===========================================================================
# Known limitation — architectural escape via stdlib __globals__ chain
# ===========================================================================

class TestKnownInProcessLimitation:
    """Documents the architectural escape that in-process Python
    sandboxing cannot close. This is **expected** behaviour — see
    SECURITY.md "Threat model" + PEP 416 (retracted) for the upstream
    consensus that in-process sandboxing is not a security boundary.

    The test exists so future contributors understand the bypass is
    KNOWN and INTENTIONALLY out-of-scope; closing it would require
    OS-level isolation (AppArmor, seccomp, namespaces) which BOB ships
    via its AppArmor profile but does not enforce in pure Python.

    What works in the test: the plugin reaches the REAL builtins via
    ``json.dumps.__globals__["__builtins__"]`` and obtains the real
    ``__import__``. What does NOT work: actually calling
    ``subprocess.run`` from there — the extended strip list removes
    primitives (``os.pipe`` etc.) that subprocess needs internally,
    breaking the practical attack chain. Future Python versions or
    stdlib refactors could re-open practical paths; the architectural
    bypass is fundamental.
    """

    def test_real_builtins_reachable_via_stdlib_globals(self, runner, tmp_path):
        """Plugin CAN reach the unrestricted builtins dict — this is
        the architectural limitation. The test pins it as KNOWN."""
        plugin = tmp_path / "arch.py"
        plugin.write_text("""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    try:
        import json
        bins = json.dumps.__globals__["__builtins__"]
        has_eval = ("eval" in bins) if isinstance(bins, dict) else hasattr(bins, "eval")
        has_real_import = ("__import__" in bins) if isinstance(bins, dict) else hasattr(bins, "__import__")
        if has_eval and has_real_import:
            r.info(message="known limitation: real builtins reachable")
        else:
            r.warn(message="unexpected: stdlib globals chain newly mitigated")
    except Exception as exc:
        r.info(message=f"chain failed: {type(exc).__name__}")
    return r
""")
        result = runner.run(plugin)
        # The known-limitation message MUST appear — if it doesn't,
        # either (a) the architectural escape has been closed (great,
        # update the docs!) or (b) the test plugin broke. Either case
        # is worth a contributor's attention.
        msgs = [f.message for f in result.findings]
        assert any("known limitation" in m for m in msgs), (
            f"Architectural escape unexpectedly mitigated or test broken: {msgs}"
        )

    def test_practical_subprocess_chain_blocked_by_strip_list(self, runner, tmp_path):
        """Even with real ``__import__``, the practical attack chain
        ``subprocess.run`` is broken because the extended strip list
        removes ``os.pipe`` (used internally by Popen)."""
        sentinel = tmp_path / "arch_practical_escape"
        plugin = tmp_path / "arch_practical.py"
        plugin.write_text(f"""\
from bob.scoring import CheckResult
def run_check(t=None):
    r = CheckResult()
    try:
        import json
        real_import = json.dumps.__globals__["__builtins__"]["__import__"]
        subprocess = real_import("subprocess")
        subprocess.run(["touch", {str(sentinel)!r}], capture_output=True)
        r.warn(message="practical chain succeeded")
    except Exception as exc:
        r.ok(message=f"practical chain broken: {{type(exc).__name__}}")
    return r
""")
        runner.run(plugin)
        assert not sentinel.exists(), (
            "Practical arch escape: subprocess.run executed via stdlib globals chain"
        )
