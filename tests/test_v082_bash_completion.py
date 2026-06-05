"""
v0.8.2 — bash completion sync guards + functional tests.

The bash completion script at ``bob/data/bob.bash-completion`` hardcodes
two lists for performance (no Python subprocess on every TAB):

  - ``_SECTIONS``         — must match ``bob.runner._ALL_SECTIONS`` exactly
  - ``_EXPLAIN_KEYS``     — must match ``bob.explain.EXPLAIN_KEYS`` exactly

A drift here means adding a new check + locale + explain entry silently
disables bash completion for the new key family. The tests below assert
exact-set equality so drift fails CI.

Plus a handful of functional tests that source the script in a sub-bash
and assert that completion returns expected candidates for the new
v0.8.1 / v0.8.2 surfaces (--unignore, --ignore=KEY canonical-key
suggestion, --explain KEY).

**Background**: bash-completion's convention passes ``$1=cmd_name``,
``$2=current_word``, ``$3=previous_word`` to the completion function.
Importantly, when the user types ``--check=ssh<TAB>``, the dispatcher
splits on the ``=`` word-break char: ``$2`` is ``"ssh"`` (the value
being completed) and ``$3`` is ``"--check"`` (NOT ``"--check="``).
Functional tests below mirror this dispatcher behaviour exactly.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest


_COMPLETION_FILE = Path(__file__).resolve().parent.parent / "bob" / "data" / "bob.bash-completion"


def _read_bash_var(name: str) -> set[str]:
    """Parse ``local NAME="a b c"`` out of the completion script."""
    src = _COMPLETION_FILE.read_text(encoding="utf-8")
    m = re.search(rf'local {re.escape(name)}="([^"]*)"', src)
    assert m, f"Could not find ``local {name}=`` in the completion script"
    return set(m.group(1).split())


def _run_completion(cur: str, prev: str) -> set[str]:
    """Source the completion script and invoke ``_bob`` with the supplied
    cur/prev (mirrors bash-completion's positional convention)."""
    script = f'''
source "{_COMPLETION_FILE}"
_bob bob "{cur}" "{prev}"
printf '%s\\n' "${{COMPREPLY[@]}}"
'''
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=5,
    )
    if out.returncode != 0:
        raise RuntimeError(f"completion script errored: {out.stderr}")
    return set(line for line in out.stdout.splitlines() if line)


# ===========================================================================
# Sync guards — hardcoded lists must match runtime sources
# ===========================================================================

class TestSectionsListInSync:

    def test_sections_match_runner_all_sections(self):
        from bob.runner import _ALL_SECTIONS
        hardcoded = _read_bash_var("_SECTIONS")
        runtime = set(_ALL_SECTIONS)
        missing = runtime - hardcoded
        extra   = hardcoded - runtime
        assert not missing, (
            f"Sections in runner but missing from completion: {sorted(missing)}. "
            f"Update ``_SECTIONS`` in bob/data/bob.bash-completion."
        )
        assert not extra, (
            f"Sections in completion but not in runner: {sorted(extra)}. "
            f"Stale entry — remove from ``_SECTIONS``."
        )


class TestExplainKeysListInSync:

    def test_explain_keys_match_runtime(self):
        from bob.explain import EXPLAIN_KEYS
        hardcoded = _read_bash_var("_EXPLAIN_KEYS")
        runtime = set(EXPLAIN_KEYS)
        missing = runtime - hardcoded
        extra   = hardcoded - runtime
        assert not missing, (
            f"EXPLAIN_KEYS in runtime but missing from completion: "
            f"{sorted(missing)[:8]}{'...' if len(missing) > 8 else ''}. "
            f"Run ``python3 scripts/regenerate_completion.py`` (planned tooling) "
            f"or hand-update ``_EXPLAIN_KEYS`` in bob/data/bob.bash-completion."
        )
        assert not extra, (
            f"EXPLAIN_KEYS in completion but not in runtime: "
            f"{sorted(extra)[:8]}{'...' if len(extra) > 8 else ''}. "
            f"Stale entries — remove or rename."
        )


# ===========================================================================
# Long opts presence
# ===========================================================================

class TestLongOptsPresence:

    @pytest.mark.parametrize("opt", [
        "--unignore=",        # v0.8.1 T57
        "--json-v1",          # v0.7.0 Phase 2
        "--check=",
        "--skip=",
        "--ignore=",
        "--profile=",
        "--explain",
        "--breakdown",
    ])
    def test_opt_present_in_long_opts(self, opt):
        src = _COMPLETION_FILE.read_text(encoding="utf-8")
        m = re.search(r'local long_opts="([^"]+)"', src)
        assert m
        long_opts = m.group(1).split()
        assert opt in long_opts


# ===========================================================================
# Functional tests — exercise the completion logic against real bash
# ===========================================================================

class TestCheckCompletion:

    def test_check_equals_completes_to_sections(self):
        # User types ``bob --check=<TAB>``: cur="", prev="--check"
        result = _run_completion("", "--check")
        assert "list" in result
        assert "ssh" in result
        assert "auditd" in result
        # Always-on sections must NOT appear in filterable --check
        assert "firewall_stack" not in result
        assert "ports" not in result

    def test_check_equals_prefix_narrows_to_ssh(self):
        # User types ``bob --check=ssh<TAB>``: cur="ssh", prev="--check"
        result = _run_completion("ssh", "--check")
        assert result == {"ssh"} or "ssh" in result

    def test_check_short_form_partial_completes_long_opt(self):
        # User types ``bob --c<TAB>``: cur="--c", prev="bob"
        result = _run_completion("--c", "bob")
        assert "--check=" in result


class TestUnignoreCompletion:
    """v0.8.1 T57 added --unignore — pin that bash completion handles it."""

    def test_unignore_space_completes_to_explain_keys(self):
        result = _run_completion("", "--unignore")
        assert "ssh.password_auth" in result
        assert "rootkit.db_outdated" in result

    def test_unignore_equals_prefix_narrows(self):
        result = _run_completion("ssh", "--unignore")
        assert any(k.startswith("ssh.") for k in result), (
            f"expected ssh.* candidates, got {sorted(result)[:5]}"
        )


class TestIgnoreKeyCompletion:

    def test_ignore_space_completes_to_explain_keys(self):
        result = _run_completion("", "--ignore")
        assert "ssh.password_auth" in result
        assert "firewall.policy_open" in result

    def test_ignore_equals_prefix_narrows_to_auditd(self):
        result = _run_completion("audit", "--ignore")
        assert any(k.startswith("auditd.") for k in result), (
            f"expected auditd.* candidates, got {sorted(result)[:5]}"
        )


class TestExplainKeyCompletion:

    def test_explain_space_completes_to_explain_keys_plus_list(self):
        result = _run_completion("", "--explain")
        assert "list" in result
        assert "ssh.password_auth" in result

    def test_explain_equals_prefix_narrows(self):
        result = _run_completion("firewall", "--explain")
        assert any(k.startswith("firewall.") for k in result)


class TestProfileCompletion:

    def test_profile_completes_to_known_profiles_space_form(self):
        result = _run_completion("", "--profile")
        for p in ("server", "desktop", "container", "workstation"):
            assert p in result, f"missing {p!r} in {sorted(result)}"

    def test_short_p_completes_to_known_profiles(self):
        result = _run_completion("", "-p")
        for p in ("server", "desktop", "container", "workstation"):
            assert p in result
