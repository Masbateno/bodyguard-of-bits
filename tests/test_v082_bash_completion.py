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


_ROOT = Path(__file__).resolve().parent.parent
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
    """Every option the parser accepts must be completable.

    This was a list of eight names until v0.17.0, and a list protects the names
    on it. ``--test-email`` shipped without ever reaching the completion file
    because nobody thought to add a ninth line — the same shape as the doc
    counters that sat stale for six releases behind a guard pinned to four
    spellings. Read from the parser now, so an option added anywhere is covered
    the moment it exists.
    """

    #: Options the parser knows *in order to reject them*. They must not be
    #: offered for completion: suggesting a retired flag is worse than not
    #: suggesting it.
    _RETIRED = {
        # v0.9.0 F-3 retired the v0.6.x legacy schema; v0.9.1 kept the branch
        # so `bob --json-v1` explains itself instead of "unknown option".
        "--json-v1",
    }

    @staticmethod
    def _parser_options() -> set:
        src = (_ROOT / "bob" / "cli.py").read_text(encoding="utf-8")
        exact = set(re.findall(r'arg == "(--[a-z0-9-]+)"', src))
        valued = {f"{o}=" for o in re.findall(r'arg\.startswith\("(--[a-z0-9-]+)=', src)}
        return exact | valued

    def test_every_parser_option_is_completable(self):
        src = _COMPLETION_FILE.read_text(encoding="utf-8")
        m = re.search(r'local long_opts="([^"]+)"', src)
        assert m, "long_opts is gone or reshaped"
        long_opts = set(m.group(1).split())
        # A valued option may be listed either bare or with its `=`.
        offered = long_opts | {o.rstrip("=") for o in long_opts}
        missing = sorted(
            o for o in self._parser_options()
            if o not in self._RETIRED and o.rstrip("=") not in offered
        )
        assert not missing, (
            f"the parser accepts these but the completion never offers them: {missing}"
        )

    def test_no_retired_option_is_offered(self):
        src = _COMPLETION_FILE.read_text(encoding="utf-8")
        m = re.search(r'local long_opts="([^"]+)"', src)
        long_opts = set(m.group(1).split())
        offered = long_opts | {o.rstrip("=") for o in long_opts}
        bad = sorted(o for o in self._RETIRED if o in offered)
        assert not bad, f"the completion offers retired options: {bad}"

    def test_the_scrape_finds_options_at_all(self):
        """A scraper that matched nothing would satisfy both tests above."""
        found = self._parser_options()
        assert len(found) > 20, f"the cli.py option scrape broke: {sorted(found)}"
        assert "--test-email" in found and "--check=" in found


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
        assert "firewall_drivers" not in result
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
