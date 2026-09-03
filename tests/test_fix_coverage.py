"""
Coverage guard for ``--fix --apply`` (v0.8.0 drift batch lesson).

The v0.7.4 → v0.8.0 structural audit revealed that ~30% of WARN/ALERT
finding emissions in ``bob/checks/*.py`` were silently no-op for the
``--fix --apply`` flow because they lacked a ``cmd=`` kwarg. Operators
ran ``bob --fix --apply``, saw the prompt for each finding, accepted,
and the apply mode just printed ``✖ manual — apply the command
manually`` instead of actually executing a fix.

This file closes the gap: every actionable WARN/ALERT finding must
either:
  - ship a ``cmd=`` kwarg (auto-fixable), OR
  - have its key explicitly listed in ``_MANUAL_BY_DESIGN`` with a
    documented rationale (contextual decision, multi-step procedure,
    UEFI-level config, etc.).

Pattern mirrors ``tests/test_explain_coverage.py`` from the v0.8.0
backfill of the ``--explain`` gap. Same idea, different feature.

## How the whitelist works

``_MANUAL_BY_DESIGN`` lists finding keys that are NOT amenable to a
single shell command. Each entry has an inline reason. Adding a new
key here means: "I considered writing a cmd= for this and concluded
the action is genuinely manual."

Adding a new WARN/ALERT finding:
  1. If a one-line shell remediation exists → add ``cmd=`` to the call.
  2. If not → add the key to ``_MANUAL_BY_DESIGN`` with a one-line
     rationale. The whitelist is for documented decisions, not laziness.

The guard catches both regressions:
  - A new finding lacking cmd= AND not in the whitelist → test fails.
  - A finding in the whitelist that has gained cmd= → test fails (the
    whitelist must shrink as backfill progresses).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHECKS_DIR = _REPO_ROOT / "bob" / "checks"


# Methods that emit a finding the operator might want to act on.
# ``info`` / ``ok`` are informational — no fix action needed.
_ACTIONABLE_METHODS = frozenset({
    "warn",
    "alert",
    "warn_with_deduction",
    "alert_with_deduction",
})


# Finding keys that are intentionally NOT auto-fixable via a single
# shell command. Each entry needs a one-line rationale (inline comment)
# explaining WHY operating-system-level automation is inappropriate.
_MANUAL_BY_DESIGN = frozenset({
    # v0.15.4 "teeth": a container's isolation is fixed by the flags it was
    # started with. No command run ON THE HOST removes --privileged from a
    # container that is already running; the operator re-launches it without
    # the flag, which the detail text spells out. A cmd= here would hand the
    # reader something that cannot work.
    "container_security.privileged",
    "container_security.cap_sys_admin",
    "container_security.no_seccomp",
    # Contextual / strategic decisions — not a single command:
    "ddns.found",                                # contextual: is DDNS intentional?
    "ddns.warn",                                 # depends on which exposed port + intent
    "network_context.sensitive_remote",          # strategic: VPN, jump host, redesign
    "virt.snap_network",                         # audit-then-decide; snap remove vs keep
    "logs.brute_found",                          # trigger to install fail2ban (separate finding)

    # UEFI / firmware level — needs reboot + manual UEFI navigation:
    "secure_boot.disabled",                      # UEFI setting, no runtime command
    "secure_boot.setup_mode",                    # UEFI Platform-Key enrollment ritual

    # Multi-step procedures requiring inspection / per-instance config:
    "docker.iptables_bypass",                    # choice between option A/B/C documented in --explain
    "docker.exposed_port",                       # inspect each container, decide bind address
    "docker.exposed_bypass_ufw",                 # combine container restrict + daemon config
    "firewall_drivers.iptables_bypass",            # inspect rules, find source, remove cleanly
    "firewall_drivers.iptables_forward_bypass",    # idem (forward chain)
    "firewall_drivers.nftables_parallel",          # choice between UFW vs nftables, then purge other
    "services.exposure.open_local",              # LAN trust-level decision, multiple fix paths
    "services.state.active_disabled",            # service name is variable — `systemctl enable <SVC>`
    "services.state.installed_inactive_critical", # idem — name varies, may need config fix first
    "samba.null_passwords",                      # smb.conf section to identify + auth-mode choice
    "samba.guest_writable",                      # per-share fix in smb.conf
    "samba.guest_readonly",                      # per-share fix in smb.conf
    "file_perms.sudoers_nopasswd_all",           # visudo edit, NEVER chmod (locking yourself out)

    # Disruptive / interactive operations:
    "ssh.rsa_weak",                              # regenerating host key disconnects all existing clients
    "ssh.no_passphrase",                         # ssh-keygen -p is interactive (passphrase prompt)
    "ssh.authorized_keys_dsa",                   # judgment call: is the key still needed by anyone?
    "ssh.authorized_keys_weak_key",              # judgment call: rotation requires coordinating with key owner
    "ssh.authorized_keys_duplicate",             # judgment call: which copy is canonical?
    "ssh.weak_ciphers",                          # may overlap with existing custom Ciphers line in sshd_config
    "ssh.weak_macs",                             # idem (MACs)
    "ssh.weak_kex",                              # idem (KexAlgorithms)

    # Per-instance content where the count + identity is variable:
    "cron.pipe_to_shell",                  # per-cron-job inspection + rewrite
    "systemd_timers.pipe_to_shell",              # per-timer inspection + rewrite
})


# Call sites where ``key=`` is a variable (helper-managed dispatch over
# multiple finding keys), addressed by (file, enclosing function). Each entry
# documents which canonical keys the site can emit. The underlying helper must
# still pass a per-key cmd= via the call kwargs, OR every emitted key must be
# in ``_MANUAL_BY_DESIGN``.
#
# v0.15.5: these used to be (file, line number), and every insertion anywhere
# above a registered site failed this guard with no defect behind it. The old
# NOTE recorded v0.15.0 moving them twice; v0.15.5 moved the ssh one twice more
# in a single day. A guard that reports a defect when nothing is wrong is on
# its way to being ignored, which is the same failure mode as one that reports
# confidence it has not earned.
#
# A function may hold several dispatch sites — services.py has two — so the
# value is the union of what any site in that function can emit. That is the
# right granularity for the question being asked: are this site's possible keys
# accounted for.
_HELPER_DISPATCH_SITES: dict[tuple[str, str], tuple[str, ...]] = {
    # Emits one of three weak-algo keys depending on the t_key arg
    # (ssh.weak_ciphers / ssh.weak_macs / ssh.weak_kex). All three are
    # whitelisted above because the right fix depends on whether the
    # operator has a custom Ciphers/MACs/KexAlgorithms line.
    ("bob/checks/ssh/_subchecks.py", "_check_weak_algo"): (
        "ssh.weak_ciphers", "ssh.weak_macs", "ssh.weak_kex",
    ),
    # Emits services.exposed.<service.id> for high/critical services exposed
    # to the world. The per-service remediation lives in the explain entries;
    # the fix is service-specific.
    ("bob/checks/services.py", "_check_port_exposure"): (
        "services.exposed.<id>",
    ),
}


def _extract_key_literal(node: ast.Call) -> str | None:
    """Return the literal value of ``key=`` kwarg, or None if not extractable
    (e.g., key passed via ``**kwargs`` or a variable)."""
    for kw in node.keywords:
        if kw.arg == "key" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _has_cmd_kwarg(node: ast.Call) -> bool:
    """Return True if ``cmd=`` is among the call's explicit kwargs (excluding
    ``**kwargs`` unpacking — those are handled separately at the helper
    level)."""
    return any(kw.arg == "cmd" for kw in node.keywords)


def _has_kwargs_unpack(node: ast.Call) -> bool:
    """Return True if the call uses ``**kwargs`` star unpacking (helper
    pattern where cmd/key are passed via dict). These sites are not
    directly verifiable by AST scan — their containing helper must
    parameterise cmd via its dataclass / signature instead."""
    return any(kw.arg is None for kw in node.keywords)


def _enclosing_function(tree: ast.AST) -> dict[int, str]:
    """Map each Call node to the name of the function that contains it.

    ``ast.walk`` is breadth-first, so an outer function is visited before the
    ones nested in it and the innermost assignment wins. A call at module level
    gets no entry and is reported under "" — no dispatch site lives there, and
    a bare module-level call should be visible rather than silently keyed.
    """
    owner: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    owner[id(inner)] = node.name
    return owner


def _collect_actionable_call_sites() -> list[tuple[str, str, int, ast.Call]]:
    """Return (file_path, function, lineno, ast.Call) for every actionable
    method call in ``bob/checks/*.py``.

    The function name addresses the site; the line number is carried only so a
    failure can point at it.
    """
    sites: list[tuple[str, str, int, ast.Call]] = []
    for py in _CHECKS_DIR.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        owner = _enclosing_function(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _ACTIONABLE_METHODS:
                continue
            sites.append((
                str(py.relative_to(_REPO_ROOT)),
                owner.get(id(node), ""),
                node.lineno,
                node,
            ))
    return sites


def test_actionable_findings_have_cmd_or_are_whitelisted():
    """Every WARN/ALERT call must either ship cmd= or have its key in
    the _MANUAL_BY_DESIGN whitelist with a documented rationale.

    Sites using ``**kwargs`` unpacking are skipped here — those are
    helper-managed and verified by ``test_helper_directives_carry_cmd``.

    Sites with a variable ``key=`` (helper dispatching to multiple
    finding keys) must be registered in ``_HELPER_DISPATCH_SITES`` AND
    every key they can emit must be whitelisted.
    """
    sites = _collect_actionable_call_sites()
    missing: list[str] = []
    for file_path, func_name, lineno, node in sites:
        if _has_cmd_kwarg(node):
            continue
        if _has_kwargs_unpack(node):
            # Helper-managed (e.g., _apply_bad_directive). Verified by
            # the dedicated test below.
            continue
        key = _extract_key_literal(node)
        if key is None:
            # Non-literal key. Accepted only if the site is registered
            # in _HELPER_DISPATCH_SITES and all keys it dispatches to
            # are whitelisted.
            registered_keys = _HELPER_DISPATCH_SITES.get((file_path, func_name))
            if registered_keys is None:
                missing.append(
                    f"  {file_path}:{lineno} — non-literal key= and not "
                    f"registered in _HELPER_DISPATCH_SITES"
                )
                continue
            dispatched_unwhitelisted = [
                k for k in registered_keys
                if k not in _MANUAL_BY_DESIGN and not k.endswith(".<id>")
            ]
            if dispatched_unwhitelisted:
                missing.append(
                    f"  {file_path}:{lineno} — helper dispatch site emits "
                    f"{dispatched_unwhitelisted!r} which are not whitelisted"
                )
            continue
        if key in _MANUAL_BY_DESIGN:
            continue
        missing.append(f"  {file_path}:{lineno} — key={key!r}")

    assert not missing, (
        f"\n{len(missing)} actionable finding(s) without cmd= and not in "
        f"_MANUAL_BY_DESIGN whitelist:\n"
        + "\n".join(missing)
        + "\n\nFix path:\n"
        "  1. If a one-line shell remediation exists → add cmd= to the call.\n"
        "  2. If the action is genuinely manual (contextual / multi-step /\n"
        "     UEFI) → add the key to _MANUAL_BY_DESIGN with an inline\n"
        "     rationale.\n"
        "DO NOT add to the whitelist without writing the rationale."
    )


def test_dispatch_registry_names_functions_that_exist():
    """Every _HELPER_DISPATCH_SITES entry must name a live function.

    The failure mode the (file, function) key introduces in place of the old
    (file, line) one. A stale line number failed loudly on the next edit — the
    problem being that it failed on edits with no defect behind them. A stale
    *function name* fails quietly instead: the entry simply stops matching, and
    either a real dispatch site goes unregistered or an obsolete exemption
    lingers unnoticed. Cheap to check, so it is checked.
    """
    stale: list[str] = []
    for (file_path, func_name) in _HELPER_DISPATCH_SITES:
        source = _REPO_ROOT / file_path
        if not source.is_file():
            stale.append(f"  {file_path} — file no longer exists")
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        names = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if func_name not in names:
            stale.append(f"  {file_path}::{func_name} — no such function")

    assert not stale, (
        "\n_HELPER_DISPATCH_SITES entries pointing at nothing:\n"
        + "\n".join(stale)
        + "\n\nRemove the entry if the dispatch site is gone, or update the "
          "function name if it was renamed."
    )


def test_whitelist_entries_are_actually_emitted_today():
    """Every entry in _MANUAL_BY_DESIGN must correspond to a key emitted
    by some actionable call (directly via literal key= OR via a helper
    dispatch site registered in _HELPER_DISPATCH_SITES). Stale entries
    accumulate and silently mask new gaps.
    """
    sites = _collect_actionable_call_sites()
    emitted_keys = {_extract_key_literal(n) for _, _, _, n in sites}
    emitted_keys.discard(None)
    # Helper-managed dispatch sites: enumerate every key they can emit.
    for registered_keys in _HELPER_DISPATCH_SITES.values():
        for k in registered_keys:
            if not k.endswith(".<id>"):  # skip placeholder patterns
                emitted_keys.add(k)
    stale = sorted(_MANUAL_BY_DESIGN - emitted_keys)
    assert not stale, (
        f"\nStale entries in _MANUAL_BY_DESIGN:\n"
        + "\n".join(f"  - {k}" for k in stale)
        + "\n\nThese keys are no longer emitted by any actionable call. "
        "Remove them from the whitelist."
    )


def test_helper_directives_carry_cmd_template():
    """Specific helper: ``bob.checks.ssh._directives._BadDirective``
    table drives the eight common sshd_config directive findings. The
    helper invokes ``warn_with_deduction`` / ``alert_with_deduction`` via
    ``**kwargs`` — so the AST guard above cannot see individual keys.
    Instead, this test verifies the underlying table has a non-None
    ``cmd_template`` for every entry, which guarantees the helper passes
    cmd= for every emitted finding.

    If a future contributor adds a new entry without a cmd_template, the
    test fails and points them at the right place to fix.
    """
    from bob.checks.ssh._directives import _BAD_DIRECTIVES

    missing = [
        (rule.name, rule.key)
        for rule in _BAD_DIRECTIVES
        if getattr(rule, "cmd_template", None) in (None, "")
    ]
    assert not missing, (
        f"\n{len(missing)} _BadDirective entry(ies) without cmd_template:\n"
        + "\n".join(f"  - {name} (key={key})" for name, key in missing)
        + "\n\nAdd a cmd_template field to each entry; the helper passes "
        "it through as cmd= to the actionable call."
    )
