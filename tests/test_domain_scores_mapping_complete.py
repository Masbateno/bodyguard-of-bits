"""
Guard against unmapped finding-key prefixes silently falling into the
"firewall" catch-all of :mod:`bob.domain_scores`.

This is option (a) of refactor audit finding #15 (v0.5.0): without an
explicit test, adding a new check that emits findings under a new
prefix would silently miscategorise those findings under the
"firewall" domain — no warning, no signal, the per-domain score box
just becomes inaccurate.

The test forces a contributor adding a new key prefix to either:

  * Add the prefix explicitly to ``_PREFIX_TO_DOMAIN`` in
    :file:`bob/domain_scores.py`, OR
  * Add it to :data:`_CATCH_ALL_BY_DESIGN` below with a justification.

The :data:`_CATCH_ALL_BY_DESIGN` allowlist captures the v0.4.x
state-of-the-art: prefixes that historically fell into the firewall
catch-all and where re-attributing them to a more semantic domain is
deferred to a future release (it changes scoring outputs — medium
risk, see refactor audit #15b).

AST-based scanning, same approach as :mod:`tests.test_locale_coverage`.
"""

from __future__ import annotations

import ast
from pathlib import Path

from bob.domain_scores import _PREFIX_TO_DOMAIN

_REPO_ROOT  = Path(__file__).resolve().parents[1]
_CHECKS_DIR = _REPO_ROOT / "bob" / "checks"

# Method names that BOB uses to emit findings with a ``key=`` kwarg.
# Hit on these via AST and we'll catch every static key emission.
_EMITTING_METHODS: frozenset[str] = frozenset({
    "add_deduction", "warn", "alert", "info", "ok",
})

# Prefixes that intentionally fall into the "firewall" catch-all. Each
# entry must have a one-line justification — these are NOT bugs, but
# decisions inherited from v0.4.x and to be revisited in finding #15b
# (Phase 5 of the v0.5.x refactor). When tightening this allowlist,
# remember the audit's medium-risk flag: changing a prefix's domain
# changes the per-domain score breakdown on production systems.
_CATCH_ALL_BY_DESIGN: dict[str, str] = {
    # Firewall/network surface — semantically *is* the firewall domain.
    "firewall":        "Self-mapping: the catch-all IS firewall",
    "firewall_rules":           "UFW rules analysis is part of firewall scoring",
    "ports":           "Port exposure is part of firewall surface",
    "services":        "Service exposure is part of firewall surface",
    "firewall_iptables":    "iptables/nftables fallback is firewall stack",
    "firewall_drivers":  "Firewall stack consistency analysis",
    "network_context": "Network interfaces / connections inventory",
    "ipv6":            "IPv6 consistency relative to UFW",
    "docker":          "Docker network exposure (port mappings)",
    "ddns":            "DDNS external exposure surface",

    # v0.4.x silent fallbacks reviewed in finding #15b (Phase 5 / v0.5.4):
    #   fail2ban     → moved to 'ssh' (primary purpose is SSH anti-bruteforce)
    #   virt         → moved to 'hardening' (KVM/bridge bypass is kernel surface)
    #   docker_audit → moved to 'hardening' (container hardening)
    # `smtp` and `desktop_apps` stay catch-all: no clean domain fit identified.
    "smtp":            "Local SMTP exposure (Postfix/Exim) — fits firewall surface semantics",
    "desktop_apps":    "Desktop process detection — INFO-only inventory, no clean domain fit",
    "prerequisites":   "Prerequisites check (UFW installed) — INFO-only, no scoring impact",
}


def _collect_static_key_prefixes() -> set[str]:
    """AST-scan bob/checks/ and return every literal ``key="X.Y"`` prefix.

    Considers only calls to methods listed in :data:`_EMITTING_METHODS`.
    Non-literal ``key=variable`` calls are ignored by design — same
    convention as :mod:`tests.test_locale_coverage`.
    """
    prefixes: set[str] = set()
    # rglob to traverse check packages (e.g. bob/checks/ssh/*.py post v0.6.0
    # #13 split). Single-file checks (bob/checks/*.py) still match at depth 1.
    for py in sorted(_CHECKS_DIR.rglob("*.py")):
        if py.name == "__init__.py":
            continue
        if "__pycache__" in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Match ``something.add_deduction(...)`` / ``.warn(...)`` etc.
            if not (isinstance(node.func, ast.Attribute)
                    and node.func.attr in _EMITTING_METHODS):
                continue
            for kw in node.keywords:
                if kw.arg != "key":
                    continue
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    full_key = kw.value.value
                    if "." in full_key:
                        prefixes.add(full_key.split(".", 1)[0])
    return prefixes


class TestDomainMappingCompleteness:
    """Refactor #15a: every emitted key prefix must be explicitly handled."""

    def test_every_emitted_prefix_is_mapped_or_whitelisted(self):
        emitted = _collect_static_key_prefixes()
        mapped  = set(_PREFIX_TO_DOMAIN.keys())
        catchall = set(_CATCH_ALL_BY_DESIGN.keys())

        unhandled = emitted - mapped - catchall
        assert not unhandled, (
            f"Finding-key prefixes emitted by bob/checks/*.py but neither "
            f"mapped in _PREFIX_TO_DOMAIN nor whitelisted in "
            f"_CATCH_ALL_BY_DESIGN: {sorted(unhandled)}\n"
            f"Either map the prefix to a domain in bob/domain_scores.py, "
            f"or add it to _CATCH_ALL_BY_DESIGN with a justification."
        )

    def test_no_stale_catchall_entries(self):
        """Whitelist entries that are no longer emitted should be removed."""
        emitted = _collect_static_key_prefixes()
        stale = set(_CATCH_ALL_BY_DESIGN.keys()) - emitted
        # We don't *fail* on stale entries — they may be retired prefixes
        # kept for forward-compat documentation. But surface them in the
        # test report so reviewers can prune deliberately.
        if stale:
            import warnings
            warnings.warn(
                f"_CATCH_ALL_BY_DESIGN entries not currently emitted by "
                f"any check (consider pruning): {sorted(stale)}",
                stacklevel=1,
            )

    def test_no_stale_prefix_to_domain_entries(self):
        """Same surface check for the explicit mapping table."""
        emitted = _collect_static_key_prefixes()
        # Some entries are emitted via dynamic keys (variable, not literal)
        # which our static scan misses. Allow these via the known list:
        _DYNAMIC_KEY_EMITTERS: frozenset[str] = frozenset({
            # Add prefixes here if a check emits via key=variable.
        })
        stale = (set(_PREFIX_TO_DOMAIN.keys()) - emitted - _DYNAMIC_KEY_EMITTERS)
        if stale:
            import warnings
            warnings.warn(
                f"_PREFIX_TO_DOMAIN entries not emitted by any static "
                f"call site (may use dynamic keys): {sorted(stale)}",
                stacklevel=1,
            )


class TestCatchAllJustifications:
    """Every catch-all entry must have a non-empty justification."""

    def test_all_entries_have_justifications(self):
        empty = [k for k, v in _CATCH_ALL_BY_DESIGN.items() if not v.strip()]
        assert not empty, (
            f"_CATCH_ALL_BY_DESIGN entries with empty justification: {empty}"
        )
