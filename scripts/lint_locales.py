#!/usr/bin/env python3
"""
v0.8.2 — Locale linter for ``bob/locales/{en,fr}.json``.

Catches the locale-drift classes that audit passes 7 + 8 surfaced in
the i18n migration (T10 / T60 / I-2 pass 7) before they hit the audit
guard or the user's shell:

  - **Strict EN/FR key parity** — every leaf key in en.json appears in
    fr.json and vice-versa. Drift here means a French audit shows
    bracketed-fallback placeholders.
  - **Placeholder set parity** — every ``{name}`` in an EN value matches
    the same set of ``{name}``s in the FR value. Drift here means
    ``str.format(**kwargs)`` either crashes (FR has a placeholder EN
    doesn't supply) or silently drops a contextual variable (EN has one,
    FR doesn't).
  - **Trailing whitespace contract** (I-2 pass 7) — for the
    ``cli.error.*_prefix`` keys whose colon-space is embedded in the
    value, both EN and FR must end with a space.
  - **Length sanity** — empty values + values > 500 chars are flagged
    (probably a copy-paste error or a missing translation).

Run: ``python3 scripts/lint_locales.py``

Exit code 0 = clean. Non-zero = at least one issue (CI hook).

This is a **dev tool**, not shipped at runtime — no ``bob`` import path.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


_ROOT       = Path(__file__).resolve().parent.parent
_LOCALES    = _ROOT / "bob" / "locales"

# Keys whose contract requires a trailing space (I-2 pass 7).
_TRAILING_SPACE_KEYS = (
    "cli.error.prefix",
    "cli.error.fatal_prefix",
    "cli.error.webhook_failed_prefix",
    "cli.error.warning_prefix",
)

# Placeholder regex — ``{name}`` or ``{name!r}`` / ``{name:fmt}``.
_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)(?:![rsa])?(?::[^}]*)?\}")

# Bumped from 500 → 1500 after the first run flagged 60+ legitimate
# ``explain.*.{why,how}`` paragraphs. The threshold catches genuine
# copy-paste mistakes (entire README, accidentally pasted document) but
# allows the longest documented technical descriptions.
_MAX_VALUE_LEN = 1500


def _flatten(d: dict, prefix: str = "") -> dict[str, str]:
    """Walk a nested locale dict and return a flat ``"a.b.c" -> "value"`` map."""
    out: dict[str, str] = {}
    for k, v in d.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, full))
        elif isinstance(v, str):
            out[full] = v
        else:
            # Unexpected non-string leaf — report as issue.
            out[full] = f"<non-string:{type(v).__name__}>"
    return out


def _placeholders(value: str) -> set[str]:
    """Return the set of ``{name}`` placeholders in *value*."""
    return set(_PLACEHOLDER_RE.findall(value))


def main() -> int:
    en = json.loads((_LOCALES / "en.json").read_text(encoding="utf-8"))
    fr = json.loads((_LOCALES / "fr.json").read_text(encoding="utf-8"))

    en_flat = _flatten(en)
    fr_flat = _flatten(fr)

    issues: list[str] = []

    # --- Strict EN/FR parity --------------------------------------------------
    en_only = set(en_flat) - set(fr_flat)
    fr_only = set(fr_flat) - set(en_flat)
    for k in sorted(en_only):
        issues.append(f"  [parity] {k!r} present in EN but missing in FR")
    for k in sorted(fr_only):
        issues.append(f"  [parity] {k!r} present in FR but missing in EN")

    # --- Placeholder set parity ----------------------------------------------
    for key in sorted(set(en_flat) & set(fr_flat)):
        en_phs = _placeholders(en_flat[key])
        fr_phs = _placeholders(fr_flat[key])
        if en_phs != fr_phs:
            issues.append(
                f"  [placeholder] {key!r}: EN has {sorted(en_phs)!r} but "
                f"FR has {sorted(fr_phs)!r}"
            )

    # --- Trailing whitespace contract (I-2 pass 7) ---------------------------
    for key in _TRAILING_SPACE_KEYS:
        for lang, flat in (("EN", en_flat), ("FR", fr_flat)):
            value = flat.get(key)
            if value is None:
                # Picked up by parity check above; skip duplicate.
                continue
            if not value.endswith(" "):
                issues.append(
                    f"  [trailing-space] {key!r} ({lang}) does not end with "
                    f"space — required since I-2 pass 7 v0.8.1"
                )

    # --- Length sanity --------------------------------------------------------
    for lang, flat in (("EN", en_flat), ("FR", fr_flat)):
        for key, value in flat.items():
            if value == "":
                issues.append(f"  [length] {key!r} ({lang}) is empty")
            elif len(value) > _MAX_VALUE_LEN:
                issues.append(
                    f"  [length] {key!r} ({lang}) is {len(value)} chars "
                    f"(max {_MAX_VALUE_LEN}) — probable copy-paste error"
                )

    # ---- Report --------------------------------------------------------------
    if issues:
        print(
            f"✖ locale lint found {len(issues)} issue(s):\n" + "\n".join(issues),
            file=sys.stderr,
        )
        return 1
    print(
        f"✔ locale lint clean: "
        f"{len(en_flat)} EN keys × {len(fr_flat)} FR keys, "
        f"0 parity drift, 0 placeholder drift, 0 trailing-space violation, "
        f"0 length anomaly"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
