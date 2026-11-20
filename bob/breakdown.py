"""
Score breakdown display for BOB (--breakdown flag).

Reads the finalized ScoreEngine and prints the full score computation path:
  1. Deductions applied (key, domain, points, context)
  2. Tool caps that reduced domain contributions
  3. Engine cap (if any)
  4. Raw score (before domain average)
  5. Per-domain scores (active domains only)
  6. Domain-average override applied
  7. Final score

Nothing is computed here — all data comes from the already-finalized engine.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bob.scoring import ScoreEngine

from bob.checks._run import TranslationFunc

from bob.domain_scores import (
    DOMAINS,
    LABELS,
    TOOL_CAPS,
    key_to_domain,
)
from bob.scoring import MAX_SCORE

from bob.output import SCORE_BAR_WIDTH as _BAR_WIDTH  # single source of truth, see bob.output


def _bar(score: int) -> str:
    """Render the breakdown bar via the shared `output.score_bar` helper
    (colours: green >=8, yellow 5–7, red 0–4).
    """
    from bob.output import score_bar
    # Map raw score (which may exceed MAX_SCORE on intermediate computations)
    # to the 0-10 range expected by score_bar.
    clamped = min(_BAR_WIDTH, max(0, round(score * _BAR_WIDTH / MAX_SCORE)))
    return score_bar(clamped)


def _domain_label(domain_id: str, t) -> str:
    """Return a translated domain label, falling back to LABELS then domain_id."""
    translated = t(f"domain_scores.{domain_id}")
    if translated != f"domain_scores.{domain_id}":
        return translated
    return LABELS.get(domain_id, domain_id.capitalize())


def display_breakdown(engine: "ScoreEngine", t: TranslationFunc | None, output_mod) -> None:
    """
    Print the full score computation path for *engine*.

    Args:
        engine:     Finalized ScoreEngine (finalize() + apply_domain_score_override() done).
        t:          Translation function.
        output_mod: The bob.output module.
    """
    output_mod.print_section(t("breakdown.section_title"))

    # ------------------------------------------------------------------ #
    # 1. Deductions                                                        #
    # ------------------------------------------------------------------ #
    breakdown = engine.breakdown

    if not breakdown:
        output_mod.print_ok(t("breakdown.no_deductions"))
    else:
        output_mod.print_dim(t("breakdown.deductions_header", count=len(breakdown)))

        # Pre-compute domain IDs once to avoid double key_to_domain() calls
        domain_ids = [key_to_domain(d.key) for d in breakdown]

        # Column widths
        key_w    = max((len(d.key or "—") for d in breakdown), default=10)
        domain_w = max(
            (len(_domain_label(did, t) if did else "—") for did in domain_ids),
            default=1,
        )

        capped = engine.capped_indices
        for idx, d in enumerate(breakdown):
            domain_id  = domain_ids[idx]
            domain_lbl = _domain_label(domain_id, t) if domain_id else "—"
            capped_tag = f"  {t('breakdown.capped')}" if idx in capped else ""
            ctx = d.context or "—"
            line = (
                f"  {(d.key or '—'):<{key_w}}  "
                f"{domain_lbl:<{domain_w}}  "
                f"−{d.points} pt"
                f"  [{ctx}]"
                f"{capped_tag}"
            )
            output_mod.print_dim(line)

    # ------------------------------------------------------------------ #
    # 2. Tool caps summary                                                 #
    # ------------------------------------------------------------------ #
    capped_prefixes = {
        d.key.split(".", 1)[0]
        for idx, d in enumerate(breakdown)
        if idx in engine.capped_indices and d.key
    }
    for prefix in sorted(capped_prefixes):
        cap = TOOL_CAPS.get(prefix)
        if cap is None:
            continue
        total_raw = sum(d.points for d in breakdown
                        if d.key and d.key.startswith(f"{prefix}."))
        output_mod.print_info(
            t("breakdown.tool_cap_applied",
              tool=prefix,
              raw=total_raw,
              counted=cap,
              cap=cap)
        )

    # ------------------------------------------------------------------ #
    # 3. Engine cap                                                        #
    # ------------------------------------------------------------------ #
    if engine.cap_info:
        cap = engine.cap_info
        output_mod.print_warn(
            t("breakdown.engine_cap_applied",
              reason=cap.reason,
              maximum=cap.maximum)
        )

    # ------------------------------------------------------------------ #
    # 4. Raw score                                                         #
    # ------------------------------------------------------------------ #
    raw = engine.raw_score
    output_mod.print_dim(t("breakdown.raw_score", score=raw))

    # ------------------------------------------------------------------ #
    # 5. Domain scores                                                     #
    # ------------------------------------------------------------------ #
    domain_scores = engine.domain_scores
    active        = engine.active_domains

    if active:
        output_mod.print_dim(t("breakdown.domain_scores_header"))
        labels  = {d: _domain_label(d, t) for d in DOMAINS if d in active}
        label_w = max(len(v) for v in labels.values())
        for domain in DOMAINS:
            if domain not in active:
                continue
            info  = domain_scores[domain]
            score = info["score"]
            ded   = info["deductions"]
            label = labels[domain]
            ded_str = f"  (−{ded} pt)" if ded else ""
            output_mod.print_dim(f"  {label:<{label_w}}  {score:>2}/10  {_bar(score)}{ded_str}")

    # ------------------------------------------------------------------ #
    # 6. Domain-average override                                           #
    # ------------------------------------------------------------------ #
    if engine.global_override is not None:
        n_active = len(active)
        precap = engine.domain_average_precap
        output_mod.print_info(
            t("breakdown.domain_average",
              score=precap if precap is not None else engine.global_override,
              count=n_active)
        )
        # F1 (v0.12.0): when a deduction exists, a perfect headline is
        # reserved for a flawless audit — show the average → cap step.
        if precap is not None and precap != engine.global_override:
            output_mod.print_info(
                t("breakdown.f1_cap", score=engine.global_override)
            )

    # ------------------------------------------------------------------ #
    # 7. Final score                                                       #
    # ------------------------------------------------------------------ #
    final = engine.score
    if final >= 8:
        output_mod.print_ok(t("breakdown.final_score", score=final))
    elif final >= 5:
        output_mod.print_warn(t("breakdown.final_score", score=final))
    else:
        output_mod.print_alert(t("breakdown.final_score", score=final))


# ---------------------------------------------------------------------------
# v0.40.0 (B-032) — the breakdown of a report, in --manage-logs's preview
# ---------------------------------------------------------------------------
#
# Decided with the user (20 November 2026): the preview of an audit report
# shows, behind the key b, the computation --breakdown prints — closed when the
# preview opens, kept as it is across ←/→, like the comparison and the
# history. Rendered by display_breakdown itself, never by a second copy: what
# the engine held is written into the report's state as data (breakdown_state)
# and handed back to display_breakdown in the engine's own shape (_Replay).
# A report written before 0.40.0 has no such data, and says so.

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def breakdown_state(engine: "ScoreEngine") -> dict:
    """What display_breakdown reads of a finalized engine, as plain data."""
    cap = engine.cap_info
    return {
        "deductions": [{"key": d.key, "points": d.points, "context": d.context}
                       for d in engine.breakdown],
        "capped": sorted(engine.capped_indices),
        "cap": {"maximum": cap.maximum, "reason": cap.reason} if cap else None,
        "raw": engine.raw_score,
        "domains": {name: {"score": info.get("score"), "deductions": info.get("deductions")}
                    for name, info in engine.domain_scores.items()},
        "active": sorted(engine.active_domains),
        "override": engine.global_override,
        "precap": engine.domain_average_precap,
        "score": engine.score,
    }


class _Replay:
    """A finalized engine as display_breakdown reads it, rebuilt from
    breakdown_state's data."""

    def __init__(self, state: dict) -> None:
        from types import SimpleNamespace
        self.breakdown = [SimpleNamespace(key=d.get("key") or "", points=int(d["points"]),
                                          context=d.get("context"))
                          for d in state["deductions"]]
        self.capped_indices = frozenset(int(i) for i in state["capped"])
        cap = state.get("cap")
        self.cap_info = (SimpleNamespace(maximum=cap["maximum"], reason=cap["reason"])
                         if cap else None)
        self.raw_score = int(state["raw"])
        self.domain_scores = {name: dict(info) for name, info in state["domains"].items()}
        self.active_domains = frozenset(state["active"])
        self.global_override = state.get("override")
        self.domain_average_precap = state.get("precap")
        self.score = int(state["score"])


def breakdown_lines(state: "dict | None", t) -> "list[str] | None":
    """The lines --breakdown prints for the engine *state* records, without
    their colours and without the section title (the block carries its own);
    None when *state* cannot be read back."""
    from bob.compare import _Lines
    if not isinstance(state, dict):
        return None
    sink = _Lines()
    try:
        display_breakdown(_Replay(state), t, sink)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    return [_ANSI.sub("", line) for line in sink.lines[1:]]
