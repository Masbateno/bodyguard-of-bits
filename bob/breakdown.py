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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bob.scoring import ScoreEngine

from bob.checks._run import TranslationFunc

from bob.domain_scores import (
    DOMAINS,
    _LABELS,
    _TOOL_CAPS,
    _key_to_domain,
    active_domains_from_engine,
    compute_domain_scores,
)
from bob.scoring import MAX_SCORE

_BAR_WIDTH  = 10
_BAR_FILLED = "█"
_BAR_EMPTY  = "░"


def _bar(score: int) -> str:
    filled = min(_BAR_WIDTH, max(0, round(score * _BAR_WIDTH / MAX_SCORE)))
    return _BAR_FILLED * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)


def _domain_label(domain_id: str, t) -> str:
    """Return a translated domain label, falling back to _LABELS then domain_id."""
    translated = t(f"domain_scores.{domain_id}")
    if translated != f"domain_scores.{domain_id}":
        return translated
    return _LABELS.get(domain_id, domain_id.capitalize())


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
    tool_contributed: dict[str, int] = {}
    capped_entries:   set[int]       = set()

    if not breakdown:
        output_mod.print_ok(t("breakdown.no_deductions"))
    else:
        output_mod.print_dim(t("breakdown.deductions_header", count=len(breakdown)))

        # Detect which tool prefixes were capped so we can annotate
        for idx, d in enumerate(breakdown):
            prefix = d.key.split(".", 1)[0] if d.key else ""
            cap = _TOOL_CAPS.get(prefix)
            if cap is not None:
                already = tool_contributed.get(prefix, 0)
                new_total = already + d.points
                if new_total > cap:
                    capped_entries.add(idx)
                    tool_contributed[prefix] = cap
                else:
                    tool_contributed[prefix] = new_total

        # Pre-compute domain IDs once to avoid double _key_to_domain() calls
        domain_ids = [_key_to_domain(d.key) for d in breakdown]

        # Column widths
        key_w    = max((len(d.key or "—") for d in breakdown), default=10)
        domain_w = max(
            (len(_domain_label(did, t) if did else "—") for did in domain_ids),
            default=1,
        )

        for idx, d in enumerate(breakdown):
            domain_id  = domain_ids[idx]
            domain_lbl = _domain_label(domain_id, t) if domain_id else "—"
            capped_tag = f"  {t('breakdown.capped')}" if idx in capped_entries else ""
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
    if tool_contributed:
        for prefix, counted in tool_contributed.items():
            cap = _TOOL_CAPS[prefix]
            total_raw = sum(d.points for d in breakdown
                            if d.key and d.key.startswith(f"{prefix}."))
            if total_raw > counted:
                output_mod.print_info(
                    t("breakdown.tool_cap_applied",
                      tool=prefix,
                      raw=total_raw,
                      counted=counted,
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
    domain_scores = compute_domain_scores(engine)
    active        = active_domains_from_engine(engine)

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
        output_mod.print_info(
            t("breakdown.domain_average",
              score=engine.global_override,
              count=n_active)
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
