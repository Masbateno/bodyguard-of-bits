"""
Watch mode for BOB (--watch[=N]).

Runs a silent audit every N seconds (default: 60) and displays only what
changed since the previous iteration.  Press Ctrl+C to quit.

Usage:
    sudo bob --watch        # default 60s interval
    sudo bob --watch=30     # custom interval in seconds
"""

from __future__ import annotations

import time
from copy import copy
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from bob.compare import (
    AuditBaseline,
    build_baseline,
    compute_delta,
    display_delta,
    save_baseline,
)
from bob.runner import run_checks
from bob.scoring import ScoreEngine
from bob.sysinfo import detect_network_context

if TYPE_CHECKING:
    from bob.cli import AuditConfig
    from bob.profiles import AuditProfile
    from bob.registry import ServiceRegistry


class _NullReport:
    """Report sink that silently discards all writes (used in watch iterations)."""

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def run_watch(
    config: "AuditConfig",
    interval: int,
    t,
    output_mod,
    registry: "ServiceRegistry",
    active_profile: "AuditProfile",
    VERSION: str,
) -> int:
    """
    Watch mode main loop.

    Runs a quiet audit every `interval` seconds and prints only changes.
    Blocks until Ctrl+C.

    Returns:
        0 on clean exit (Ctrl+C).
    """
    # Build a quiet, non-reporting config for each iteration
    watch_cfg = copy(config)
    watch_cfg.quiet   = True
    watch_cfg.detailed = False

    print()
    output_mod.print_section(t("watch.header", interval=interval))
    print()

    prev_baseline: AuditBaseline | None = None

    try:
        while True:
            now = datetime.now()
            ts  = now.strftime("%H:%M:%S")

            # ---- Run a silent audit ----
            engine = ScoreEngine()
            network_context, _ = detect_network_context(offline=config.offline)
            result = run_checks(
                watch_cfg, t, engine, _NullReport(), registry, network_context,
                profile=active_profile,
            )
            engine.finalize()
            from bob.domain_scores import apply_domain_score_override as _apply_dso
            _apply_dso(engine)
            curr_baseline = build_baseline(
                engine, result.ports_snapshot, result.snapshots
            )
            save_baseline(curr_baseline)

            # ---- Display ----
            bar = _score_bar(engine.score)
            print(f"  [{ts}]  {t('watch.score', score=engine.score)}  {bar}")

            if prev_baseline is None:
                output_mod.print_ok(t("watch.baseline_established"))
            else:
                delta = compute_delta(prev_baseline, curr_baseline)
                if delta.is_empty():
                    output_mod.print_ok(t("compare.no_changes"))
                else:
                    display_delta(delta, t, output_mod)

            prev_baseline = curr_baseline

            # ---- Next check ----
            next_time = (now + timedelta(seconds=interval)).strftime("%H:%M:%S")
            output_mod.print_dim(t("watch.next_check", interval=interval, time=next_time))
            print()

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        output_mod.print_info(t("watch.stopped"))
        return 0

    return 0


def _score_bar(score: int) -> str:
    """Return a 10-character visual bar for a score 0–10.

    Args:
        score: Integer score in range 0–10. Values outside the range are
               clamped. Passing a non-int raises TypeError.
    """
    if not isinstance(score, int):
        raise TypeError(f"_score_bar requires int, got {type(score).__name__}")
    filled = max(0, min(10, score))
    return "█" * filled + "░" * (10 - filled)
