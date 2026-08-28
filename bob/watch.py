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
from bob.ignore import load_ignore_keys
from bob.report import AuditReport
from bob.runner import run_checks
from bob.scoring import ScoreEngine
from bob.sysinfo import detect_network_context

if TYPE_CHECKING:
    from bob.cli import AuditConfig
    from bob.config import UserConfig
    from bob.profiles import AuditProfile
    from bob.registry import ServiceRegistry


# M-2 (v0.5.5): _NullReport removed — use bob.report.NullReport via
# AuditReport.null() (added in v0.5.0 alongside the Report Protocol).
# Previous duck-typed implementation duplicated the no-op surface.


def run_watch(
    config: "AuditConfig",
    interval: int,
    t,
    output_mod,
    registry: "ServiceRegistry",
    active_profile: "AuditProfile",
    VERSION: str,
    user_config: "UserConfig | None" = None,
) -> int:
    """
    Watch mode main loop.

    Runs a quiet audit every `interval` seconds and prints only changes.
    Blocks until Ctrl+C.

    Args:
        user_config: User configuration (forwarded to run_checks so the SUID
                     whitelist and other user-configured behavior match the
                     non-watch audit path).

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
            engine = ScoreEngine(profile=active_profile)
            # I-1 (v0.7.1): propagate the user's ignore.yml so watch mode
            # respects the same skip list as the non-watch audit path
            # (compare bob/__main__.py "if ignore_keys: engine.ignore_keys = ...").
            # Pre-v0.7.1, watch ignored ignore.yml entirely, so suppressed
            # findings reappeared in every iteration and inflated deductions.
            engine.ignore_keys = load_ignore_keys()
            network_context, _ = detect_network_context(offline=config.offline)
            result = run_checks(
                watch_cfg, t, engine, AuditReport.null(), registry, network_context,
                profile=active_profile,
                user_config=user_config,
            )
            engine.finalize()
            from bob.domain_scores import apply_domain_score_override as _apply_dso
            _apply_dso(engine)

            # I-1 (v0.7.1): apply the same posture escalation rules used by
            # the non-watch audit summary. Without this, watch displayed the
            # raw score-derived level even when UFW was inactive — a host
            # whose firewall just went down kept showing "LOW" until the
            # operator ran a full non-watch audit.
            # M-10 (v0.7.3): single source of truth via set_posture_from_engine.
            from bob.scoring import set_posture_from_engine
            set_posture_from_engine(engine, fw_active=getattr(result, "fw_active", True))

            curr_baseline = build_baseline(
                engine, result.ports_snapshot, result.snapshots
            )
            save_baseline(curr_baseline)

            # ---- Display ----
            bar = _score_bar(engine.score)
            # I-1 (v0.7.1): display ``effective_level`` so the watch line
            # surfaces posture escalation. The score itself stays the raw
            # value (matches the non-watch box header layout).
            effective_level = getattr(engine, "effective_level", engine.level)
            print(
                f"  [{ts}]  "
                f"{t('watch.score', score=engine.score)}  "
                f"{bar}  "
                f"[{effective_level.value}]"
            )

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
    """Return a 10-character coloured visual bar for a score 0–10.

    Delegates to `bob.output.score_bar` which applies high=good thresholds:
    green (>=8), yellow (5–7), red (0–4). Same colour scheme as the disk
    partition bars in display.py.

    Args:
        score: Integer score in range 0–10. Values outside the range are
               clamped. Passing a non-int (including bool, which subclasses
               int) raises TypeError. The explicit bool rejection matches
               the v0.7.0 Phase 2.1 I-3 ``ScoreEngine.set_posture`` guard.
    """
    if isinstance(score, bool) or not isinstance(score, int):
        raise TypeError(f"_score_bar requires int (not bool), got {type(score).__name__}")
    from bob.output import score_bar
    return score_bar(score)
