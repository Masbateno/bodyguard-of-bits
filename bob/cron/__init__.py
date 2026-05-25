"""
Cron management utilities for BOB.

Handles:
- CronEntry dataclass representing an installed cron job
- Listing installed cron jobs (/etc/cron.d/bob-*)
- Parsing generated cron files to extract metadata
- Converting cron expressions to human-readable descriptions (EN/FR)
- Building cron expressions from wizard answers
- Interactive install wizard (plain-text flow)
- Interactive management (plain-text flow)

Curses TUI code lives in bob.tui.cron.

Module layout (v0.6.0 #14 split):
  - ``_parse``:   CronEntry + parsing + listing + cron_to_human + build_schedule_expr
                  + validators + day helpers + MTA detection + constants
  - ``_io``:      _atomic_write + build_script_content + apply_cron_schedule
                  + apply_cron_email (all file-mutation helpers)
  - ``_install``: prompt_emails / prompt_email + _run_install_cron_plain
                  + run_install_cron + _CronQuit signal
  - ``_manage``:  _manage_email_store + edit_cron_email + edit_cron_schedule
                  + _run_manage_cron_plain + run_manage_cron
"""

from __future__ import annotations

# datetime re-exported at package level for M-8 (v0.5.8) — tests/test_cron.py
# asserts `bob.cron.datetime is datetime.datetime`.
from datetime import datetime  # noqa: F401

from ._parse import (
    CRON_DIR,
    LEGACY_CRON_PATH,
    LEGACY_SCRIPT_PATH,
    SCRIPT_DIR,
    CronEntry,
    _CRON_FIELD_BOUNDS,
    _DAYS_EN,
    _DAYS_FR,
    _detect_mta,
    _ordinal,
    _parse_day_names,
    _parse_dom,
    _validate_cron_field,
    _validate_custom_cron,
    build_schedule_expr,
    cron_to_human,
    list_installed_crons,
    make_slug,
    parse_cron_file,
    suggest_name,
)
from ._io import (
    _atomic_write,
    apply_cron_email,
    apply_cron_schedule,
    build_script_content,
)
from ._install import (
    _CronQuit,
    _run_install_cron_plain,
    prompt_email,
    prompt_emails,
    run_install_cron,
)
from ._manage import (
    _manage_email_store,
    _run_manage_cron_plain,
    edit_cron_email,
    edit_cron_schedule,
    run_manage_cron,
)

# Re-export _EMAIL_RE for backwards-compat — tests + bob/tui/cron.py both
# import it via `from bob.cron import _EMAIL_RE`. The canonical source is
# bob.config._EMAIL_RE (M-1 v0.5.5) but the cron-level re-export is part
# of the v0.5.x public API.
from bob.config import _EMAIL_RE  # noqa: F401

__all__ = [
    # Public API
    "CronEntry",
    "CRON_DIR",
    "SCRIPT_DIR",
    "apply_cron_email",
    "apply_cron_schedule",
    "build_schedule_expr",
    "build_script_content",
    "cron_to_human",
    "edit_cron_email",
    "edit_cron_schedule",
    "list_installed_crons",
    "make_slug",
    "parse_cron_file",
    "prompt_email",
    "prompt_emails",
    "run_install_cron",
    "run_manage_cron",
    "suggest_name",
]
