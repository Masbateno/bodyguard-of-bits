"""
Shared path resolution for BOB installed data files.

Used by i18n.py and registry.py to locate locale and service data files.

Environment variable contract
-----------------------------
``BOB_SHARE`` (preferred) — absolute path to the directory containing BOB's
shipped data (locales/, data/, …). Set by the installer entry point (typically
to ``/usr/local/share/bob`` or ``/usr/share/bob`` for distro packages).

``UFW_AUDIT_SHARE`` (legacy alias) — accepted for backward compatibility with
pre-v0.4.2 installer scripts. **Deprecated since v0.5.4** and will be removed
in **v0.6.0**. ``BOB_SHARE`` takes precedence when both are set.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_ENV_PRIMARY = "BOB_SHARE"
_ENV_LEGACY  = "UFW_AUDIT_SHARE"   # pre-v0.4.2 name — kept for compat


def resolve_share_dir() -> Path | None:
    """
    Return the validated share directory, or None if unset/invalid.

    Reads ``BOB_SHARE`` first (the documented contract since v0.4.2), then
    falls back to the legacy ``UFW_AUDIT_SHARE`` for installers that haven't
    been updated yet. Resolves all symlinks to prevent symlink-chain attacks
    where an intermediate path component points outside the intended tree.

    Returns:
        Resolved Path if either variable is set and points to an absolute
        directory; None otherwise (callers fall back to package-local data).
    """
    share = os.environ.get(_ENV_PRIMARY, "").strip()
    source = _ENV_PRIMARY
    if not share:
        share = os.environ.get(_ENV_LEGACY, "").strip()
        source = _ENV_LEGACY
    if not share:
        return None
    try:
        # strict=True: raises OSError immediately if the path does not exist
        # (catches broken symlinks and non-existent directories early)
        resolved = Path(share).resolve(strict=True)
    except OSError as exc:
        logger.warning("%s could not be resolved, ignoring: %r (%s)", source, share, exc)
        return None
    if resolved.is_absolute() and resolved.is_dir():
        if source == _ENV_LEGACY:
            logger.warning(
                "Using legacy env var %s — DEPRECATED since v0.5.4, will be "
                "REMOVED in v0.6.0. Update your installer to %s (both are "
                "accepted today; %s takes precedence when both are set).",
                _ENV_LEGACY, _ENV_PRIMARY, _ENV_PRIMARY,
            )
        return resolved
    logger.warning("%s is invalid or unsafe, ignoring: %r", source, share)
    return None
