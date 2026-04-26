"""
Shared path resolution for BOB installed data files.

Used by i18n.py and registry.py to locate locale and service data files.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_share_dir() -> Path | None:
    """
    Return the validated UFW_AUDIT_SHARE directory, or None if unset/invalid.

    Reads the UFW_AUDIT_SHARE environment variable (set by the installer
    entry point to /usr/local/share/bob). Resolves all symlinks to
    prevent symlink-chain attacks where an intermediate path component
    points outside the intended tree.

    Returns:
        Resolved Path if the variable is set and points to an absolute
        directory; None otherwise (fall back to package-local data).
    """
    share = os.environ.get("UFW_AUDIT_SHARE", "").strip()
    if not share:
        return None
    try:
        # strict=True: raises OSError immediately if the path does not exist
        # (catches broken symlinks and non-existent directories early)
        resolved = Path(share).resolve(strict=True)
    except OSError as exc:
        logger.warning("UFW_AUDIT_SHARE could not be resolved, ignoring: %r (%s)", share, exc)
        return None
    if resolved.is_absolute() and resolved.is_dir():
        return resolved
    logger.warning("UFW_AUDIT_SHARE is invalid or unsafe, ignoring: %r", share)
    return None
