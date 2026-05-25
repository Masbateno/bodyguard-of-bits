"""
Shared path resolution for BOB installed data files.

Used by i18n.py and registry.py to locate locale and service data files.

Environment variable contract
-----------------------------
``BOB_SHARE`` — absolute path to the directory containing BOB's shipped data
(locales/, data/, …). Set by the installer entry point (typically to
``/usr/local/share/bob`` or ``/usr/share/bob`` for distro packages).

The legacy ``UFW_AUDIT_SHARE`` alias was deprecated in v0.5.4 and removed
in v0.6.0 (this release). Installers still setting it will see no effect —
update them to use ``BOB_SHARE``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_ENV_PRIMARY = "BOB_SHARE"


def resolve_share_dir() -> Path | None:
    """
    Return the validated share directory, or None if unset/invalid.

    Reads ``BOB_SHARE`` (the documented contract since v0.4.2). Resolves all
    symlinks to prevent symlink-chain attacks where an intermediate path
    component points outside the intended tree.

    Returns:
        Resolved Path if BOB_SHARE is set and points to an absolute
        directory; None otherwise (callers fall back to package-local data).
    """
    share = os.environ.get(_ENV_PRIMARY, "").strip()
    if not share:
        return None
    try:
        # strict=True: raises OSError immediately if the path does not exist
        # (catches broken symlinks and non-existent directories early)
        resolved = Path(share).resolve(strict=True)
    except OSError as exc:
        logger.warning("%s could not be resolved, ignoring: %r (%s)", _ENV_PRIMARY, share, exc)
        return None
    if resolved.is_absolute() and resolved.is_dir():
        return resolved
    logger.warning("%s is invalid or unsafe, ignoring: %r", _ENV_PRIMARY, share)
    return None
