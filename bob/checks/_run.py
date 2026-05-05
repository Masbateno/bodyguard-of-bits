"""
Shared subprocess and utility helpers for BOB check modules.

All check modules import from here instead of duplicating these helpers.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

_CMD_TIMEOUT = 10  # seconds — shared across all check modules

logger = logging.getLogger(__name__)

# Force English output for all system commands so regexes work regardless
# of the system locale (e.g. French UFW outputs "État : actif" instead of
# "Status: active" when LC_ALL is not overridden).
# LANGUAGE must be cleared explicitly: gettext gives it higher priority
# than LC_ALL, so "LANGUAGE=fr_FR" would still override LC_ALL=C.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": ""}


def _run(*args: str, timeout: int = _CMD_TIMEOUT) -> str:
    """Run a command and return stdout. Returns empty string on error."""
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=timeout,
            env=_C_LOCALE_ENV,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %r failed: %s (stderr=%r)", args, exc,
                     getattr(exc, "stderr", None))
        return ""


def _command_exists(name: str) -> bool:
    """Return True if the command is available in PATH."""
    return shutil.which(name) is not None


def _identity_t(key: str, **kwargs) -> str:
    """Fallback translation function — returns the key itself."""
    return key


TranslationFunc = Callable[..., str]
"""Type alias for BOB's translation function: t(key, **kwargs) -> str."""


def _is_safe_config_path(path) -> bool:
    """Return True if path is absolute and not a symlink (safe to read)."""
    p = Path(path)
    return p.is_absolute() and not p.is_symlink()
