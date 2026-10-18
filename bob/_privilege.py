"""The command a printed fix runs as root through (v0.25.0).

BOB writes every fix as ``sudo …``. Alpine ships ``doas`` and no sudo: a fix
pasted there failed on its first word. The prefix is now the host's — sudo
where it exists, doas where only doas does — applied once, where a finding
is recorded, so no check has to know about it. A host with neither keeps
``sudo``: there is nothing better to name, and root runs the rest unchanged.
"""

from __future__ import annotations

import re
import shutil
from functools import lru_cache

#: ``sudo`` as a command word — not ``visudo``, ``/etc/sudoers`` or ``sudo.d``.
#: v0.25.1: also before a closing parenthesis or a final punctuation mark
#: ("run with sudo)", "re-run with sudo."), which prose uses.
_SUDO_WORD = re.compile(r"(?<![\w./-])sudo(?=\s|\)|[.,;:](?!\w)|$)")


@lru_cache(maxsize=1)
def privilege_prefix() -> str:
    """``sudo`` when it is installed, else ``doas`` when that is, else ``sudo``."""
    try:
        if shutil.which("sudo"):
            return "sudo"
        if shutil.which("doas"):
            return "doas"
    except Exception:  # noqa: BLE001 — v0.25.1: inside the plugin sandbox
        pass           # `os` is restricted; keep the text as written
    return "sudo"


def with_privilege(cmd: str) -> str:
    """*cmd* with each ``sudo`` command word replaced by the host's prefix."""
    # v0.25.1: look for the word first. Finding prose now passes through here
    # too, and a plugin's findings are built inside the sandbox, where `os` is
    # restricted and `shutil.which` cannot run: most texts never name sudo.
    if not cmd or not _SUDO_WORD.search(cmd):
        return cmd
    prefix = privilege_prefix()
    return cmd if prefix == "sudo" else _SUDO_WORD.sub(prefix, cmd)
