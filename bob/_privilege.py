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
_SUDO_WORD = re.compile(r"(?<![\w./-])sudo(?=\s)")


@lru_cache(maxsize=1)
def privilege_prefix() -> str:
    """``sudo`` when it is installed, else ``doas`` when that is, else ``sudo``."""
    if shutil.which("sudo"):
        return "sudo"
    if shutil.which("doas"):
        return "doas"
    return "sudo"


def with_privilege(cmd: str) -> str:
    """*cmd* with each ``sudo`` command word replaced by the host's prefix."""
    if not cmd:
        return cmd
    prefix = privilege_prefix()
    return cmd if prefix == "sudo" else _SUDO_WORD.sub(prefix, cmd)
