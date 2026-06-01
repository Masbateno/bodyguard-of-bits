"""Bash completion install helper."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def install_completion() -> int:
    """Install bash completion script and sudo PATH symlink. Returns exit code."""
    ok = True

    src      = Path(__file__).parent / "data" / "bob.bash-completion"
    dst_comp = Path("/etc/bash_completion.d/bob")
    if not src.exists():
        print(f"✖ Completion data file not found: {src}", file=sys.stderr)
        ok = False
    elif not dst_comp.parent.exists():
        print("✖ /etc/bash_completion.d not found — is bash-completion installed?",
              file=sys.stderr)
        ok = False
    else:
        try:
            shutil.copy2(src, dst_comp)
            print(f"✔ Bash completion installed: {dst_comp}")
        except OSError as exc:
            print(f"✖ Failed to install completion script: {exc}", file=sys.stderr)
            ok = False

    dst_bin   = Path("/usr/local/bin/bob")
    sudo_user = os.environ.get("SUDO_USER")
    bin_src   = None
    # I-2 (v0.7.3): validate SUDO_USER format AND catch pwd.getpwnam
    # KeyError before consuming the value. Pre-v0.7.3 a malformed or
    # spoofed SUDO_USER (anything not in the system's user db) crashed
    # install_completion() with an unhandled KeyError instead of
    # returning exit 3 like every other CLI-level failure. The regex
    # mirrors bob/sysinfo.py::get_user_home + chown_to_sudo_user.
    import re as _re
    if sudo_user and _re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        try:
            import pwd
            home      = Path(pwd.getpwnam(sudo_user).pw_dir)
            candidate = home / ".local" / "bin" / "bob"
        except KeyError:
            # SUDO_USER set but the user doesn't exist in /etc/passwd —
            # fall through as if no SUDO_USER were set.
            candidate = None
    else:
        candidate = None
    if candidate is not None:
        # exists() returns False for broken/circular symlinks, so this also
        # guards against those cases.
        if candidate.exists() and candidate.resolve() != dst_bin.resolve():
            bin_src = candidate
    if bin_src:
        try:
            if dst_bin.is_symlink() or dst_bin.exists():
                dst_bin.unlink()
            dst_bin.symlink_to(bin_src)
            print(f"✔ Symlink created: {dst_bin} → {bin_src}")
        except OSError as exc:
            print(f"✖ Failed to create symlink: {exc}", file=sys.stderr)
            ok = False
    elif sudo_user:
        print("ℹ  Symlink skipped — bob not found in ~/.local/bin (pipx install?)")
    else:
        print("ℹ  Symlink skipped — run via sudo to detect user binary")

    if ok:
        print("  Open a new shell or run: source /etc/bash_completion.d/bob")
    return 0 if ok else 3
