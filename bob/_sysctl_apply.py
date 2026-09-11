"""Applying a sysctl setting without a shell.

`--fix --apply` refuses commands carrying `&&` or `|`, and the fifteen sysctl
fixes BOB proposes carry both:

    sudo sysctl -w net.ipv4.conf.all.rp_filter=1 && { grep -qxF … || echo … | sudo tee -a … ; }

That refusal is right. A pipeline hides its left-hand failure — `/bin/sh` is
dash, `pipefail` is off, and `false | true` exits 0 — and `A && B` can leave a
state neither half describes: the value live but not persisted, which reverts
at the next boot while the audit says OK.

The command stays exactly as it is, because a human reading a one-liner is what
it is for. This module is the same change expressed as code, which BOB can run
itself: set the value, persist it idempotently through the atomic writer, and
then *read it back*. The read-back is the point — v0.17.1 spent a release on
fixes that reported success without having succeeded.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from bob._atomic import atomic_write

#: `key = value`, with the keys the kernel actually exposes. Anything else is
#: refused rather than passed to a subprocess: this value reaches argv.
_PARAM_RE = re.compile(r"^([a-z0-9_]+(?:\.[a-z0-9_*-]+)+)=([A-Za-z0-9 ._:+-]+)$")

_TIMEOUT = 10


class SysctlResult:
    """What happened, in enough detail to report it honestly.

    ``applied`` is only True when the value was read back and matched. Every
    other outcome carries a ``reason`` naming which step failed, because "it
    did not work" and "it worked and I could not confirm it" are different
    things to tell an operator.
    """

    __slots__ = ("applied", "persisted", "reason")

    def __init__(self, applied: bool, persisted: bool, reason: str = ""):
        self.applied = applied
        self.persisted = persisted
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return (f"SysctlResult(applied={self.applied}, "
                f"persisted={self.persisted}, reason={self.reason!r})")


def parse_param(param: str) -> "tuple[str, str] | None":
    """Split ``key=value``, or None when it is not one.

    Refusing here rather than quoting later: the parameter comes from BOB's own
    tables today, and a table is exactly the kind of thing that grows an entry
    from somewhere else.
    """
    m = _PARAM_RE.match(param.strip())
    return (m.group(1), m.group(2).strip()) if m else None


def _read_live(key: str) -> "str | None":
    """The kernel's current value, or None when it cannot be read."""
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _persist(key: str, value: str, conf: Path) -> "str | None":
    """Write ``key = value`` into *conf*, replacing any line that sets *key*.

    Returns None on success, or a reason. Idempotent by construction: the file
    is rebuilt with exactly one line for this key, so applying twice leaves one
    line — the defect v0.17.1 fixed in the *advice*, made structural here.
    """
    try:
        existing = conf.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        existing = []
    except OSError as exc:
        return f"{type(exc).__name__} reading {conf}"

    setter = re.compile(rf"^\s*{re.escape(key)}\s*=")
    kept = [ln for ln in existing if not setter.match(ln)]
    kept.append(f"{key} = {value}")
    try:
        conf.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(conf, "\n".join(kept) + "\n", mode=0o644)
    except OSError as exc:
        return f"{type(exc).__name__} writing {conf}"
    return None


def apply_sysctl(param: str, conf: Path) -> SysctlResult:
    """Set *param* now, persist it in *conf*, and confirm by reading back.

    The order matters. Persisting first would leave a file promising something
    the running kernel refused; setting first means a failure here stops before
    anything is written.
    """
    parsed = parse_param(param)
    if parsed is None:
        return SysctlResult(False, False, f"not a sysctl assignment: {param!r}")
    key, value = parsed

    try:
        proc = subprocess.run(
            ["sysctl", "-w", f"{key}={value}"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return SysctlResult(False, False, type(exc).__name__)
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip()
        return SysctlResult(False, False, detail or f"sysctl exited {proc.returncode}")

    # Read back before claiming anything. A kernel can accept the write and
    # hold a different value — a clamped range, a key aliased elsewhere.
    live = _read_live(key)
    if live is None:
        return SysctlResult(False, False, f"cannot read /proc/sys for {key}")
    if live.split() != value.split():
        return SysctlResult(False, False, f"kernel holds {live!r}, not {value!r}")

    reason = _persist(key, value, conf)
    if reason is not None:
        # Live but not persisted is the state the shell one-liner could reach
        # silently. It is reported, not rounded up to success.
        return SysctlResult(True, False, reason)
    return SysctlResult(True, True)
