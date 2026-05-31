"""Adversarial plugin 05 — ctypes-based direct libc call.

Attack: ``ctypes.CDLL("libc.so.6").execve(b"/bin/touch", ..., None)``
Expected sandbox behaviour: ImportError on ``ctypes`` (not in allowlist).
"""
from bob.scoring import CheckResult

PLUGIN_TARGET = "/tmp/bob_sandbox_attack_05"


def run_check(t=None):
    result = CheckResult()
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        # Even if we don't reach execve, the import itself is the attack signal
        result.warn(
            message=f"ATTACK SUCCEEDED: ctypes imported, libc={libc!r}"
        )
    except ImportError:
        result.ok(message="sandbox blocked ctypes import")
    return result
