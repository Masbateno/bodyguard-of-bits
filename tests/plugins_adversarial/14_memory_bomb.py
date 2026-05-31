"""Adversarial plugin 14 — out-of-memory denial of service.

Attack: allocate a list of ~ 10^8 pointers (~ 800 MiB on 64-bit) to OOM
the audit process. Expected sandbox behaviour: the worker's
``RLIMIT_AS`` cap (256 MiB by default, see ``_apply_resource_limits``)
raises MemoryError well before the allocation succeeds. The
multiprocessing.Process isolation guarantees the parent audit survives
even if the cap is bypassed.

Why 10**8: at 8 bytes per pointer on 64-bit Python, ``[0] * 10**8`` is
800 MiB — well above the 256 MiB sandbox cap, but small enough that
a non-sandboxed run would succeed quickly (worth a couple of seconds
of allocation). The contract being pinned: the cap MUST stop this.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        # 10**8 pointers × 8 bytes = ~ 800 MiB. Above the sandbox's
        # 256 MiB RLIMIT_AS cap → MemoryError. Below the cap → "attack
        # succeeded" (sandbox is broken).
        x = [0] * (10 ** 8)
        result.warn(message=f"ATTACK SUCCEEDED: allocated {len(x)} pointers")
    except MemoryError:
        result.ok(message="sandbox / rlimit blocked allocation (MemoryError)")
    return result
