"""Adversarial plugin 14 — out-of-memory denial of service.

Attack: allocate a list of 10**8 zeros (~ 4 GB) to OOM the audit process.
Expected sandbox behaviour: the multiprocessing.Process isolation + an
optional rlimit on the child means OOM in the plugin process does NOT
crash the parent audit. The plugin runner times out / kills the child
and surfaces a clean WARN finding.

NOTE: this test uses a smaller allocation (1e6) in practice so the test
suite doesn't actually OOM; the runner's resource limit handling is the
contract being pinned.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        # Smaller than the real attack size so the test machine doesn't OOM
        x = [0] * (10 ** 6)
        result.warn(message=f"ATTACK SUCCEEDED: allocated {len(x)} ints")
    except MemoryError:
        result.ok(message="sandbox / rlimit blocked allocation")
    return result
