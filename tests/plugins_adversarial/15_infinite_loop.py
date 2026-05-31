"""Adversarial plugin 15 — CPU denial of service via infinite loop.

Attack: ``while True: pass`` — starve the audit of CPU until the user
SIGINTs. Expected sandbox behaviour: the runner enforces a per-plugin
timeout (default ~5s); the multiprocessing.Process is killed when the
deadline expires and a clean WARN finding is returned.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    # We can't actually loop forever in the test suite — the runner is
    # supposed to kill us. Use a bounded busy-wait so the test asserts
    # the timeout path was taken rather than a normal return.
    # In real life the attack omits the bound.
    import time
    deadline = time.monotonic() + 30.0  # 30s — well past the runner's 5s budget
    while time.monotonic() < deadline:
        pass
    result.warn(
        message="ATTACK COMPLETED: ran for 30s without being killed"
    )
    return result
