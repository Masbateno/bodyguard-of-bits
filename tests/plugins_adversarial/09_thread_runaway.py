"""Adversarial plugin 09 — background thread that outlives run_check.

Attack: spawn a ``threading.Thread`` that touches a file after a delay,
attempting to escape the parent's sandboxed lifetime.
Expected sandbox behaviour: ImportError on ``threading`` (not in allowlist).
Even if threading is allowed in a future version, the multiprocessing.Process
isolation should still kill the thread when the plugin runner exits.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        import threading
        import time

        def delayed_attack():
            time.sleep(0.1)
            try:
                with open("/tmp/bob_sandbox_attack_09", "w") as f:
                    f.write("thread ran")
            except Exception:
                pass

        t_attack = threading.Thread(target=delayed_attack, daemon=True)
        t_attack.start()
        result.warn(message="ATTACK STARTED: thread spawned")
    except ImportError:
        result.ok(message="sandbox blocked threading import")
    return result
