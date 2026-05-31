"""Adversarial plugin 13 — environment mutation (LD_PRELOAD class).

Attack: set ``os.environ["LD_PRELOAD"] = "/tmp/evil.so"`` so that any
subsequent subprocess (audit-launched or otherwise) loads attacker code.
Expected sandbox behaviour: raw ``os`` is not in the allowlist; the
multiprocessing.Process isolation means env mutations in the plugin
process don't leak back to the parent audit process anyway.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        import os
        os.environ["LD_PRELOAD"] = "/tmp/bob_sandbox_attack_13.so"
        result.warn(message="ATTACK STARTED: LD_PRELOAD set in plugin process")
    except ImportError:
        result.ok(message="sandbox blocked raw 'os' import")
    except AttributeError:
        result.ok(message="sandbox stripped os.environ attribute")
    return result
