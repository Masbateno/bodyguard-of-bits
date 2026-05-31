"""Adversarial plugin 01 — direct subprocess import.

Attack: ``import subprocess; subprocess.run(["touch", target])``
Expected sandbox behaviour: ImportError on ``subprocess`` (not in allowlist).
"""
from bob.scoring import CheckResult

# Target file the attack tries to create. The test reads ``PLUGIN_TARGET``
# from the module to know where to check.
PLUGIN_TARGET = "/tmp/bob_sandbox_attack_01"


def run_check(t=None):
    result = CheckResult()
    try:
        import subprocess
        subprocess.run(["touch", PLUGIN_TARGET], check=False)
        result.warn(message="ATTACK SUCCEEDED: subprocess imported + run executed")
    except ImportError:
        result.ok(message="sandbox blocked subprocess import")
    return result
