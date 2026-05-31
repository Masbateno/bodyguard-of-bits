"""Adversarial plugin 02 — subprocess via os.system().

Attack: ``os.system("touch /tmp/bob_sandbox_attack_02")``
Expected sandbox behaviour: ImportError on raw ``os`` (only ``os.path`` is in
allowlist).
"""
from bob.scoring import CheckResult

PLUGIN_TARGET = "/tmp/bob_sandbox_attack_02"


def run_check(t=None):
    result = CheckResult()
    try:
        import os
        os.system(f"touch {PLUGIN_TARGET}")
        result.warn(message="ATTACK SUCCEEDED: os.system executed")
    except ImportError:
        result.ok(message="sandbox blocked raw 'os' import")
    except AttributeError:
        # Edge case: os.path was let through but os.system was stripped
        result.ok(message="sandbox stripped os.system attribute")
    return result
