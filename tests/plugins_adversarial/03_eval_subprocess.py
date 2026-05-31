"""Adversarial plugin 03 — eval-based dynamic subprocess construction.

Attack: ``eval("__import__('subprocess').run(['touch', target])")``
Expected sandbox behaviour: NameError on ``eval`` (restricted builtins).
"""
from bob.scoring import CheckResult

PLUGIN_TARGET = "/tmp/bob_sandbox_attack_03"


def run_check(t=None):
    result = CheckResult()
    try:
        eval(f"__import__('subprocess').run(['touch', '{PLUGIN_TARGET}'], check=False)")
        result.warn(message="ATTACK SUCCEEDED: eval executed subprocess")
    except NameError:
        result.ok(message="sandbox removed 'eval' from builtins")
    except (ImportError, AttributeError):
        result.ok(message="sandbox blocked dynamic subprocess import")
    return result
