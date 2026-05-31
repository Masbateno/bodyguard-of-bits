"""Adversarial plugin 04 — exec-based dynamic subprocess construction.

Attack: ``exec("import subprocess; subprocess.run(...)")``
Expected sandbox behaviour: NameError on ``exec`` (restricted builtins).
"""
from bob.scoring import CheckResult

PLUGIN_TARGET = "/tmp/bob_sandbox_attack_04"


def run_check(t=None):
    result = CheckResult()
    try:
        exec(
            "import subprocess\n"
            f"subprocess.run(['touch', '{PLUGIN_TARGET}'], check=False)"
        )
        result.warn(message="ATTACK SUCCEEDED: exec ran subprocess")
    except NameError:
        result.ok(message="sandbox removed 'exec' from builtins")
    except (ImportError, AttributeError):
        result.ok(message="sandbox blocked subprocess import inside exec")
    return result
