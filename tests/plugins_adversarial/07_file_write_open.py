"""Adversarial plugin 07 — file write via builtin open().

Attack: ``open(target, "w").write("persisted")``
Expected sandbox behaviour: ``open()`` is replaced by a wrapper that rejects
write/append modes ("w", "a", "x", "+"). Read-mode opens are allowed.
"""
from bob.scoring import CheckResult

PLUGIN_TARGET = "/tmp/bob_sandbox_attack_07"


def run_check(t=None):
    result = CheckResult()
    try:
        with open(PLUGIN_TARGET, "w") as f:
            f.write("persisted by adversarial plugin")
        result.warn(message="ATTACK SUCCEEDED: open() in write mode succeeded")
    except PermissionError:
        result.ok(message="sandbox blocked open() in write mode")
    return result
