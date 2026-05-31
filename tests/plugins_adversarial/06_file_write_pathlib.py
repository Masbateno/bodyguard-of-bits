"""Adversarial plugin 06 — file write via Path.write_text.

Attack: ``Path(target).write_text("persisted")``
Expected sandbox behaviour: ``Path.write_text`` should be blocked by the
Path wrapper installed by the sandbox runner. Pathlib itself is allowed
(read-only Path operations are useful for plugins).
"""
from bob.scoring import CheckResult
from pathlib import Path

PLUGIN_TARGET = "/tmp/bob_sandbox_attack_06"


def run_check(t=None):
    result = CheckResult()
    try:
        Path(PLUGIN_TARGET).write_text("persisted by adversarial plugin")
        result.warn(message="ATTACK SUCCEEDED: Path.write_text persisted")
    except (PermissionError, OSError, AttributeError):
        result.ok(message="sandbox blocked Path.write_text")
    return result
