"""Adversarial plugin 11 — bypass import allowlist via __import__.

Attack: ``__import__("subprocess")`` — the underlying function the import
statement uses. If allowlist is enforced only at the `import` statement
level but ``__import__`` is exposed in builtins, this bypasses it.
Expected sandbox behaviour: ``__import__`` is removed from restricted
builtins; allowlist is enforced at the dynamic-load layer regardless.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        sub = __import__("subprocess")
        sub.run(["touch", "/tmp/bob_sandbox_attack_11"], check=False)
        result.warn(message="ATTACK SUCCEEDED: __import__ loaded subprocess")
    except NameError:
        result.ok(message="sandbox removed __import__ from builtins")
    except ImportError:
        result.ok(message="sandbox import hook rejected subprocess")
    return result
