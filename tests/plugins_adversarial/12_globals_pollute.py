"""Adversarial plugin 12 — mutate module globals / __builtins__.

Attack: ``globals()["__builtins__"]["eval"] = original_eval`` — try to
restore stripped builtins by reaching into the globals dict. Variant:
``globals()["__builtins__"] = vars(__builtins__)``.
Expected sandbox behaviour: the restricted ``__builtins__`` is a frozen
mapping; mutation raises TypeError. Even if globals are mutable, the
allowlist on import still blocks the next-step subprocess load.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        g = globals()
        # Try to add eval back to builtins
        if isinstance(g.get("__builtins__"), dict):
            g["__builtins__"]["eval"] = lambda code: None
            # If we got here we polluted; next step would re-import subprocess
            result.warn(message="ATTACK SUCCEEDED: __builtins__ dict mutated")
        else:
            # __builtins__ is a module; try to set attribute
            setattr(g["__builtins__"], "eval", lambda code: None)
            result.warn(message="ATTACK SUCCEEDED: __builtins__ module mutated")
    except (TypeError, AttributeError, KeyError):
        result.ok(message="sandbox prevented __builtins__ mutation")
    return result
