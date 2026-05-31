"""Adversarial plugin 10 — process duplication via os.fork().

Attack: ``os.fork()`` to spawn a child that escapes the sandbox.
Expected sandbox behaviour: raw ``os`` is not in the allowlist; even if it
were, ``os.fork`` would be stripped by the restricted environment.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        import os
        pid = os.fork()
        if pid == 0:
            # Child process — try to persist evidence then exit
            try:
                with open("/tmp/bob_sandbox_attack_10", "w") as f:
                    f.write("fork child ran")
            except Exception:
                pass
            os._exit(0)
        result.warn(message=f"ATTACK SUCCEEDED: fork() returned pid={pid}")
    except ImportError:
        result.ok(message="sandbox blocked raw 'os' import")
    except AttributeError:
        result.ok(message="sandbox stripped os.fork attribute")
    except OSError as exc:
        # Fork itself blocked at the OS level (seccomp, rlimit) — also OK
        result.ok(message=f"sandbox / kernel blocked fork: {exc}")
    return result
