"""Adversarial plugin 08 — outbound network connection.

Attack: ``socket.socket().connect(("8.8.8.8", 53))``
Expected sandbox behaviour: ImportError on ``socket`` (not in allowlist).
A plugin running root with network access could exfiltrate audit data.
"""
from bob.scoring import CheckResult


def run_check(t=None):
    result = CheckResult()
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # We don't actually connect (no test environment guarantee), the
        # import + socket() creation is the attack signal we measure.
        result.warn(message=f"ATTACK SUCCEEDED: socket created {s!r}")
        s.close()
    except ImportError:
        result.ok(message="sandbox blocked socket import")
    return result
