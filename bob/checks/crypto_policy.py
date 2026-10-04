"""
System-wide crypto policy for BOB (crypto-policies: Fedora, RHEL, openSUSE).

``update-crypto-policies`` sets, in one place, which algorithms and protocol
versions OpenSSL, GnuTLS, NSS, OpenSSH, libkrb5 and libreswan accept. The
``LEGACY`` policy re-enables what the default refuses (SHA-1 signatures,
smaller DH and RSA keys…) for every one of them at once — usually set to reach
one old server and never reverted.

BOB reads the *applied* policy (``state/current``, written by the tool) and the
*configured* one (``config``). They differ when someone edited ``config`` and
never ran ``update-crypto-policies``: the libraries still use the applied one,
so that is the one judged, and the gap is reported.

Policy names are those shipped in /usr/share/crypto-policies (measured on
Fedora 44 and openSUSE Tumbleweed). Hosts without crypto-policies (Debian,
Ubuntu, Arch, Alpine — each library keeps its own defaults there) get one INFO
saying the mechanism is absent, never an OK.

Findings:
  - LEGACY applied                          : WARN −1
  - a weakening module (SHA1, AD-SUPPORT…)  : INFO
  - a previous release's policy (FEDORA43…) : INFO
  - unrecognised / custom policy            : INFO
  - configured ≠ applied                    : INFO
  - DEFAULT / FUTURE / FIPS / NEXT / BSI     : OK
  - no crypto-policies on this host         : INFO
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t
from bob._atomic import read_text_capped
from bob.scoring import CheckResult

_CONFIG = Path("/etc/crypto-policies/config")
_CURRENT = Path("/etc/crypto-policies/state/current")

_STRONG = frozenset({"DEFAULT", "FUTURE", "FIPS", "NEXT", "BSI", "GOST-ONLY"})
_WEAK = frozenset({"LEGACY"})
_DATED = re.compile(r"^(FEDORA|RHEL)\d+$")
#: Modules that re-enable something the base policy refused.
_WEAKENING_MODULES = frozenset({"SHA1", "AD-SUPPORT", "AD-SUPPORT-LEGACY",
                                "NO-ENFORCE-EMS", "NO-PQ"})


def _first_value(text: str) -> "str | None":
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if s:
            return s
    return None


@dataclass
class CryptoPolicySnapshot:
    """
    Args:
        present:    /etc/crypto-policies/config exists.
        readable:   it (and state/current, when present) could be read.
        configured: the policy string in config, e.g. "DEFAULT:SHA1".
        applied:    the policy string in state/current, None when absent.
    """
    present:    bool = False
    readable:   bool = False
    configured: "str | None" = None
    applied:    "str | None" = None

    @classmethod
    def from_system(cls) -> "CryptoPolicySnapshot":
        snap = cls()
        try:
            snap.configured = _first_value(read_text_capped(_CONFIG, encoding="utf-8",
                                                            errors="replace"))
            snap.present = snap.readable = True
        except FileNotFoundError:
            return snap
        except OSError:
            snap.present = True
            return snap
        try:
            snap.applied = _first_value(read_text_capped(_CURRENT, encoding="utf-8",
                                                         errors="replace"))
        except FileNotFoundError:
            pass
        except OSError:
            snap.readable = False
        return snap


def check_crypto_policy(snapshot: CryptoPolicySnapshot,
                        t: "TranslationFunc | None" = None) -> CheckResult:
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.present:
        result.info(message=_t("crypto_policy.absent"), key="crypto_policy.absent")
        return result
    if not snapshot.readable or not (snapshot.applied or snapshot.configured):
        result.info(message=_t("crypto_policy.unknown"), key="crypto_policy.unknown")
        return result

    # Judge what the libraries actually use; fall back to config when the tool
    # never wrote a state file.
    policy = snapshot.applied or snapshot.configured or ""
    base, *modules = [p.strip().upper() for p in policy.split(":")]
    weakening = [m for m in modules if m in _WEAKENING_MODULES]

    if base in _WEAK:
        result.warn_with_deduction(
            key="crypto_policy.legacy",
            message=_t("crypto_policy.legacy", policy=policy),
            reason=_t("crypto_policy.legacy_reason"),
            points=1,
            detail=_t("crypto_policy.legacy_detail"),
            nature="improvement",
            cmd="update-crypto-policies --set DEFAULT",
        )
    elif _DATED.match(base):
        result.info(message=_t("crypto_policy.dated", policy=policy),
                    detail=_t("crypto_policy.dated_detail"),
                    key="crypto_policy.dated")
    elif base not in _STRONG:
        result.info(message=_t("crypto_policy.unrecognised", policy=policy),
                    key="crypto_policy.unrecognised")
    elif not weakening:
        result.ok(message=_t("crypto_policy.ok", policy=policy), key="crypto_policy.ok")

    if weakening:
        result.info(message=_t("crypto_policy.weakening_module",
                               modules=", ".join(weakening), policy=policy),
                    detail=_t("crypto_policy.weakening_module_detail"),
                    key="crypto_policy.weakening_module")

    if (snapshot.applied and snapshot.configured
            and snapshot.applied.upper() != snapshot.configured.upper()):
        result.info(message=_t("crypto_policy.pending",
                               configured=snapshot.configured, applied=snapshot.applied),
                    key="crypto_policy.pending")
    return result
