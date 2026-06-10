"""sshd_config directive tables and weak-crypto reference sets.

Extracted from bob/checks/ssh.py in v0.6.0 (#13 split). Self-contained,
no dependencies on other ssh submodules — safe to import from
``_subchecks`` without introducing cycles.
"""

from __future__ import annotations

from dataclasses import dataclass

from bob.scoring import CheckResult

# ---------------------------------------------------------------------------
# Weak crypto reference sets (OpenSSH deprecated algorithms)
# ---------------------------------------------------------------------------

_WEAK_CIPHERS: frozenset[str] = frozenset({
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
})

_WEAK_MACS: frozenset[str] = frozenset({
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com",
})

_WEAK_KEX: frozenset[str] = frozenset({
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
})

# ---------------------------------------------------------------------------
# sshd_config bad-directive table (declarative, v0.5.2)
# ---------------------------------------------------------------------------
#
# Each row encodes "this directive has a value that should trigger a finding +
# deduction." The shape is uniform enough across ~9 sshd directives to express
# them as data rather than 9 near-identical if-blocks.
#
# Two predicate styles:
#   - ``bad_values`` (tuple): the directive is bad when its lower-cased value
#     IS in this set. E.g. PermitEmptyPasswords is bad when set to "yes".
#   - ``safe_values`` (tuple): the directive is bad when its lower-cased value
#     is NOT in this set. E.g. AllowTcpForwarding is bad except when "no" or
#     "local". Use this when "anything other than these is bad" is more
#     concise than enumerating bad values.
#
# Exactly one of ``bad_values`` or ``safe_values`` must be set; using both or
# neither is a programming error caught by ``__post_init__``.
#
# Directives that don't fit this shape stay imperative in ``_check_sshd_config``:
#   - PermitRootLogin (4-way branch with OK sub-states)
#   - PasswordAuthentication (depends on ssh_exposed orchestration flag)
#   - MaxAuthTries (integer threshold, not enum)
#   - LoginGraceTime, AllowUsers/AllowGroups, _match_block (INFO-only paths)
#   - Weak ciphers/macs/kex (handled by _check_weak_algo with intersection logic)

@dataclass(frozen=True)
class _BadDirective:
    """Declarative rule for one sshd_config directive."""
    name: str            # lowercase directive key in cfg dict
    default: str         # value returned by cfg.get() when directive is missing
    level: str           # "warn" or "alert"
    key: str             # i18n key for finding message + deduction reason
    points: int          # deduction amount
    bad_values: tuple[str, ...] = ()    # values that trigger the finding
    safe_values: tuple[str, ...] = ()   # alternative: anything not in this set is bad
    nature: str = ""     # "" → defaults to "improvement" for warn, "action" for alert
    detail_key: str = "" # optional separate i18n key for `detail=`
    # v0.8.0 drift batch: shell remediation passed as ``cmd=`` to the
    # actionable call. Empty string means "no auto-fix" — the finding is
    # then surfaced manually and ``tests/test_fix_coverage.py`` requires
    # the key to be on the manual-by-design whitelist.
    cmd_template: str = ""

    def __post_init__(self) -> None:
        if bool(self.bad_values) == bool(self.safe_values):
            raise ValueError(
                f"_BadDirective({self.name!r}): exactly one of bad_values "
                f"or safe_values must be set"
            )
        if self.level not in ("warn", "alert"):
            raise ValueError(f"_BadDirective({self.name!r}): level must be 'warn' or 'alert'")

    def is_bad(self, value: str) -> bool:
        v = value.lower()
        if self.bad_values:
            return v in self.bad_values
        return v not in self.safe_values

_BAD_DIRECTIVES: tuple[_BadDirective, ...] = (
    _BadDirective(
        name="permitemptypasswords", default="no",
        bad_values=("yes",),
        level="alert", key="ssh.permit_empty_passwords",
        points=5, nature="improvement",
        cmd_template="sudo sed -i 's/^#*PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        name="x11forwarding", default="no",
        bad_values=("yes",),
        # v0.10.1 D-4 Rank 1: server-side X11 forwarding split from a generic
        # ``ssh.x11_forwarding`` into ``ssh.x11.forwarding.server`` so the
        # parallel client-side detection in _check_client_config can ship
        # under ``.client`` without overloading the legacy key. Pre-v0.10.1
        # ``ignore.yml`` entries with ``ssh.x11_forwarding`` keep working
        # via the SUBCHECK_RENAMES_V100 shim (covers both ``.server`` and
        # ``.client`` via the ``ssh.x11.forwarding.*`` glob).
        level="warn", key="ssh.x11.forwarding.server",
        points=1,
        cmd_template="sudo sed -i 's/^#*X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        name="ignorerhosts", default="yes",
        bad_values=("no",),
        level="warn", key="ssh.ignore_rhosts_disabled",
        points=2,
        cmd_template="sudo sed -i 's/^#*IgnoreRhosts no/IgnoreRhosts yes/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        name="hostbasedauthentication", default="no",
        bad_values=("yes",),
        level="alert", key="ssh.host_based_auth",
        points=3, nature="improvement",
        cmd_template="sudo sed -i 's/^#*HostbasedAuthentication yes/HostbasedAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        name="permituserenvironment", default="no",
        bad_values=("yes",),
        level="warn", key="ssh.permit_user_env",
        points=1,
        cmd_template="sudo sed -i 's/^#*PermitUserEnvironment yes/PermitUserEnvironment no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        name="strictmodes", default="yes",
        bad_values=("no",),
        level="warn", key="ssh.strict_modes_disabled",
        points=2,
        cmd_template="sudo sed -i 's/^#*StrictModes no/StrictModes yes/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        # "local" is acceptable (more restrictive than "yes", documented in
        # remediation) — safe_values rather than bad_values
        name="allowtcpforwarding", default="yes",
        safe_values=("no", "local"),
        level="warn", key="ssh.allow_tcp_forwarding",
        points=1, detail_key="ssh.allow_tcp_forwarding_detail",
        cmd_template="sudo sed -i 's/^#*AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
    _BadDirective(
        name="pubkeyauthentication", default="yes",
        bad_values=("no",),
        level="alert", key="ssh.pubkey_auth_disabled",
        points=3, nature="improvement",
        detail_key="ssh.pubkey_auth_disabled_detail",
        cmd_template="sudo sed -i 's/^#*PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
    ),
)

def _apply_bad_directive(rule: _BadDirective, cfg: dict, result: CheckResult, _t) -> bool:
    """Apply a single ``_BadDirective`` rule. Returns True if a finding was emitted."""
    # M-2 (v0.6.1): single lowercase. ``is_bad`` re-lowercases internally —
    # passing the raw value is enough.
    value = cfg.get(rule.name, rule.default)
    if not rule.is_bad(value):
        return False
    kwargs = {
        "key": rule.key,
        "message": _t(rule.key),
        "points": rule.points,
    }
    if rule.detail_key:
        kwargs["detail"] = _t(rule.detail_key)
    # T31 (v0.8.1): every directive emission must carry a nature so
    # ``bob --fix --apply`` (which filters on ``f.nature == "action"``)
    # picks them up. Rule-level ``nature`` (set in the dataclass) wins;
    # otherwise default by severity: alert → action, warn → improvement.
    # Explicit literal kwarg below — the T31 regression guard inspects
    # call sites for a visible ``nature=`` token.
    if rule.nature:
        nature = rule.nature
    elif rule.level == "alert":
        nature = "action"
    else:
        nature = "improvement"
    # v0.8.0 drift batch: ship cmd= so ``bob --fix --apply`` actually
    # has something to run for the 8 sshd_config directives covered by
    # this table. Empty cmd_template intentionally omits cmd=.
    if rule.cmd_template:
        kwargs["cmd"] = rule.cmd_template
    if rule.level == "alert":
        result.alert_with_deduction(**kwargs, nature=nature)
    else:
        result.warn_with_deduction(**kwargs, nature=nature)
    return True
