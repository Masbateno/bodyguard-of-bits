"""SSH check_ssh + sub-check helpers.

Extracted from bob/checks/ssh.py in v0.6.0 (#13 split). Contains the public
``check_ssh`` entry point plus all ``_check_*`` per-area helpers. Pure logic —
no file I/O or subprocess (those live in ``_snapshot`` / ``_parsers``).
"""

from __future__ import annotations

import shlex
from pathlib import Path

from bob.checks._run import TranslationFunc, _identity_t
from bob.scoring import CheckResult, FindingLevel

from ._directives import (
    _BAD_DIRECTIVES,
    _WEAK_CIPHERS,
    _WEAK_KEX,
    _WEAK_MACS,
    _apply_bad_directive,
)
from ._parsers import _parse_time_seconds
from ._snapshot import SSHSnapshot


def check_ssh(snapshot: SSHSnapshot, t: TranslationFunc | None = None, ssh_exposed: bool = True) -> CheckResult:
    """
    Check SSH server and client configuration.

    Args:
        snapshot:     SSHSnapshot collected from the system (or built in tests).
        t:            Translation function. Defaults to key pass-through.
        ssh_exposed:  False when SSH is not reachable from outside (local network +
                      UFW default deny). Downgrades PasswordAuthentication from WARN
                      to INFO and appends a context note.

    Returns:
        CheckResult with findings and score deductions.
    """
    _t = t if t is not None else _identity_t
    result = CheckResult()

    # --- SSH not installed ---
    if not snapshot.sshd_installed:
        result.info(
            message=_t("ssh.not_installed"),
            detail=_t("ssh.not_installed_detail", cmd=snapshot.install_cmd),
            key="ssh.not_installed",
        )
        return result

    # --- SSH not active ---
    if not snapshot.sshd_active:
        result.warn(
            message=_t("ssh.not_active"),
            detail=_t("ssh.not_active_detail"),
            nature="action",
            cmd="sudo systemctl enable --now ssh",
            key="ssh.not_active",
        )
    else:
        result.ok(message=_t("ssh.active"), key="ssh.active")

    # --- server host keys ---
    _check_host_keys(snapshot, result, _t)

    # --- sshd_config ---
    _check_sshd_config(snapshot, result, _t, ssh_exposed=ssh_exposed)

    # --- ~/.ssh directory permissions ---
    _check_ssh_dir(snapshot, result, _t)

    # --- private keys ---
    _check_private_keys(snapshot, result, _t)

    # --- authorized_keys ---
    _check_authorized_keys(snapshot, result, _t)

    # --- client config (~/.ssh/config) ---
    _check_client_config(snapshot, result, _t)

    # --- known_hosts ---
    _check_known_hosts(snapshot, result, _t)

    # Correlation note: when SSH is behind a deny firewall on a local network,
    # the above informational findings have reduced real-world impact.
    if not ssh_exposed:
        has_non_ok = any(
            f.level != FindingLevel.OK
            for f in result.findings
        )
        if has_non_ok:
            result.info(
                message=_t("ssh.local_context_note"),
                key="ssh.local_context_note",
            )

    return result


def _check_host_keys(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Audit server host keys in /etc/ssh/ssh_host_*."""
    keys = snapshot.host_keys
    if not keys:
        return  # No host keys found — daemon probably not configured, skip silently

    for hk in keys:
        name = hk.path.name

        if hk.key_type == "dsa":
            result.warn_with_deduction(
                key="ssh.host_key_dsa",
                message=_t("ssh.host_key_dsa", name=name),
                reason=_t("ssh.host_key_dsa_reason", name=name),
                points=1,
                detail=_t("ssh.host_key_dsa_detail"),
                cmd=f"sudo rm {shlex.quote(str(hk.path))} {shlex.quote(str(hk.path) + '.pub')} && sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' && sudo systemctl restart ssh",
                template_vars={"name": name},  # pilot v0.4.1 — exposes vars for locale-independent rebuild
            )

        elif hk.key_type == "rsa" and hk.rsa_bits is not None and hk.rsa_bits < 4096:
            result.info(
                message=_t("ssh.host_key_rsa_short", name=name, bits=hk.rsa_bits),
                detail=_t("ssh.host_key_rsa_short_detail"),
                cmd="sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N '' && sudo systemctl restart ssh",
                cmd_type="fix",
                key="ssh.host_key_rsa_short",
                template_vars={"name": name, "bits": hk.rsa_bits},  # pilot v0.4.1
            )

        else:
            # ed25519, ecdsa, RSA ≥ 4096, or unknown → OK
            result.ok(
                message=_t("ssh.host_key_ok", name=name, type=hk.key_type.upper()),
                key="ssh.host_key_ok",
                template_vars={"name": name, "type": hk.key_type.upper()},  # pilot v0.4.1
            )

def _check_sshd_config(snapshot: SSHSnapshot, result: CheckResult, _t,
                       ssh_exposed: bool = True) -> None:
    """Analyse /etc/ssh/sshd_config directives."""
    cfg = snapshot.sshd_config
    found_issue = False

    # PermitRootLogin
    prl = cfg.get("permitrootlogin", "prohibit-password").lower()
    if prl == "yes":
        result.alert_with_deduction(
            key="ssh.permit_root_login",
            message=_t("ssh.permit_root_login", value=prl),
            points=3,
            nature="improvement",
            detail=_t("ssh.permit_root_login_detail"),
            cmd="sudo sed -i 's/^#*PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
        )
        found_issue = True
    elif prl == "no":
        result.ok(
            message=_t("ssh.permit_root_login_disabled"),
            key="ssh.permit_root_login_disabled",
        )
    # ``without-password`` is the pre-6.7 spelling of ``prohibit-password``;
    # OpenSSH still accepts it and canonicalises it (``sshd -T`` prints
    # ``without-password`` for both). Legacy configs carry it, and before
    # v0.15.0 they fell through to the INFO branch — the host was correctly
    # hardened and got no credit for it.
    elif prl in ("prohibit-password", "without-password", "forced-commands-only"):
        result.ok(
            message=_t("ssh.permit_root_login_restricted", value=prl),
            key="ssh.permit_root_login_restricted",
        )
    else:
        result.info(
            message=_t("ssh.permit_root_login", value=prl),
            key="ssh.permit_root_login",
        )

    # PasswordAuthentication
    pw_auth = cfg.get("passwordauthentication", "yes").lower()
    if pw_auth == "yes":
        if ssh_exposed:
            result.warn_with_deduction(
                key="ssh.password_auth",
                message=_t("ssh.password_auth"),
                points=2,
                detail=_t("ssh.password_auth_detail"),
                cmd="sudo sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
                nature="action",
            )
            found_issue = True
        else:
            result.info(
                message=_t("ssh.password_auth_local"),
                detail=_t("ssh.password_auth_local_detail"),
                key="ssh.password_auth",
            )

    # Uniform "directive value is bad" rules — driven by the _BAD_DIRECTIVES
    # table. Covers PermitEmptyPasswords, X11Forwarding, IgnoreRhosts,
    # HostbasedAuthentication, PermitUserEnvironment, StrictModes,
    # AllowTcpForwarding, PubkeyAuthentication.
    for rule in _BAD_DIRECTIVES:
        if _apply_bad_directive(rule, cfg, result, _t):
            found_issue = True

    # MaxAuthTries — integer threshold (doesn't fit the enum-style table).
    # M-3 (v0.6.1): reject non-positive values (sshd treats <=0 as "no retry
    # allowed" which is also misconfiguration); fall back to default 6.
    try:
        max_tries = int(cfg.get("maxauthtries", "6"))
        if max_tries < 1:
            max_tries = 6
    except ValueError:
        max_tries = 6
    if max_tries > 3:
        result.warn_with_deduction(
            key="ssh.max_auth_tries",
            message=_t("ssh.max_auth_tries", value=max_tries),
            points=1,
            cmd="sudo sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config && sudo systemctl restart ssh",
            nature="improvement",
        )
        found_issue = True

    # LoginGraceTime — INFO only, no deduction.
    raw_grace = cfg.get("logingracetime", "120")
    grace_secs = _parse_time_seconds(raw_grace)
    if grace_secs > 60:
        result.info(
            message=_t("ssh.login_grace_time", value=grace_secs),
            key="ssh.login_grace_time",
        )

    # Weak Ciphers / MACs / KexAlgorithms — set-intersection logic, handled by
    # the _check_weak_algo helper (different shape than _BAD_DIRECTIVES rules).
    found_issue |= _check_weak_algo(cfg, result, _t, "ciphers",      _WEAK_CIPHERS, "ssh.weak_ciphers", "ciphers", 2)
    found_issue |= _check_weak_algo(cfg, result, _t, "macs",         _WEAK_MACS,    "ssh.weak_macs",    "macs",    1)
    found_issue |= _check_weak_algo(cfg, result, _t, "kexalgorithms", _WEAK_KEX,    "ssh.weak_kex",     "kex",     1)

    # AllowUsers / AllowGroups (informational only)
    has_restriction = any(k in cfg for k in ("allowusers", "allowgroups",
                                              "denyusers", "denygroups"))
    if not has_restriction:
        result.info(
            message=_t("ssh.no_allow_users"),
            key="ssh.no_allow_users",
        )

    if cfg.get("_match_block"):
        result.info(
            message=_t("ssh.match_block_skipped"),
            key="ssh.match_block_skipped",
        )

    if not found_issue:
        result.ok(message=_t("ssh.config_ok"), key="ssh.config_ok")

def _check_weak_algo(
    cfg: dict, result: "CheckResult", _t,
    cfg_key: str, weak_set: "frozenset[str]", t_key: str, param: str, points: int,
) -> bool:
    """Flag weak crypto algorithm entries; return True if any found."""
    algo_str = cfg.get(cfg_key, "")
    if not algo_str:
        return False
    configured = {a.strip().lower() for a in algo_str.split(",")}
    weak = sorted(configured & weak_set)
    if not weak:
        return False
    joined = ", ".join(weak)
    result.warn_with_deduction(
        key=t_key,
        message=_t(t_key, **{param: joined}),
        points=points,
        nature="improvement",
    )
    return True

def _check_ssh_dir(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Check ~/.ssh directory permissions."""
    user = snapshot.sudo_user or "root"
    if not snapshot.ssh_dir_exists:
        result.info(
            message=_t("ssh.dir_not_found", user=user),
            key="ssh.dir_not_found",
        )
        return

    perms = snapshot.ssh_dir_perms
    if perms is not None and perms != 0o700:
        perms_str = oct(perms)
        result.alert_with_deduction(
            key="ssh.dir_perms",
            message=_t("ssh.dir_perms", perms=perms_str),
            points=2,
            cmd=f"chmod 700 {shlex.quote(str(snapshot.user_home / '.ssh'))}",
        )
    else:
        result.ok(message=_t("ssh.dir_perms_ok"), key="ssh.dir_perms_ok")

def _check_private_keys(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse private SSH keys in ~/.ssh/."""
    if not snapshot.ssh_dir_exists:
        return

    keys = snapshot.private_keys
    if not keys:
        result.info(message=_t("ssh.no_private_keys"), key="ssh.no_private_keys")
        return

    for ki in keys:
        name = ki.path.name

        # permissions
        if ki.permissions != 0o600:
            perms_str = oct(ki.permissions)
            result.alert_with_deduction(
                key="ssh.private_key_perms",
                message=_t("ssh.private_key_perms", name=name, perms=perms_str),
                points=2,
                cmd=f"chmod 600 {shlex.quote(str(ki.path))}",
            )

        # key type
        if ki.key_type == "dsa":
            result.alert_with_deduction(
                key="ssh.dsa_key",
                message=_t("ssh.dsa_key", name=name),
                points=2,
                nature="improvement",
                detail=_t("ssh.dsa_key_detail"),
                cmd=f"sudo rm -f {shlex.quote(str(ki.path))} {shlex.quote(str(ki.path) + '.pub')} && sudo systemctl restart ssh",
            )
        elif ki.key_type == "rsa" and ki.rsa_bits is not None and ki.rsa_bits < 2048:
            result.warn_with_deduction(
                key="ssh.rsa_weak",
                message=_t("ssh.rsa_weak", name=name, bits=ki.rsa_bits),
                points=1,
                nature="action",
            )
        elif ki.key_type == "rsa" and ki.rsa_bits is not None:
            result.ok(
                message=_t("ssh.rsa_ok", name=name, bits=ki.rsa_bits),
                key="ssh.rsa_ok",
            )

        # passphrase
        if ki.has_passphrase is False:
            result.warn_with_deduction(
                key="ssh.no_passphrase",
                message=_t("ssh.no_passphrase", name=name),
                points=1,
                nature="action",
            )

        if (ki.permissions == 0o600
                and ki.key_type not in ("dsa",)
                and not (ki.key_type == "rsa"
                         and ki.rsa_bits is not None
                         and ki.rsa_bits < 2048)
                and ki.has_passphrase is not False):
            result.ok(
                message=_t("ssh.key_ok", name=name),
                key="ssh.key_ok",
            )

def _check_authorized_keys(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse authorized_keys entries."""
    if not snapshot.ssh_dir_exists:
        return

    if not snapshot.authorized_keys_exists:
        result.info(
            message=_t("ssh.authorized_keys_not_found"),
            key="ssh.authorized_keys_not_found",
        )
        return

    # permissions
    perms = snapshot.authorized_keys_perms
    if perms is not None and perms != 0o600:
        ak_path = (snapshot.user_home or Path("/root")) / ".ssh" / "authorized_keys"
        result.alert_with_deduction(
            key="ssh.authorized_keys_perms",
            message=_t("ssh.authorized_keys_perms", perms=oct(perms)),
            points=2,
            cmd=f"chmod 600 {shlex.quote(str(ak_path))}",
        )

    entries = snapshot.authorized_keys_entries
    if not entries:
        return

    ak_found_issue = False

    # weak key types and sizes
    for entry in entries:
        if entry.key_type == "ssh-dss":
            result.alert_with_deduction(
                key="ssh.authorized_keys_dsa",
                message=_t("ssh.authorized_keys_dsa", line=entry.line_no),
                points=2,
                nature="improvement",
            )
            ak_found_issue = True
        elif (entry.key_type == "ssh-rsa"
              and entry.rsa_bits is not None
              and entry.rsa_bits < 2048):
            result.warn_with_deduction(
                key="ssh.authorized_keys_weak_key",
                message=_t("ssh.authorized_keys_weak_key",
                           line=entry.line_no,
                           type=entry.key_type,
                           bits=entry.rsa_bits),
                points=1,
                nature="action",
            )
            ak_found_issue = True

    # duplicate keys
    seen_blobs: dict[str, int] = {}
    for entry in entries:
        if entry.blob_prefix in seen_blobs:
            result.warn_with_deduction(
                key="ssh.authorized_keys_duplicate",
                message=_t("ssh.authorized_keys_duplicate",
                           a=seen_blobs[entry.blob_prefix],
                           b=entry.line_no),
                points=1,
                nature="improvement",
            )
            ak_found_issue = True
        else:
            seen_blobs[entry.blob_prefix] = entry.line_no

    # keys without restrictions (informational — does not prevent ok)
    unrestricted = [e for e in entries if not e.has_restrictions]
    if unrestricted:
        result.info(
            message=_t("ssh.authorized_keys_no_restrictions",
                       count=len(unrestricted)),
            key="ssh.authorized_keys_no_restrictions",
        )

    if not ak_found_issue:
        result.ok(
            message=_t("ssh.authorized_keys_ok", count=len(entries)),
            key="ssh.authorized_keys_ok",
        )

def _check_client_config(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse ~/.ssh/config for dangerous settings."""
    if not snapshot.ssh_dir_exists:
        return

    if not snapshot.client_config_exists:
        result.info(
            message=_t("ssh.client_config_not_found"),
            key="ssh.client_config_not_found",
        )
        return

    found_issue = False
    entries = snapshot.client_config_entries

    # v0.11.0 M-2: hoist the invariant config path/quote out of the loop.
    client_config = (snapshot.user_home or Path("/root")) / ".ssh" / "config"
    client_config_q = shlex.quote(str(client_config))

    for entry in entries:
        k, v = entry.key, entry.value.lower()

        # v0.11.0 M-3: a directive inside a restricted ``Host pattern``
        # block (anything other than the global ``Host *``) is scoped — it
        # only applies when connecting to that host. BOB's own remediation
        # advice for the forwarding directives is "restrict it per-Host", so
        # an operator who follows that advice must not keep getting WARNed as
        # if it were global. For ``forwardx11`` / ``forwardagent`` (legitimate
        # when scoped to a trusted host) we downgrade scoped occurrences to an
        # INFO note with no deduction. ``stricthostkeychecking no`` and
        # ``userknownhostsfile /dev/null`` stay ALERT in ANY scope — disabling
        # host-key verification is a MITM exposure even for a single host.
        #
        # A ``Host`` line can list multiple patterns (``Host bastion *``);
        # OpenSSH applies the block if ANY pattern matches, and a bare ``*``
        # matches every host — so such a line is globally effective. Tokenise
        # and treat the presence of a bare ``*`` token as global, otherwise
        # a config like ``Host gitlab *`` would silently dodge the deduction.
        # A bounded subdomain wildcard (``Host *.example.com``) stays scoped.
        scoped = "*" not in entry.host.split()

        # `no`, `off` and `false` all resolve to "do not check" — `ssh -G`
        # prints `stricthostkeychecking false` for all three. Matching only
        # "no" missed the other two spellings, i.e. missed host-key checking
        # being disabled, which is what makes a MITM silent.
        if k == "stricthostkeychecking" and v in ("no", "off", "false"):
            result.alert_with_deduction(
                key="ssh.client_strict_host_no",
                message=_t("ssh.client_strict_host_no"),
                points=3,
                nature="improvement",
                detail=_t("ssh.client_strict_host_no_detail"),
                cmd=f"sed -i '/^[[:space:]]*StrictHostKeyChecking[[:space:]]\\+no/d' {client_config_q}",
            )
            found_issue = True

        elif k == "userknownhostsfile" and "/dev/null" in v:
            result.alert_with_deduction(
                key="ssh.client_known_hosts_devnull",
                message=_t("ssh.client_known_hosts_devnull"),
                points=3,
                nature="improvement",
                detail=_t("ssh.client_known_hosts_devnull_detail"),
                cmd=f"sed -i '/^[[:space:]]*UserKnownHostsFile[[:space:]].*\\/dev\\/null/d' {client_config_q}",
            )
            found_issue = True

        elif k == "forwardagent" and v in ("yes", "true"):
            if scoped:
                result.info(
                    key="ssh.client_forward_agent_scoped",
                    message=_t("ssh.client_forward_agent_scoped", host=entry.host),
                )
            else:
                result.warn_with_deduction(
                    key="ssh.client_forward_agent",
                    message=_t("ssh.client_forward_agent"),
                    points=1,
                    detail=_t("ssh.client_forward_agent_detail"),
                    cmd=f"sed -i '/^[[:space:]]*ForwardAgent[[:space:]]\\+yes/d' {client_config_q}",
                    nature="action",
                )
            found_issue = True

        # v0.10.1 D-4 Rank 1: detect ``ForwardX11 yes`` client-side.
        # The server side has always emitted ``ssh.x11.forwarding.server``
        # (formerly ``ssh.x11_forwarding`` — see _directives.py); the
        # client-side risk is orthogonal: forwarding an X11 display INTO
        # an untrusted host lets that host take screenshots and inject
        # keystrokes through the X protocol's wide-open security model.
        elif k == "forwardx11" and v in ("yes", "true"):
            if scoped:
                result.info(
                    key="ssh.x11.forwarding.client_scoped",
                    message=_t("ssh.x11.forwarding.client_scoped", host=entry.host),
                )
            else:
                result.warn_with_deduction(
                    key="ssh.x11.forwarding.client",
                    message=_t("ssh.x11.forwarding.client"),
                    points=1,
                    detail=_t("ssh.x11.forwarding.client_detail"),
                    cmd=f"sed -i '/^[[:space:]]*ForwardX11[[:space:]]\\+yes/d' {client_config_q}",
                    nature="action",
                )
            found_issue = True

    if not found_issue:
        result.ok(
            message=_t("ssh.client_config_ok"),
            key="ssh.client_config_ok",
        )

def _check_known_hosts(snapshot: SSHSnapshot, result: CheckResult, _t) -> None:
    """Analyse known_hosts entries."""
    if not snapshot.ssh_dir_exists:
        return

    if not snapshot.known_hosts_exists:
        result.info(
            message=_t("ssh.known_hosts_not_found"),
            key="ssh.known_hosts_not_found",
        )
        return

    entries = snapshot.known_hosts_entries
    found_issue = False

    # deprecated key types
    deprecated = [e for e in entries if e.key_type in ("ssh-dss", "ssh-rsa1")]
    known_hosts_path = (snapshot.user_home or Path("/root")) / ".ssh" / "known_hosts"
    known_hosts_q = shlex.quote(str(known_hosts_path))
    for e in deprecated:
        result.warn_with_deduction(
            key="ssh.known_hosts_deprecated",
            message=_t("ssh.known_hosts_deprecated",
                       line=e.line_no, type=e.key_type),
            points=1,
            cmd=f"sed -i '{e.line_no}d' {known_hosts_q}",
            nature="improvement",
        )
        found_issue = True

    # duplicate host entries (plain text only — hashed entries can't be compared)
    # A host field may contain multiple names: "host1,host2,host3"
    plain_hosts: dict[str, list[int]] = {}
    for e in entries:
        if not e.is_hashed:
            for h in e.host.split(","):
                plain_hosts.setdefault(h.strip(), []).append(e.line_no)
    for host, lines in plain_hosts.items():
        if len(lines) > 1:
            result.info(
                message=_t("ssh.known_hosts_duplicate", host=host),
                key="ssh.known_hosts_duplicate",
            )
            found_issue = True

    if not found_issue:
        result.ok(
            message=_t("ssh.known_hosts_ok", count=len(entries)),
            key="ssh.known_hosts_ok",
        )
