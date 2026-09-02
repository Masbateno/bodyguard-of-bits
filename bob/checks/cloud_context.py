"""
Host-side cloud context audit for BOB.

When BOB runs on a cloud instance there are a handful of exposures that are
visible **from the host itself**, offline, without any cloud API or credential —
and those are exactly the ones a single-host auditor should cover. This check
deliberately stays on that side of the line: it never talks to a cloud account,
an IAM API, buckets, security groups or a VPC (that is Scout Suite / Prowler
territory and would dissolve BOB's singularity). It only reads what the kernel
and local filesystem already expose:

  * the cloud provider, from SMBIOS/DMI (``/sys/class/dmi/id``);
  * whether the instance metadata service (169.254.169.254) is reachable
    *on-link* (a link-scoped route, not merely routed via the default gateway);
  * whether a persisted user-data file is present and world-readable.

Detection is deliberately conservative. A DMI-identified provider is
authoritative. A bare cloud-init install is **not**: Ubuntu ships cloud-init
enabled by default, so ``/var/lib/cloud/instance`` exists (with a
``DataSourceNone``) on plenty of Proxmox / VMware / homelab VMs that are not
cloud at all — exactly BOB's historical audience. cloud-init therefore only
counts as cloud when the metadata service is *also* reachable on-link (the
homelab case routes it via the gateway and is correctly excluded).

The whole section is suppressed on a non-cloud host (``skip_if`` on
``is_cloud``), so it only appears where it is meaningful — exactly like the
container posture check.

INFO-only by design (v0.13.1): each line is a *latent finding*. The deductions
(IMDS reachable on-link without enforced IMDSv2 — which can only be confirmed
off the host; world-readable user-data with secrets) belong in the v0.14.0
scoring bundle once calibrated against real instances.

No network calls. Local ``ip route`` + ``systemctl`` + ``/sys`` / ``/var/lib``.

Split into:
  1. CloudContextSnapshot.from_system() — detect provider + gather host signals.
  2. check_cloud_context(snapshot, t)   — pure analysis, returns CheckResult.
"""

from __future__ import annotations

import shlex
import stat
from dataclasses import dataclass
from pathlib import Path

from bob.checks._run import (
    TranslationFunc,
    _identity_t,
    _run,
    path_exists,
)
from bob.scoring import CheckResult

_DMI_DIR = Path("/sys/class/dmi/id")
_DMI_FIELDS = ("sys_vendor", "product_name", "chassis_asset_tag", "bios_vendor")

# Substring (lower-case) found in a DMI field -> human cloud provider name.
# Bare virtualization (QEMU / VMware / VirtualBox) is intentionally absent: a
# local VM is not a cloud instance, and flagging every VM would be noise.
_CLOUD_SIGNATURES: tuple[tuple[str, str], ...] = (
    # Specific substrings only — a bare "amazon" / "google" would false-positive
    # on e.g. an Amazon Linux AMI run elsewhere or a Chromebook (sys_vendor
    # "Google"). EC2 DMI is "Amazon EC2"; GCE product_name is
    # "Google Compute Engine".
    ("amazon ec2", "Amazon EC2"),
    ("google compute", "Google Cloud"),
    ("digitalocean", "DigitalOcean"),
    ("openstack", "OpenStack"),
    ("alibaba", "Alibaba Cloud"),
    ("oraclecloud", "Oracle Cloud"),
    ("hetzner", "Hetzner Cloud"),
    ("scaleway", "Scaleway"),
    ("vultr", "Vultr"),
    ("linode", "Linode / Akamai"),
    ("akamai", "Linode / Akamai"),
)
# Azure publishes a fixed chassis asset tag; matching it avoids flagging
# on-prem Hyper-V (which also reports "Microsoft Corporation" as vendor).
_AZURE_ASSET_TAG = "7783-7084-3265-9085-8269-3286-77"

_IMDS_ADDR = "169.254.169.254"
_CLOUD_INIT_INSTANCE = Path("/var/lib/cloud/instance")
_USERDATA_CANDIDATES = (
    Path("/var/lib/cloud/instance/user-data.txt"),
    Path("/var/lib/cloud/instance/user-data.txt.i"),
)


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

@dataclass
class CloudContextSnapshot:
    """Host-side cloud signals.

    Attributes:
        is_cloud:            True when a cloud provider (or cloud-init + on-link
                             IMDS) was found.
        provider:            human provider name ("" when only cloud-init seen).
        imds_onlink:         IMDS (169.254.169.254) reachable on-link (link route).
        cloud_init_present:  /var/lib/cloud/instance exists.
        userdata_path:       persisted user-data file ("" when none/unreadable).
        userdata_world_read: user-data file is group/other readable.
    """
    is_cloud: bool = False
    provider: str = ""
    imds_onlink: bool = False
    cloud_init_present: bool = False
    userdata_path: str = ""
    userdata_world_read: bool = False

    @classmethod
    def from_system(cls) -> "CloudContextSnapshot":
        snap = cls()
        snap.provider = _detect_provider()
        snap.cloud_init_present = _path_exists(_CLOUD_INIT_INSTANCE)
        snap.imds_onlink = _imds_onlink()
        # Conservative: a DMI provider is authoritative; bare cloud-init is not
        # (it ships enabled on non-cloud Ubuntu/Proxmox/VMware boxes). Require
        # on-link IMDS to corroborate the cloud-init signal.
        snap.is_cloud = bool(snap.provider) or (snap.cloud_init_present and snap.imds_onlink)
        if not snap.is_cloud:
            return snap  # section will be skipped

        for cand in _USERDATA_CANDIDATES:
            mode = _file_mode(cand)
            if mode is not None:
                snap.userdata_path = str(cand)
                snap.userdata_world_read = bool(mode & (stat.S_IRGRP | stat.S_IROTH))
                break
        return snap


def _read_dmi(field: str) -> str:
    """Read one DMI field, lower-cased; "" when unreadable."""
    try:
        return (_DMI_DIR / field).read_text(encoding="utf-8", errors="ignore").strip().lower()
    except OSError:
        return ""


def _detect_provider() -> str:
    """Return a cloud provider name from DMI, or "" when not a known cloud."""
    fields = {f: _read_dmi(f) for f in _DMI_FIELDS}
    if fields.get("chassis_asset_tag") == _AZURE_ASSET_TAG:
        return "Microsoft Azure"
    blob = " ".join(fields.values())
    for needle, name in _CLOUD_SIGNATURES:
        if needle in blob:
            return name
    return ""


def _imds_onlink() -> bool:
    """True when 169.254.169.254 is reachable on-link (link-scoped route).

    A plain host routes the link-local metadata address via its default gateway
    (``... via <gw> ...``); a real cloud instance reaches it directly on the
    interface (``... dev eth0 ...`` with no ``via``). The latter is the IMDS
    signal; the former is a false positive we must reject.

    This is a deliberate **heuristic** on iproute2 text output (the ``via`` /
    ``dev`` keywords), not an absolute proof — it only ever *corroborates*
    cloud-init; a DMI-identified provider is detected independently. Kept text
    parsing on purpose: BOB never opens a socket to the metadata endpoint.
    """
    out = _run("ip", "route", "get", _IMDS_ADDR)
    if not out:
        return False
    first = out.splitlines()[0]
    return " dev " in first and " via " not in first


def _path_exists(p: Path) -> bool:
    """Robust existence check (degrades to False on PermissionError etc.)."""
    try:
        return path_exists(p)
    except OSError:
        return False


def _file_mode(p: Path) -> "int | None":
    """Permission bits of ``p`` (resolving the cloud-init symlink), or None."""
    try:
        return stat.S_IMODE(p.stat().st_mode)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Check logic
# ---------------------------------------------------------------------------

def check_cloud_context(
    snapshot: CloudContextSnapshot, t: TranslationFunc | None = None
) -> CheckResult:
    """Surface host-side cloud exposure (INFO-only, no deduction)."""
    _t = t if t is not None else _identity_t
    result = CheckResult()

    if not snapshot.is_cloud:
        # Defensive: the runner suppresses this section via skip_if.
        return result

    if snapshot.provider:
        result.info(message=_t("cloud_context.detected", provider=snapshot.provider),
                    key="cloud_context.detected")
    else:
        result.info(message=_t("cloud_context.detected_generic"),
                    key="cloud_context.detected_generic")

    if snapshot.imds_onlink:
        result.info(
            message=_t("cloud_context.imds_reachable", addr=_IMDS_ADDR),
            detail=_t("cloud_context.imds_reachable_detail"),
            key="cloud_context.imds_reachable",
        )

    if snapshot.userdata_path:
        if snapshot.userdata_world_read:
            # v0.15.4 "teeth": cloud-init user-data routinely carries passwords,
            # API tokens and SSH keys, and every local user can read this file.
            # The mode is an operator choice — cloud-init writes 0600.
            # ``userdata_present`` alone stays INFO and never deducts: having a
            # user-data file is normal, reading it as a stranger is not.
            result.warn_with_deduction(
                message=_t("cloud_context.userdata_world_readable",
                           path=snapshot.userdata_path),
                detail=_t("cloud_context.userdata_world_readable_detail"),
                key="cloud_context.userdata_world_readable",
                points=2,
                nature="improvement",
                cmd=f"sudo chmod 600 {shlex.quote(snapshot.userdata_path)}",
            )
        else:
            result.info(message=_t("cloud_context.userdata_present",
                                   path=snapshot.userdata_path),
                        key="cloud_context.userdata_present")

    return result
