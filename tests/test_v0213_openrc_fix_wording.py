"""SSH restart hints must be OpenRC-aware, not systemd-only.

On Alpine (OpenRC) there is no `systemctl`, so a remediation string ending in
`systemctl restart ssh` is not runnable. The dynamic fix commands already resolve
this via `service_restart_cmd()` (rc-service on OpenRC), but the *static* explain
and detail strings hardcoded `systemctl restart ssh` with a distro comment that
named only systemd distros. Every such hint now also names the OpenRC form.
"""

from __future__ import annotations

import json
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _offenders(locale: str) -> list[str]:
    data = json.loads((_ROOT / "bob" / "locales" / f"{locale}.json")
                      .read_text(encoding="utf-8"))
    bad: list[str] = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, str) and "systemctl restart ssh" in node \
                and "rc-service" not in node:
            bad.append(path)

    walk(data, locale)
    return bad


def test_every_ssh_restart_hint_is_openrc_aware_en():
    bad = _offenders("en")
    assert not bad, f"systemd-only ssh restart hints (add rc-service): {bad}"


def test_every_ssh_restart_hint_is_openrc_aware_fr():
    bad = _offenders("fr")
    assert not bad, f"indices restart ssh systemd-only (ajouter rc-service) : {bad}"
