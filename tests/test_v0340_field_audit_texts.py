"""v0.34.0 — four texts from a field audit of the operator's desktop (12 November 2026).

The run (Linux Mint 22.3, wip-0340) was reviewed; four points held up:
- the container section said "Docker" and "No running containers" on a host
  where Podman alone answered, beside "Docker not installed";
- the AppArmor complain detail read "0 of them are snap profiles";
- the kexec detail said kexec_load_disabled=0 bypasses Secure Boot, whatever
  lockdown and kexec's signature checking say;
- the `↩ N×` mark under a finding was explained nowhere but in changelogs.
"""

from __future__ import annotations

import json
from pathlib import Path

from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
from bob.i18n import init, t

ROOT = Path(__file__).resolve().parent.parent


def test_no_containers_names_the_runtime_asked():
    init("en")
    snap = DockerAuditSnapshot(runtime="podman", runtimes=["podman"])
    f = next(f for f in check_docker_audit(snap, t=t).findings if f.key == "docker_hardening.no_containers")
    assert "(podman)" in f.message and "{" not in f.message


def test_the_section_title_names_both_runtimes():
    for lang in ("en", "fr"):
        title = json.loads((ROOT / f"bob/locales/{lang}.json").read_text())["sections"]["docker_hardening"]
        assert "DOCKER" in title and "PODMAN" in title, lang


def test_apparmor_split_reads_right_with_no_snap():
    for lang in ("en", "fr"):
        init(lang)
        text = t("mac_policy.apparmor_complain_split", snap=0, others="transmission-cli")
        assert not text.startswith("0 "), (lang, text)
        assert ": 0" in text or ": 0 " in text, (lang, text)


def test_kexec_detail_does_not_promise_a_secure_boot_bypass():
    for lang, word in (("en", "lockdown"), ("fr", "lockdown")):
        detail = json.loads((ROOT / f"bob/locales/{lang}.json").read_text())["kexec_lockdown"]["kexec_allowed_detail"]
        assert word in detail and "signature" in detail, lang
        assert "with it, Secure Boot" not in detail and "avec lui, Secure Boot" not in detail, lang


def test_the_recurrence_mark_is_documented():
    for doc in ("DOCUMENTS/TUTORIAL.md", "DOCUMENTS/TUTORIAL_FR.md",
                "DOCUMENTS/README_TECH.md", "DOCUMENTS/README_TECH_FR.md"):
        assert "`↩ N×`" in (ROOT / doc).read_text(), doc
