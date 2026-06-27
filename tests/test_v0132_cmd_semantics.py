"""v0.13.2 — finding-command safety / coherence patch.

Covers:
  * the cmd_type contract guard in CheckResult.add_finding;
  * the docker userns_not_configured command no longer clobbering daemon.json.
(kernel obsolete/update cmd_type are pinned in tests/test_kernel_modules.py.)
"""

from __future__ import annotations

import json

import pytest

from bob.checks.docker_audit import DockerAuditSnapshot, check_docker_audit
from bob.scoring import CheckResult, FindingLevel


class TestCmdTypeGuard:
    def test_valid_values_accepted(self):
        r = CheckResult()
        r.info(message="m", cmd="ls", cmd_type="check", key="k.a")
        r.info(message="m", cmd="sudo apt upgrade", cmd_type="fix", key="k.b")
        assert len(r.findings) == 2

    def test_invalid_value_raises(self):
        r = CheckResult()
        with pytest.raises(ValueError):
            r.info(message="m", cmd="x", cmd_type="action", key="k.c")  # nature value, not a cmd_type

    def test_arbitrary_value_raises(self):
        r = CheckResult()
        with pytest.raises(ValueError):
            r.add_finding(FindingLevel.WARN, "m", cmd="x", cmd_type="bogus", key="k.d")


class TestDockerUsernsNonClobbering:
    def _userns_finding(self):
        snap = DockerAuditSnapshot(docker_installed=True, running_count=1,
                                   userns_remap=False)
        result = check_docker_audit(snap)
        return next(f for f in result.findings
                    if f.key == "docker_hardening.userns_not_configured")

    def test_cmd_is_create_if_absent(self):
        f = self._userns_finding()
        # Must guard on existence so an existing daemon.json is never overwritten.
        assert "test -f /etc/docker/daemon.json" in f.cmd
        # The tee is now inside the create-if-absent branch, not unconditional.
        assert f.cmd.strip().startswith("test -f")

    def test_cmd_has_no_localized_text(self):
        # A human-language string in the cmd would leak the wrong locale into
        # the other language's audit (the v0.11.1 reverse-i18n class).
        f = self._userns_finding()
        for word in ("existant", "existing", "merge", "fusionnez", "back up", "sauvegard"):
            assert word.lower() not in f.cmd.lower()

    def test_detail_warns_about_overwrite_both_locales(self):
        for loc in ("en", "fr"):
            d = json.load(open(f"bob/locales/{loc}.json"))["docker_hardening"]
            detail = d["userns_not_configured_detail"].lower()
            # both locales must warn not to overwrite an existing file
            assert ("overwrite" in detail or "écrasez" in detail or "ecrasez" in detail)
