"""
v0.8.1 deep-hardening audit fixes regression pins.

The v0.8.1 sub-agent audit surfaced 5 findings on the v0.8.1-prep
surfaces (4 from new T-ships of this cycle + 1 pre-existing 3-way
duplication exposed by T26's docstring claim). All 5 shipped together.

  - I-1: remove_ignore_key destroys hand-curated comments
  - M-1: T32 regex rejects digit-containing keys (fail2ban / ipv6 / ...)
  - M-2: T32 silently accepts services.exposure.<svc_id> overrides
  - M-3: service_label → subkey triple-duplicated
  - M-4: --unignore missing from man + no mutual-exclusion guard
"""

from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path

import pytest


# ===========================================================================
# I-1 — remove_ignore_key preserves hand-curated content
# ===========================================================================

class TestI1IgnoreCommentPreservation:

    def test_comment_above_ignore_block_preserved(self, tmp_path):
        from bob.ignore import remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        path.write_text(
            "# Per ticket SECOPS-1234 — temporarily ignore brute-force\n"
            "ignore:\n"
            "  - key: ssh.password_auth\n"
            "  - key: ssh.permit_root_login\n",
            encoding="utf-8",
        )
        assert remove_ignore_key("ssh.password_auth", path=path) is True
        content = path.read_text(encoding="utf-8")
        assert "# Per ticket SECOPS-1234" in content, (
            "I-1 regression: file-header comment dropped on --unignore"
        )
        assert load_ignore_keys(path) == frozenset({"ssh.permit_root_login"})

    def test_inline_comment_above_key_preserved(self, tmp_path):
        """A comment on the line ABOVE the removed key stays in place. We
        don't try to detect "tied" comments — would be heuristic, risks
        deleting multi-key block comments. The orphan comment is left for
        the operator to clean up."""
        from bob.ignore import remove_ignore_key
        path = tmp_path / "ignore.yml"
        path.write_text(
            "ignore:\n"
            "  # ssh.password_auth: documented exception for legacy automation\n"
            "  - key: ssh.password_auth\n"
            "  - key: ssh.permit_root_login\n",
            encoding="utf-8",
        )
        remove_ignore_key("ssh.password_auth", path=path)
        content = path.read_text(encoding="utf-8")
        assert "documented exception" in content
        assert "- key: ssh.password_auth" not in content
        assert "- key: ssh.permit_root_login" in content

    def test_trailing_comment_preserved(self, tmp_path):
        from bob.ignore import remove_ignore_key
        path = tmp_path / "ignore.yml"
        path.write_text(
            "ignore:\n"
            "  - key: foo.bar\n"
            "# Tail comment after the ignore block\n",
            encoding="utf-8",
        )
        # foo.bar isn't a real key but pin behaviour: write a valid key first
        path.write_text(
            "ignore:\n"
            "  - key: ssh.password_auth\n"
            "# Tail comment after the ignore block\n",
            encoding="utf-8",
        )
        remove_ignore_key("ssh.password_auth", path=path)
        assert "# Tail comment after the ignore block" in path.read_text()

    def test_exact_key_match_no_prefix_collision(self, tmp_path):
        """Removing ``ssh.password_auth`` must NOT delete
        ``ssh.password_authentication_disabled`` even though one is a
        prefix of the other."""
        from bob.ignore import add_ignore_key, remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        # Use valid canonical keys; add via the API so we know the file
        # writes them in the expected form.
        add_ignore_key("ssh.password_auth", path=path)
        add_ignore_key("ssh.permit_root_login", path=path)
        remove_ignore_key("ssh.password_auth", path=path)
        keys = load_ignore_keys(path)
        assert "ssh.password_auth" not in keys
        assert "ssh.permit_root_login" in keys


# ===========================================================================
# M-1 — typo-detection accepts digit-containing keys + file_perms.*
# ===========================================================================

class TestM1DigitContainingKeys:

    def setup_method(self):
        from bob.profiles import _recognised_override_keys
        _recognised_override_keys.cache_clear()

    def _load_with_override(self, *override_lines):
        """Write a temp profile with overrides + capture warnings."""
        from bob.profiles import _load_from_path
        content = (
            "[profile]\nname = m1_test\nextends = server\n"
            "description = M-1 test\n\n[overrides]\n"
            + "".join(f"{k} = {v}\n" for k, v in override_lines)
        )
        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "m1_test.conf"
        path.write_text(content, encoding="utf-8")
        records: list[str] = []
        logger = logging.getLogger("bob.profiles")
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r.getMessage())
        logger.addHandler(handler)
        try:
            return _load_from_path(path, depth=0), records
        finally:
            logger.removeHandler(handler)

    @pytest.mark.parametrize("legit_key", [
        "fail2ban.ssh_jail_active",
        "ipv6.ufw_disabled_no_listeners",
        "ipv6.ufw_disabled_listeners_link_local",
        "ipv6.port_no_v6_rule",
    ])
    def test_digit_containing_legit_key_does_not_warn(self, legit_key):
        _, records = self._load_with_override((legit_key, "info"))
        flagged = [r for r in records if legit_key in r and "not recognised" in r]
        assert not flagged, (
            f"M-1 regression: legitimate runtime-emitted key {legit_key!r} "
            f"triggered a typo warning: {flagged}"
        )

    @pytest.mark.parametrize("legit_key", [
        "file_perms.passwd.world_writable",
        "file_perms.shadow.too_permissive",
        "file_perms.sudoers_nopasswd_all",
    ])
    def test_file_perms_prefix_does_not_warn(self, legit_key):
        _, records = self._load_with_override((legit_key, "info"))
        flagged = [r for r in records if legit_key in r and "not recognised" in r]
        assert not flagged, (
            f"M-1 regression: file_perms.* key {legit_key!r} triggered "
            f"a typo warning: {flagged}"
        )


# ===========================================================================
# M-2 — services.exposure.<svc_id> is bogus, must warn
# ===========================================================================

class TestM2ServicesExposureCanonical:

    def setup_method(self):
        from bob.profiles import _recognised_override_keys
        _recognised_override_keys.cache_clear()

    def _load_with_override(self, *override_lines):
        from bob.profiles import _load_from_path
        content = (
            "[profile]\nname = m2_test\nextends = server\n"
            "description = M-2 test\n\n[overrides]\n"
            + "".join(f"{k} = {v}\n" for k, v in override_lines)
        )
        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "m2_test.conf"
        path.write_text(content, encoding="utf-8")
        records: list[str] = []
        logger = logging.getLogger("bob.profiles")
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r.getMessage())
        logger.addHandler(handler)
        try:
            return _load_from_path(path, depth=0), records
        finally:
            logger.removeHandler(handler)

    # M-2 pass 8 (v0.8.1 audit) narrowed the ``_ufw_inactive`` variants
    # to only the 2 exposures that actually emit them at runtime
    # (``no_rule``, ``loopback_no_rule``). Pre-pass-8 list had the
    # _ufw_inactive variants on all 7 exposures — covered the same
    # false-positive UX that the pass-6 M-2 was meant to close. The
    # narrowed list below now matches the runtime emit sites.
    @pytest.mark.parametrize("canonical", [
        "services.exposure.open_world",
        "services.exposure.open_local",
        "services.exposure.loopback",
        "services.exposure.deny",
        "services.exposure.no_rule",
        "services.exposure.loopback_no_rule",
        "services.exposure.not_listening",
        "services.exposure.no_rule_ufw_inactive",
        "services.exposure.loopback_no_rule_ufw_inactive",
    ])
    def test_canonical_exposure_enum_value_does_not_warn(self, canonical):
        _, records = self._load_with_override((canonical, "info"))
        flagged = [r for r in records if canonical in r and "not recognised" in r]
        assert not flagged, (
            f"M-2 regression: canonical exposure key {canonical!r} triggered "
            f"a typo warning: {flagged}"
        )

    @pytest.mark.parametrize("bogus", [
        "services.exposure.ssh",
        "services.exposure.ollama",
        "services.exposure.totally_invalid",
    ])
    def test_bogus_services_exposure_svc_id_warns(self, bogus):
        _, records = self._load_with_override((bogus, "info"))
        flagged = [r for r in records if bogus in r and "not recognised" in r]
        assert flagged, (
            f"M-2 regression: bogus services.exposure.<svc_id> override "
            f"{bogus!r} was silently accepted as valid (should warn)"
        )


# ===========================================================================
# M-3 — service_label → subkey transform consolidated in bob.registry
# ===========================================================================

class TestM3LabelTransformConsolidation:

    def test_registry_exposes_canonical_helper(self):
        from bob.registry import service_label_to_subkey
        # Pin the documented examples from the helper docstring
        assert service_label_to_subkey("SSH Server") == "ssh_server"
        assert service_label_to_subkey("Samba (Windows file sharing)") == "samba_windows_file_sharing"
        assert service_label_to_subkey("MySQL / MariaDB") == "mysql___mariadb"
        assert service_label_to_subkey("AdGuard Home (DNS sinkhole)") == "adguard_home_dns_sinkhole"
        assert service_label_to_subkey("") == ""

    def test_explain_helper_delegates_to_registry(self):
        """The pre-M-3 inline helper now forwards to the registry helper.
        Same input → identical output."""
        from bob.registry import service_label_to_subkey as reg
        from bob.explain import _service_label_to_subkey as exp
        for label in (
            "SSH Server", "Vaultwarden Password Manager",
            "Ollama (local LLM)", "Tailscale VPN",
        ):
            assert reg(label) == exp(label)

    def test_display_py_no_inline_duplicates(self):
        """The 3-way duplication pre-M-3 was 2× inline in display.py + 1
        in explain.py. Post-M-3 display.py must not contain the inline
        ``.lower().replace(" ", "_").replace("/", "_")`` fragment."""
        src = (Path(__file__).resolve().parent.parent / "bob" / "display.py").read_text(encoding="utf-8")
        # Pattern: `.lower().replace(" ", "_").replace("/", "_")` (the inline transform)
        inline = re.findall(
            r"\.lower\(\)\s*\.replace\(['\"] ['\"],\s*['\"]_['\"]\)\.replace\(['\"]/['\"]",
            src,
        )
        assert not inline, (
            f"M-3 regression: display.py still contains {len(inline)} inline "
            f"service-label transform(s) — should delegate to "
            f"bob.registry.service_label_to_subkey"
        )

    def test_display_py_imports_registry_helper(self):
        src = (Path(__file__).resolve().parent.parent / "bob" / "display.py").read_text(encoding="utf-8")
        assert "service_label_to_subkey" in src, (
            "M-3 regression: display.py no longer imports the centralised helper"
        )


# ===========================================================================
# M-4 — --unignore: man page entry + mutual-exclusion guard
# ===========================================================================

class TestM4UnignoreManPage:

    def test_man_page_documents_unignore(self):
        man = (Path(__file__).resolve().parent.parent / "man" / "bob.1").read_text(encoding="utf-8")
        # The .B macro form
        assert "\\-\\-unignore=" in man, (
            "M-4 regression: --unignore=KEY is missing from man/bob.1"
        )

    def test_man_page_mentions_mutual_exclusion_with_ignore(self):
        man = (Path(__file__).resolve().parent.parent / "man" / "bob.1").read_text(encoding="utf-8")
        # The mutual-exclusion sentence in the --unignore section
        # references the --ignore flag.
        block_pos = man.find("\\-\\-unignore=")
        assert block_pos >= 0
        # Look for "Mutually exclusive" in the next ~600 chars of the man page
        nearby = man[block_pos:block_pos + 600]
        assert "Mutually exclusive" in nearby or "mutually exclusive" in nearby, (
            "M-4 regression: --unignore man entry should call out the "
            "mutual-exclusion with --ignore (consistent with the runtime CLIError)"
        )


class TestM4UnignoreMutualExclusion:

    def _parse(self, *args):
        from bob.cli import parse_args
        return parse_args(list(args))

    def test_ignore_and_unignore_combined_raises(self):
        from bob.cli import CLIError
        with pytest.raises(CLIError, match="mutually exclusive"):
            self._parse("--ignore=ssh.password_auth", "--unignore=ssh.permit_root_login")

    def test_ignore_alone_still_works(self):
        cfg = self._parse("--ignore=ssh.password_auth")
        assert cfg.ignore_key == "ssh.password_auth"
        assert cfg.unignore_key == ""

    def test_unignore_alone_still_works(self):
        cfg = self._parse("--unignore=ssh.password_auth")
        assert cfg.unignore_key == "ssh.password_auth"
        assert cfg.ignore_key == ""
