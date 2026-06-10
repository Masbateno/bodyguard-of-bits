"""
Tests for bob/cis_refs.py — CIS benchmark reference lookup.

Coverage:
  - get_cis_ref(): known key, unknown key, None return
  - get_cis_code(): formal CIS keys return code, best-practice keys return None
  - _load(): cache behaviour, JSON integrity, fallback on missing file
  - JSON schema: {ref, code} structure, key pattern, no duplicates
  - No stale explain_cis keys remain in locale files
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bob.cis_refs import _load, get_cis_code, get_cis_ref


_DATA_FILE = Path(__file__).parent.parent / "bob" / "data" / "cis_refs.json"
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_CODE_RE = re.compile(r"^CIS( Docker)?:\d+(\.\d+)*$")


class TestGetCisRef:
    def test_known_key_returns_string(self):
        ref = get_cis_ref("ssh.password_auth")
        assert isinstance(ref, str)
        assert ref.startswith("CIS")

    def test_known_iptables_nft_key(self):
        ref = get_cis_ref("firewall_iptables.input_accept")
        assert ref is not None
        assert ref.startswith("CIS")

    def test_known_kernel_modules_key(self):
        ref = get_cis_ref("kernel_modules.risky_fs")
        assert ref is not None
        assert ref.startswith("CIS")

    def test_new_iptables_no_backend(self):
        ref = get_cis_ref("firewall_iptables.no_backend")
        assert ref is not None

    def test_new_kernel_modules_reboot_pending(self):
        ref = get_cis_ref("kernel_modules.kernels_reboot_pending")
        assert ref is not None

    def test_best_practice_entry_returns_string(self):
        ref = get_cis_ref("virt.bypass_risk")
        assert ref is not None
        assert ref.startswith("Best practice")

    def test_best_practice_entry_no_cis_prefix(self):
        ref = get_cis_ref("samba.smb1_enabled")
        assert ref is not None
        assert not ref.startswith("CIS")

    def test_unknown_key_returns_none(self):
        assert get_cis_ref("does_not.exist") is None

    def test_partial_key_returns_none(self):
        assert get_cis_ref("ssh") is None

    def test_empty_key_returns_none(self):
        assert get_cis_ref("") is None

    def test_services_state_service_inactive(self):
        ref = get_cis_ref("services_health.service_inactive")
        assert ref is not None

    def test_mac_policy_apparmor_inactive(self):
        ref = get_cis_ref("mac_policy.apparmor_inactive")
        assert ref is not None
        assert ref.startswith("CIS")


class TestGetCisCode:
    def test_formal_cis_entry_returns_code(self):
        code = get_cis_code("ssh.max_auth_tries")
        assert code == "CIS:5.2.7"

    def test_code_format_matches_pattern(self):
        # v0.10.1 D-4 Rank 1: ssh.x11_forwarding was split into
        # ssh.x11.forwarding.server (keeps the CIS reference) +
        # ssh.x11.forwarding.client (Best practice — no CIS code).
        code = get_cis_code("ssh.x11.forwarding.server")
        assert code is not None
        assert _CODE_RE.match(code), f"Unexpected code format: {code!r}"

    def test_docker_entry_returns_docker_code(self):
        code = get_cis_code("docker_hardening.privileged")
        assert code == "CIS Docker:5.4"

    def test_best_practice_entry_returns_none(self):
        assert get_cis_code("virt.bypass_risk") is None

    def test_samba_best_practice_returns_none(self):
        assert get_cis_code("samba.smb1_enabled") is None

    def test_disk_best_practice_returns_none(self):
        assert get_cis_code("disk.smart_failed") is None

    def test_unknown_key_returns_none(self):
        assert get_cis_code("does_not.exist") is None

    def test_code_format_rejects_bare_colon(self):
        assert not _CODE_RE.match("CIS:")

    def test_code_format_rejects_alpha_section(self):
        assert not _CODE_RE.match("CIS:foo")

    def test_auditd_code(self):
        code = get_cis_code("auditd.no_rules")
        assert code == "CIS:4.1.4"

    def test_iptables_nft_forward_accept_code(self):
        code = get_cis_code("firewall_iptables.forward_accept")
        assert code == "CIS:3.5.1.1"


class TestLoadCache:
    def test_returns_dict(self):
        data = _load()
        assert isinstance(data, dict)
        assert len(data) >= 130

    def test_entries_have_ref_and_code_keys(self):
        data = _load()
        for key, entry in data.items():
            assert "ref" in entry, f"{key!r}: missing 'ref' field"
            assert "code" in entry, f"{key!r}: missing 'code' field"

    def test_cache_returns_same_object(self):
        a = _load()
        b = _load()
        assert a is b

    def test_load_returns_empty_dict_on_missing_file(self, monkeypatch, tmp_path):
        import bob.cis_refs as mod
        monkeypatch.setattr(mod, "_DATA_FILE", tmp_path / "nonexistent.json")
        mod._load.cache_clear()
        result = mod._load()
        assert result == {}
        mod._load.cache_clear()


class TestJsonSchema:
    def setup_method(self):
        self.data = json.loads(_DATA_FILE.read_text(encoding="utf-8"))

    def test_all_top_level_keys_are_domain_subkey(self):
        for key in self.data:
            assert _KEY_RE.match(key), f"Key {key!r} does not match domain.subkey pattern"

    def test_all_ref_values_are_non_empty_strings(self):
        for key, entry in self.data.items():
            assert isinstance(entry["ref"], str), f"{key!r}: ref is not a string"
            assert entry["ref"].strip(), f"{key!r}: empty ref"

    def test_code_is_string_or_null(self):
        for key, entry in self.data.items():
            code = entry["code"]
            assert code is None or isinstance(code, str), f"{key!r}: code must be str or null"

    def test_formal_cis_refs_start_with_cis(self):
        for key, entry in self.data.items():
            if entry["code"] is not None:
                assert entry["ref"].startswith("CIS"), \
                    f"{key!r}: has code {entry['code']!r} but ref does not start with 'CIS'"

    def test_best_practice_refs_do_not_start_with_cis_benchmark(self):
        for key, entry in self.data.items():
            if entry["code"] is None:
                assert not re.match(r"CIS Ubuntu \d+\.\d+ L[12]", entry["ref"]), \
                    f"{key!r}: code=null but ref looks like a formal CIS control: {entry['ref'][:60]!r}"

    def test_all_codes_match_pattern(self):
        for key, entry in self.data.items():
            if entry["code"] is not None:
                assert _CODE_RE.match(entry["code"]), \
                    f"{key!r}: code {entry['code']!r} does not match expected pattern"

    def test_minimum_entry_count(self):
        assert len(self.data) >= 130

    def test_no_duplicate_keys(self):
        raw = _DATA_FILE.read_text(encoding="utf-8")

        def _check_no_dup(pairs):
            seen: set[str] = set()
            for k, _ in pairs:
                if _KEY_RE.match(k):
                    assert k not in seen, f"Duplicate key in JSON: {k!r}"
                    seen.add(k)
            return dict(pairs)

        json.loads(raw, object_pairs_hook=_check_no_dup)

    def test_best_practice_count_reasonable(self):
        null_count = sum(1 for e in self.data.values() if e["code"] is None)
        assert null_count >= 20, f"Too few best-practice entries: {null_count}"

    def test_code_section_number_appears_in_ref(self):
        """Section number from code must appear verbatim in the ref text."""
        for key, entry in self.data.items():
            if entry["code"] is not None:
                section = entry["code"].split(":", 1)[1]
                assert section in entry["ref"], \
                    f"{key!r}: section {section!r} not found in ref {entry['ref'][:60]!r}"


class TestNoStaleExplainCis:
    def test_en_json_has_no_explain_cis(self):
        en_path = Path(__file__).parent.parent / "bob" / "locales" / "en.json"
        data = json.loads(en_path.read_text(encoding="utf-8"))
        assert "explain_cis" not in data, "explain_cis still present in en.json"

    def test_fr_json_has_no_explain_cis(self):
        fr_path = Path(__file__).parent.parent / "bob" / "locales" / "fr.json"
        data = json.loads(fr_path.read_text(encoding="utf-8"))
        assert "explain_cis" not in data, "explain_cis still present in fr.json"
