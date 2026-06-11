"""v0.11.1 — small UX-audit fixes F3 + F5 + F7.

From the post-v0.11.0 functional / perceived-quality audit. These are the
three trivially-safe, no-contract-change items pulled into the v0.11.1
patch (F1 score model, F2 severity presentation, F4 explain exit code, F6
root-gate ordering are deferred to the planned v0.12.0 bundle).

F3 — fwupd device-name parsing leaked connector junk.
  Under the default ``LC_ALL=C``, ``fwupdmgr get-updates`` renders its device
  tree connectors (├ └ ─ │) as ``?``. Tree detection then failed, the parser
  fell into flat mode, and harvested ``?`` / ``??UEFI dbx:`` / the container
  header as "device names" (observed live: "ASUSTeK ... , ?, ??UEFI dbx:").
  Fix: run fwupd under C.UTF-8 so the tree renders correctly, plus a parser
  guard rejecting names that don't start with an alphanumeric.

F5 — the "key not found" explain hint wrongly told the user to use sudo.
  ``--explain list`` needs no sudo (the help marks the whole explain surface
  "no sudo required"), yet the unknown-key hint said "Run 'sudo bob --explain
  list'". Dropped the sudo.

F7 — protocol-unspecified UFW orphan rules displayed a bare port.
  A rule with no protocol (UFW applies it to both tcp+udp) showed as "57621"
  next to proto-qualified siblings like "41681/tcp". Now renders as
  "57621/tcp+udp"; the delete command keeps the bare port (UFW's only form).
"""

from __future__ import annotations

import pytest

from bob import i18n


# ---------------------------------------------------------------------------
# F5 — explain unknown-key hint must not say sudo
# ---------------------------------------------------------------------------


class TestExplainHintNoSudo:
    @pytest.mark.parametrize("lang", ["en", "fr"])
    def test_unknown_hint_has_no_sudo(self, lang):
        i18n.init(lang)
        hint = i18n.t("explain.ui.unknown_hint")
        assert "sudo" not in hint.lower(), (
            f"{lang}: unknown-key explain hint still says sudo — but "
            "`bob --explain list` needs no sudo"
        )
        # Still points the user at the list command.
        assert "--explain list" in hint


# ---------------------------------------------------------------------------
# F8b — disk SMART command comments must not leak French into an EN audit
# ---------------------------------------------------------------------------


class TestDiskSmartCmdLocalised:
    """The smartctl command suggestions in bob/checks/disk.py carried hardcoded
    French inline comments, which leaked French into English audits. They are
    now locale keys (disk.smart_cmd.*)."""

    _KEYS = ["test_short", "test_long", "watch", "abort", "history"]

    def test_no_hardcoded_french_comment_in_disk_source(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "bob" / "checks" / "disk.py").read_text(encoding="utf-8")
        for fr_fragment in ("lancer un test", "surveiller la progression",
                            "interrompre le test", "consulter l'historique"):
            assert fr_fragment not in src, (
                f"hardcoded French {fr_fragment!r} still in disk.py — it leaks "
                "into non-FR audits"
            )

    @pytest.mark.parametrize("key", _KEYS)
    def test_smart_cmd_keys_present_both_locales(self, key):
        i18n.init("en")
        en = i18n.t(f"disk.smart_cmd.{key}")
        i18n.init("fr")
        fr = i18n.t(f"disk.smart_cmd.{key}")
        assert not en.startswith("["), f"EN disk.smart_cmd.{key} missing"
        assert not fr.startswith("["), f"FR disk.smart_cmd.{key} missing"
        # EN comment must not be the French string (the leak being fixed).
        assert en != fr, f"disk.smart_cmd.{key} identical EN/FR — likely untranslated"

    def test_en_comment_is_english(self):
        i18n.init("en")
        assert i18n.t("disk.smart_cmd.test_short") == "run a short self-test (~2 min)"


# ---------------------------------------------------------------------------
# F3 — fwupd parser robustness + UTF-8 locale
# ---------------------------------------------------------------------------


class TestFwupdParsing:
    def test_utf8_locale_env_exists_and_is_utf8(self):
        from bob.checks._run import _C_UTF8_LOCALE_ENV
        assert _C_UTF8_LOCALE_ENV["LC_ALL"] == "C.UTF-8"
        assert _C_UTF8_LOCALE_ENV["LANG"] == "C.UTF-8"
        # LANGUAGE must be cleared (gettext outranks LC_ALL otherwise).
        assert _C_UTF8_LOCALE_ENV["LANGUAGE"] == ""

    def test_proper_tree_parses_clean_device(self):
        from bob.checks.firmware import _parse_fwupd_updates
        proper = (
            "ASUSTeK COMPUTER INC. ASUS X500MA_U500MA\n"
            "│\n"
            "└─UEFI dbx:\n"
            "  │   Device ID: abc\n"
        )
        assert _parse_fwupd_updates(proper) == ["UEFI dbx"]

    def test_degraded_question_mark_output_emits_no_junk(self):
        """When the tree degrades to ``?`` (no UTF-8 locale), the parser must
        not surface ``?`` / ``??UEFI dbx:`` / bare connectors as device names."""
        from bob.checks.firmware import _parse_fwupd_updates
        degraded = (
            "Devices with the latest available firmware version:\n"
            " • UEFI CA\n"
            "ASUSTeK COMPUTER INC. ASUS X500MA_U500MA\n"
            "?\n"
            "??UEFI dbx:\n"
            "  ?   Device ID: abc\n"
        )
        result = _parse_fwupd_updates(degraded)
        # No placeholder/connector junk leaks through.
        for name in result:
            assert name[:1].isalnum(), f"junk device name leaked: {name!r}"
            assert "?" not in name

    def test_no_updates_returns_empty(self):
        from bob.checks.firmware import _parse_fwupd_updates
        assert _parse_fwupd_updates("") == []


# ---------------------------------------------------------------------------
# F7 — UFW orphan-rule port display consistency
# ---------------------------------------------------------------------------


class TestOrphanRulePortDisplay:
    def _run_orphans(self, lines, listening):
        from bob.checks.firewall import _check_orphan_rules
        from bob.scoring import CheckResult
        from bob.checks._run import _identity_t

        result = CheckResult()
        _check_orphan_rules(lines, set(listening), _identity_t, result)
        return [f for f in result.findings if f.key == "firewall_rules.orphan_rule"]

    def test_bare_protocol_port_shows_tcp_udp_but_deletes_bare(self):
        lines = ["[ 2] 57621                      ALLOW IN    Anywhere"]
        findings = self._run_orphans(lines, listening=[])
        assert len(findings) == 1
        f = findings[0]
        # Display clarifies it covers both protocols...
        assert "57621/tcp+udp" in f.message
        # ...but the delete command uses the bare port (UFW's only accepted form).
        assert f.cmd == "sudo ufw delete allow 57621"

    def test_proto_qualified_port_unchanged(self):
        lines = ["[ 1] 41681/tcp                  ALLOW IN    Anywhere"]
        findings = self._run_orphans(lines, listening=[])
        assert len(findings) == 1
        f = findings[0]
        assert "41681/tcp" in f.message
        assert "tcp+udp" not in f.message
        assert f.cmd == "sudo ufw delete allow 41681/tcp"

    def test_listening_port_is_not_flagged_as_orphan(self):
        lines = ["[ 1] 41681/tcp                  ALLOW IN    Anywhere"]
        findings = self._run_orphans(lines, listening=["41681/tcp"])
        assert findings == []
