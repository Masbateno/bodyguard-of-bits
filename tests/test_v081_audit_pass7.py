"""
v0.8.1 deep-hardening audit pass #7 regression pins.

The 7th sub-agent audit pass surfaced 3 findings — including one regression
introduced by the previous pass's own I-1 fix. All shipped together.

  - I-1 (pass 7) — ``remove_ignore_key`` mismatches the loader on
    multi-space / tab whitespace between ``-`` and ``key:``. Pre-fix the
    file ``  -  key: ssh.x`` (two spaces) was un-removable: loader saw the
    key, remover bailed out, user got the misleading "Key not present"
    message. Same condition triggered by tab separators.
  - I-2 (pass 7) — French typography drift on T10 / T60 error prefixes.
    Hardcoded ``": "`` after a translated prefix produced ``Erreur: ...``
    (wrong) and ``Avertissement : échec du webhook: ...`` (double colon,
    because FR value already embeds ``" : "``). Fix: move colon-space into
    locale values, drop hardcoded suffix.
  - M-1 (pass 7) — ``man/bob.1`` ``--show-ignored`` paragraph described
    the wrong behaviour (claimed "list keys and exit"; actual: display
    suppressed findings inline during the full audit).
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest


# ===========================================================================
# I-1 (pass 7) — remove_ignore_key matches loader grammar exactly
# ===========================================================================

class TestI1Pass7LoaderRemoverParity:
    """The loader regex ``_KEY_LINE_RE`` and the remover line-walk MUST
    agree on what counts as a key line — otherwise a yamllint-styled
    ignore.yml gets the misleading 'Key not present' message even though
    the loader sees the key."""

    def test_two_space_indentation_removable(self, tmp_path):
        from bob.ignore import remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        path.write_text("ignore:\n  -  key: ssh.permit_root_login\n", encoding="utf-8")
        assert "ssh.permit_root_login" in load_ignore_keys(path)
        assert remove_ignore_key("ssh.permit_root_login", path=path) is True
        assert "ssh.permit_root_login" not in load_ignore_keys(path)

    def test_tab_separator_removable(self, tmp_path):
        from bob.ignore import remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        path.write_text("ignore:\n  -\tkey: ssh.password_auth\n", encoding="utf-8")
        assert "ssh.password_auth" in load_ignore_keys(path)
        assert remove_ignore_key("ssh.password_auth", path=path) is True

    def test_standard_indentation_still_works(self, tmp_path):
        """The base case — single space between ``-`` and ``key:`` — must
        still work; we don't want to fix one whitespace contract by
        breaking the canonical form."""
        from bob.ignore import remove_ignore_key, load_ignore_keys
        path = tmp_path / "ignore.yml"
        path.write_text("ignore:\n  - key: ssh.x11_forwarding\n", encoding="utf-8")
        assert remove_ignore_key("ssh.x11_forwarding", path=path) is True
        assert load_ignore_keys(path) == frozenset()

    def test_excessive_whitespace_removable(self, tmp_path):
        """Pathological but RFC-compliant — many spaces between ``-`` and
        ``key:``. Should still remove cleanly."""
        from bob.ignore import remove_ignore_key
        path = tmp_path / "ignore.yml"
        path.write_text("ignore:\n  -      key: ssh.allow_tcp_forwarding\n", encoding="utf-8")
        assert remove_ignore_key("ssh.allow_tcp_forwarding", path=path) is True

    def test_remover_grammar_matches_loader_grammar(self):
        """Direct guard: the loader regex must accept every line shape
        the operator's idiom produces. I-1 pass 8 unified loader +
        remover on a single ``_KEY_LINE_RE`` (the pass 7 sibling regex
        ``_KEY_LINE_MATCH_RE`` was dead code masked by the defensive
        ``load_ignore_keys`` guard, so it was removed)."""
        from bob.ignore import _KEY_LINE_RE
        for line in (
            "  - key: ssh.password_auth\n",
            "  -  key: ssh.password_auth\n",   # 2 spaces
            "  -\tkey: ssh.password_auth\n",   # tab
            "  -     key: ssh.password_auth\n",  # many spaces
            "- key: ssh.password_auth\n",       # no leading indent
        ):
            match = _KEY_LINE_RE.match(line)
            assert match is not None, f"loader rejected {line!r}"
            assert match.group(1) == "ssh.password_auth"


# ===========================================================================
# I-2 (pass 7) — FR colon typography embedded in locale values
# ===========================================================================

class TestI2Pass7FrenchColonTypography:

    _LOCALES_DIR = Path(__file__).resolve().parent.parent / "bob" / "locales"

    @pytest.mark.parametrize("key,expected", [
        ("cli.error.prefix",                  "Error: "),
        ("cli.error.fatal_prefix",            "Fatal error: "),
        ("cli.error.webhook_failed_prefix",   "Warning: webhook failed: "),
    ])
    def test_en_locale_embeds_trailing_colon_space(self, key, expected):
        en = json.loads((self._LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
        parts = key.split(".")
        node = en
        for p in parts:
            node = node[p]
        assert node == expected, (
            f"I-2 pass 7 regression: EN locale {key!r} should embed "
            f"trailing ``: `` (was {node!r})"
        )

    @pytest.mark.parametrize("key,expected", [
        ("cli.error.prefix",                  "Erreur : "),
        ("cli.error.fatal_prefix",            "Erreur fatale : "),
        ("cli.error.webhook_failed_prefix",   "Avertissement : échec du webhook : "),
    ])
    def test_fr_locale_uses_space_colon_space_typography(self, key, expected):
        fr = json.loads((self._LOCALES_DIR / "fr.json").read_text(encoding="utf-8"))
        parts = key.split(".")
        node = fr
        for p in parts:
            node = node[p]
        assert node == expected, (
            f"I-2 pass 7 regression: FR locale {key!r} should follow "
            f"French typography (space-colon-space). Got {node!r}"
        )

    def test_no_remaining_hardcoded_colon_after_t_cli_error_in_main(self):
        """Pin that the ``__main__.py`` sites no longer concatenate a
        hardcoded ``: `` after the translated prefix — they must use the
        locale value verbatim."""
        src = (Path(__file__).resolve().parent.parent / "bob" / "__main__.py").read_text(encoding="utf-8")
        # Forbidden pattern: ``{t('cli.error.*')}: `` (translated prefix
        # immediately followed by hardcoded `:`).
        forbidden = re.findall(
            r"""\{[\w_]*t\(['"]cli\.error\.[\w_]+['"]\)\}: """,
            src,
        )
        assert not forbidden, (
            f"I-2 pass 7 regression: {len(forbidden)} site(s) still "
            f"concatenate hardcoded ``: `` after a translated cli.error.* "
            f"prefix: {forbidden}"
        )


# ===========================================================================
# M-1 (pass 7) — man/bob.1 --show-ignored description matches actual behaviour
# ===========================================================================

class TestM1Pass7ShowIgnoredManDescription:

    def test_man_no_longer_claims_exit_and_dump(self):
        """Pin that the stale "List the persistently-ignored finding keys ...
        and exit" wording is gone from man/bob.1."""
        man = (Path(__file__).resolve().parent.parent / "man" / "bob.1").read_text(encoding="utf-8")
        # Locate the --show-ignored block
        block_start = man.find("\\-\\-show\\-ignored")
        assert block_start >= 0, "man/bob.1 --show-ignored entry missing"
        # Take the next ~600 chars after the marker
        block = man[block_start:block_start + 600]
        assert "and exit" not in block, (
            "M-1 pass 7 regression: man/bob.1 still claims --show-ignored "
            "lists keys and exits — the flag actually runs the full audit "
            "and shows ignored findings inline."
        )

    def test_man_describes_inline_dim_behaviour(self):
        man = (Path(__file__).resolve().parent.parent / "man" / "bob.1").read_text(encoding="utf-8")
        block_start = man.find("\\-\\-show\\-ignored")
        block = man[block_start:block_start + 600]
        assert ("dimmed" in block or "during the audit" in block.lower()), (
            "M-1 pass 7 regression: man/bob.1 --show-ignored should "
            "describe the actual behaviour (dimmed inline rendering during "
            "the audit) rather than the pre-fix file-dump claim."
        )
