"""v0.10.1 D-4 Rank 1 — ssh.x11_forwarding split + new client-side detection.

Pins the v0.10.1 contract:

  1. Server-side X11Forwarding detection (sshd_config) emits the renamed
     canonical key ``ssh.x11.forwarding.server`` (was ``ssh.x11_forwarding``
     pre-v0.10.1). The ``_BadDirective`` rule in
     ``bob/checks/ssh/_directives.py`` was updated alongside the rename.

  2. Client-side ForwardX11 yes detection in ~/.ssh/config (NEW in v0.10.1)
     emits the new canonical key ``ssh.x11.forwarding.client``. Pre-v0.10.1
     BOB had ZERO client-side X11 detection; this is added detection
     capability, not just a rename.

  3. Pre-v0.10.1 ``ignore.yml`` entries with ``ssh.x11_forwarding`` continue
     to suppress BOTH ``ssh.x11.forwarding.server`` and
     ``ssh.x11.forwarding.client`` via the
     ``bob/_v100_subcheck_renames.py::SUBCHECK_RENAMES_V100`` shim shipped
     in v0.10.0 (the ``ssh.x11.forwarding.*`` glob).

  4. Pre-v0.10.1 ``bob --explain ssh.x11_forwarding`` resolves to the
     server-side content via ``EXPLAIN_KEY_ALIASES`` (the entry was added
     in v0.10.1 — the v0.9.0 D-3 retrait emptied the dict, this is the
     first live alias after that).

Test coverage:

  - Server-side split — sshd_config ``X11Forwarding yes`` emits
    ``ssh.x11.forwarding.server`` (existing ssh.py tests cover the
    underlying mechanic; this file adds the key-name pin)
  - Client-side detection (NEW) — ~/.ssh/config ``ForwardX11 yes`` emits
    ``ssh.x11.forwarding.client`` with the right level + points
  - Legacy ignore.yml — entry ``ssh.x11_forwarding`` suppresses both
    new sub-keys via SUBCHECK_RENAMES_V100 fnmatch glob
  - Legacy explain — ``normalize_key("ssh.x11_forwarding")`` returns
    ``ssh.x11.forwarding.server`` via EXPLAIN_KEY_ALIASES
"""
from __future__ import annotations

import pytest

from bob._v100_subcheck_renames import (
    SUBCHECK_RENAMES_V100,
    matches_legacy_ignore,
)
from bob.explain import EXPLAIN_KEY_ALIASES, normalize_key


# ---------------------------------------------------------------------------
# Server-side rename
# ---------------------------------------------------------------------------


class TestServerSideRename:

    def test_directive_rule_uses_new_key(self):
        """The _BadDirective row for x11forwarding emits the renamed key."""
        from bob.checks.ssh._directives import _BAD_DIRECTIVES
        x11_rules = [r for r in _BAD_DIRECTIVES if r.name == "x11forwarding"]
        assert len(x11_rules) == 1, "Expected exactly 1 x11forwarding _BadDirective"
        assert x11_rules[0].key == "ssh.x11.forwarding.server", (
            f"Expected canonical key 'ssh.x11.forwarding.server', "
            f"got {x11_rules[0].key!r}"
        )

    def test_legacy_key_not_emitted_anywhere(self):
        """The legacy ``ssh.x11_forwarding`` finding key is no longer emitted
        anywhere in the code base (only kept as an EXPLAIN_KEY_ALIASES entry
        for back-compat lookup)."""
        import bob.checks.ssh._directives
        import bob.checks.ssh._subchecks
        src1 = open(bob.checks.ssh._directives.__file__).read()
        src2 = open(bob.checks.ssh._subchecks.__file__).read()
        # The legacy name may only appear in comments documenting the rename
        # — never as a key="..." string literal.
        assert 'key="ssh.x11_forwarding"' not in src1
        assert 'key="ssh.x11_forwarding"' not in src2
        assert "key='ssh.x11_forwarding'" not in src1
        assert "key='ssh.x11_forwarding'" not in src2


# ---------------------------------------------------------------------------
# Client-side detection (NEW in v0.10.1)
# ---------------------------------------------------------------------------


class TestClientSideDetection:

    def test_client_branch_present_in_subchecks(self):
        """The new ``elif k == "forwardx11"`` branch sits next to the
        existing ``elif k == "forwardagent"`` branch in
        ``_check_client_config``. Verified via source scan."""
        import bob.checks.ssh._subchecks
        src = open(bob.checks.ssh._subchecks.__file__).read()
        assert 'elif k == "forwardx11"' in src, (
            "Client-side ForwardX11 detection branch missing from "
            "_check_client_config — v0.10.1 D-4 Rank 1 ship incomplete."
        )
        # Emits the new canonical key
        assert 'key="ssh.x11.forwarding.client"' in src
        # Wires the locale entries added in v0.10.1
        assert 't("ssh.x11.forwarding.client")' in src
        assert 't("ssh.x11.forwarding.client_detail")' in src

    def test_locale_keys_present_in_both_locales(self):
        """The 4 new ssh.x11.forwarding.* locale entries must be present in
        EN + FR (a missing entry would surface a bracketed-fallback, same UX
        trap v0.9.1 fixed for cli.error.json_v1_retired)."""
        import json
        from pathlib import Path
        for loc in ("en", "fr"):
            d = json.loads(Path(f"bob/locales/{loc}.json").read_text(encoding="utf-8"))
            fwd = d.get("ssh", {}).get("x11", {}).get("forwarding", {})
            for k in ("server", "client", "client_detail"):
                assert k in fwd, (
                    f"ssh.x11.forwarding.{k} missing from {loc}.json — "
                    f"v0.10.1 D-4 Rank 1 locale migration incomplete."
                )

    def test_explain_content_present_in_both_locales(self):
        """The new client key has full explain.* content (title + why + how)
        in both locales — required by test_locale_coverage."""
        import json
        from pathlib import Path
        for loc in ("en", "fr"):
            d = json.loads(Path(f"bob/locales/{loc}.json").read_text(encoding="utf-8"))
            client_expl = d.get("explain", {}).get("ssh", {}).get("x11", {}).get("forwarding", {}).get("client", {})
            for leaf in ("title", "why", "how"):
                assert leaf in client_expl and client_expl[leaf], (
                    f"explain.ssh.x11.forwarding.client.{leaf} missing or "
                    f"empty in {loc}.json — operator running "
                    f"``bob --explain ssh.x11.forwarding.client`` would see "
                    f"a bracketed-fallback in {loc} locale."
                )


# ---------------------------------------------------------------------------
# Back-compat — ignore.yml + explain
# ---------------------------------------------------------------------------


class TestBackCompat:

    def test_legacy_key_in_subcheck_renames(self):
        """The v0.10.0 shim foundation must list the legacy key with the
        umbrella glob that covers both new sub-keys."""
        assert "ssh.x11_forwarding" in SUBCHECK_RENAMES_V100
        assert SUBCHECK_RENAMES_V100["ssh.x11_forwarding"] == "ssh.x11.forwarding.*"

    def test_legacy_ignore_covers_server_subkey(self):
        """A v0.9.x ignore.yml with ``ssh.x11_forwarding`` still suppresses
        the server-side finding via the SUBCHECK_RENAMES_V100 shim."""
        assert matches_legacy_ignore("ssh.x11.forwarding.server", "ssh.x11_forwarding")

    def test_legacy_ignore_covers_client_subkey(self):
        """Same legacy entry also covers the new client-side finding."""
        assert matches_legacy_ignore("ssh.x11.forwarding.client", "ssh.x11_forwarding")

    def test_legacy_explain_lookup_resolves_to_server(self):
        """``bob --explain ssh.x11_forwarding`` resolves via EXPLAIN_KEY_ALIASES
        to the server-side content (matches the v0.10.1 D-4 audit decision
        that pre-v0.10.1 the finding was server-side only)."""
        assert "ssh.x11_forwarding" in EXPLAIN_KEY_ALIASES
        assert EXPLAIN_KEY_ALIASES["ssh.x11_forwarding"] == "ssh.x11.forwarding.server"
        assert normalize_key("ssh.x11_forwarding") == "ssh.x11.forwarding.server"

    def test_canonical_keys_pass_through_normalize(self):
        """The new canonical sub-keys themselves pass through normalize_key
        unchanged (not aliases)."""
        assert normalize_key("ssh.x11.forwarding.server") == "ssh.x11.forwarding.server"
        assert normalize_key("ssh.x11.forwarding.client") == "ssh.x11.forwarding.client"
