"""v0.38.0 — texts that said more than BOB measures, made precise.

From the review of a real 0.37.0 audit (Linux Mint 22.3, 14 November 2026). No
verdict changes; each text now says what BOB actually knows:

- ClamAV: the last scan is the last one found in ClamAV's logs.
- Secure Boot: physical access or root are not the only way, and it replaces
  neither disk encryption nor a firmware password.
- UEFI dbx: `fwupdmgr update` applies every pending firmware update.
- journald: 500M is an example, to size to the disk.
- "No changes": what the comparison compares.
- Attack surface, SSH: password auth "tolerated", not "OK".
- Attack surface, Internet-facing: no public address on the host, the router's
  forwards not checked — a neutral line, no longer a green check.
"""

from __future__ import annotations

import pytest

from bob import i18n

_CASES = [
    ("clamav.scan_very_old", {"days": 216, "date": "2026-04-12"}, "ClamAV logs", "journaux de ClamAV", None),
    ("clamav.scan_old", {"days": 40, "date": "2026-10-01"}, "ClamAV logs", "journaux de ClamAV", None),
    ("clamav.scan_recent", {"date": "2026-11-10"}, "ClamAV logs", "journaux de ClamAV", None),
    ("secure_boot.disabled_detail", {}, "disk encryption", "chiffrement du disque", "requires physical access or a prior root compromise"),
    ("firmware.fwupd_dbx_sb_off_detail", {}, "fwupdmgr get-updates", "fwupdmgr get-updates", None),
    ("log_rotation.cmd_comment_maxuse", {}, "for example", "par exemple", None),
    ("compare.no_changes", {}, "the running services", "les services actifs", "No changes detected since last audit"),
    ("exposure.ssh_ok_password_on", {}, "tolerated in this context", "tolérée dans ce contexte", "OK for this context"),
    ("exposure.internet_facing_local", {}, "not checked from here", "ne sont pas vérifiées", "behind NAT / no direct public IP"),
]


@pytest.mark.parametrize("key, kw, en, fr, gone", _CASES, ids=[c[0] for c in _CASES])
def test_the_precise_text_renders_in_both_languages(key, kw, en, fr, gone):
    real = key
    for lang, words in (("en", en), ("fr", fr)):
        i18n.init(lang)
        try:
            text = i18n.t(real, **kw)
        finally:
            i18n.init(lang="en")
        assert words in text, (lang, real, text)
        if gone and lang == "en":
            assert gone not in text, (real, text)
