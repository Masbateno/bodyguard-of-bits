"""v0.28.0 — /etc/login.defs read, and fixed, as shadow reads it.

The 0.19.0 note left "the lighter sed exact-match fragility" on /etc/login.defs
for later. Measured on Debian 13 (shadow's useradd, 25 October 2026):

- `   UMASK 077` (indented): applied — the home was created 700 — and BOB did
  not read it; its sed, anchored at column 0, did not change it;
- `umask 077` (lowercase): ignored — the home was created 755 — and BOB read
  077, a stricter umask than the one in force;
- `UMASK<TAB>077`: applied, read; no UMASK line: 755, nothing read.

And the weak-hash explain's `sed 's/^ENCRYPT_METHOD.*/…/'` changed nothing on a
file whose ENCRYPT_METHOD line is commented out or absent. It now rewrites an
indented line and appends one when none is set.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from bob.checks.umask import _LOGIN_DEFS_RE, _scan

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("line, read", [
    ("UMASK 077", "077"), ("   UMASK 077", "077"), ("UMASK\t077", "077"),
    ("umask 077", None), ("", None), ("#UMASK 077", None),
], ids=["plain", "indented", "tab", "lowercase", "none", "commented"])
def test_the_umask_shadow_applies(tmp_path, line, read):
    defs = tmp_path / "login.defs"
    defs.write_text("PASS_MAX_DAYS 99999\n" + line + "\n", encoding="utf-8")
    assert _scan(defs, _LOGIN_DEFS_RE) == read


def _encrypt_fix(lang: str) -> str:
    how = json.loads((ROOT / "bob" / "locales" / f"{lang}.json").read_text(encoding="utf-8"))[
        "explain"]["password_policy"]["weak_hash"]["how"]
    return next(ln.strip() for ln in how.splitlines() if "ENCRYPT_METHOD YESCRYPT" in ln and "sed" in ln)


@pytest.mark.parametrize("lang", ["en", "fr"])
@pytest.mark.parametrize("before", ["ENCRYPT_METHOD MD5", "   ENCRYPT_METHOD MD5", "#ENCRYPT_METHOD SHA512", ""],
                         ids=["set", "indented", "commented", "absent"])
def test_the_hash_fix_leaves_yescrypt_in_force(tmp_path, lang, before):
    defs = tmp_path / "login.defs"
    defs.write_text("UMASK 022\n" + before + "\n", encoding="utf-8")
    cmd = _encrypt_fix(lang).replace("sudo ", "").replace("/etc/login.defs", str(defs))
    subprocess.run(cmd, shell=True, check=True, capture_output=True)
    active = re.findall(r"^[ \t]*ENCRYPT_METHOD[ \t]+(\S+)", defs.read_text(encoding="utf-8"), re.M)
    assert active and active[-1] == "YESCRYPT", defs.read_text(encoding="utf-8")
