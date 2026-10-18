"""v0.25.1 — `--ignore` on a former key name says what it still suppresses.

`ssh.x11_forwarding` was split in v0.10.1 and `logs.brute_found` renamed in
v0.16.0; ScoreEngine.apply still honours both in ignore.yml. `--ignore` told
the operator such a key "matches no finding BOB can emit — it will never
suppress anything", which the engine contradicted.
"""

import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _ignore(tmp_path, key):
    env = dict(os.environ, HOME=str(tmp_path), LANG="C")
    env.pop("SUDO_USER", None)
    return subprocess.run([sys.executable, "-m", "bob", "--ignore", key, "--lang=en", "-n"],
                          cwd=_ROOT, env=env, capture_output=True, text=True, timeout=60)


def test_a_former_name_is_reported_as_honoured(tmp_path):
    r = _ignore(tmp_path, "ssh.x11_forwarding")
    assert r.returncode == 0
    assert "former name that BOB still honours" in r.stderr
    assert "ssh.x11.forwarding.server" in r.stderr and "ssh.x11.forwarding.client" in r.stderr
    assert "never suppress" not in r.stderr


def test_the_v0160_rename_is_covered_too(tmp_path):
    r = _ignore(tmp_path, "logs.brute_found")
    assert "logs.blocked_repeat_public" in r.stderr
    assert "never suppress" not in r.stderr


def test_a_real_typo_still_warns(tmp_path):
    r = _ignore(tmp_path, "firewall.inactve")
    assert "never suppress" in r.stderr
