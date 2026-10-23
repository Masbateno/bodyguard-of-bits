"""v0.26.1 — the publish workflow after the eMudhra / emSign CA incident.

Measured from the 0.26.0 run (20 October 2026): the build job ran
`pip install --upgrade pip build` with pip 26.2.1 — whose vendored certifi
still held emSign ECC Root CA - G3. It was already the latest pip (26.2.2 came
out later that day) and fetched the build tools over that connection; once a
newer pip exists, the same command fetches it over that connection too. The
upload used pypa/gh-action-pypi-publish v1.14.2, before the
fix for GHSA-5xjx-3w67-w9x9 (v1.14.3, commit 7245906). Measured in a venv:
pip 24.0 installs the hash-pinned wheel, refuses a wrong #sha256=, and the
version check exits 1 on 24.0, 0 on 26.2.2.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

_WF = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "publish.yml"
_PIP_WHEEL_SHA = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
_PUBLISH_V1143 = "7245906fb61fa33a13554f9d5fb856fe61758086"


def _build_steps() -> str:
    text = _WF.read_text(encoding="utf-8")
    start = text.index("\n  build:\n")
    return text[start:text.index("\n  publish:\n", start)]


def test_pip_comes_from_a_hash_pinned_wheel():
    steps = _build_steps()
    assert f"pip-26.2.2-py3-none-any.whl#sha256={_PIP_WHEEL_SHA}" in steps
    assert "--upgrade pip" not in steps   # the old pip would fetch the new one


def test_the_build_tools_come_after_the_check():
    steps = _build_steps()
    pinned = steps.index(f"#sha256={_PIP_WHEEL_SHA}")
    check = steps.index("Refuse a pip older than 26.2.2")
    tools = steps.index("python -m pip install build")
    assert pinned < check < tools < steps.index("python -m build\n")


def _check_script() -> str:
    steps = _build_steps()
    body = steps[steps.index("python - <<'PY'\n") + len("python - <<'PY'\n"):steps.index("          PY\n")]
    return "\n".join(line[10:] for line in body.splitlines())


@pytest.mark.parametrize("pip_version, refused", [("26.2.1", True), ("24.0", True),
                                                  ("26.2.2", False), ("26.3", False)])
def test_the_check_refuses_an_old_pip(tmp_path, pip_version, refused):
    script = _check_script().replace('version("pip")', repr(pip_version))
    run = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True)
    assert (run.returncode != 0) is refused, run.stderr


def test_the_upload_action_is_pinned_to_the_fixed_release():
    uses = re.findall(r"uses: pypa/gh-action-pypi-publish@(\S+)", _WF.read_text(encoding="utf-8"))
    assert uses == [_PUBLISH_V1143]
