"""v0.28.0 — the integration workflow's apt step fails itself when apt fails.

On 25 October 2026 the Kali mirror (mirror.us.cdn-perfprod.com) was
unreachable, twice. The step's retry loop ended on `sleep 5`, which succeeds,
so the step passed after three failed attempts; python3-venv was missing and
the next step, "Install BOB from source", failed with exit 127 — a code that
says nothing about a mirror. The block is run here as the container runs it
(`sh -e`), with stand-ins for apt-get and sleep on PATH: three failures fail
the step and say why; a success, or a failure then a success, passes.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "integration.yml"


def _apt_block() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("      - name: Install system deps (Debian/Ubuntu/Kali)")
    end = text.index("      - name: Install system deps (Fedora)", start)
    step = text[start:end]
    body = step[step.index("run: |\n") + len("run: |\n"):]
    return textwrap.dedent(body)


def _run(tmp_path: Path, apt_fails: int) -> subprocess.CompletedProcess:
    """Run the step with an apt-get that fails its first *apt_fails* installs."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    count = tmp_path / "count"
    count.write_text("0")
    (bin_dir / "apt-get").write_text(
        "#!/bin/sh\n"
        '[ "$1" = update ] && exit 0\n'
        f'n=$(cat "{count}"); n=$((n + 1)); echo "$n" > "{count}"\n'
        f'[ "$n" -le {apt_fails} ] && exit 100\n'
        "exit 0\n")
    (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}
    return subprocess.run(["sh", "-e", "-c", _apt_block()], env=env,
                          capture_output=True, text=True, timeout=30)


def test_the_block_was_found():
    block = _apt_block()
    assert "apt-get install" in block and "exit 1" in block


@pytest.mark.parametrize("apt_fails, ok", [(3, False), (0, True), (1, True), (2, True)])
def test_the_step_fails_only_when_every_attempt_failed(tmp_path, apt_fails, ok):
    res = _run(tmp_path, apt_fails)
    assert (res.returncode == 0) is ok, res.stdout + res.stderr
    if not ok:
        assert "::error::apt could not install" in res.stdout
