"""v0.27.0 — every action pinned by commit, Dependabot to move them, pip by hash in every job.

0.26.1 pinned the upload action, after the 0.26.0 upload ran
pypa/gh-action-pypi-publish v1.14.2 from the moving `release/v1` branch
(GHSA-5xjx-3w67-w9x9). The other actions still moved under the workflows:
checkout, setup-python, upload/download-artifact, setup-qemu, action-gh-release.
Each is now pinned to the commit its tag pointed at on 24 October 2026 — the
commits the 0.26.1 publish run executed (its log names them) — and Dependabot
proposes the moves as pull requests. The test jobs upgraded pip with the pip in
place, over whatever trust that pip carried; they now install the same
hash-pinned wheel as the build job.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PIP_WHEEL = "pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_by_commit(wf):
    uses = re.findall(r"uses:\s*(\S+)(.*)", wf.read_text(encoding="utf-8"))
    assert uses
    for ref, rest in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), (wf.name, ref)
        assert re.search(r"#\s*v\d", rest), (wf.name, ref, "the version it stands for is written beside it")


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_no_job_upgrades_pip_with_itself(wf):
    text = wf.read_text(encoding="utf-8")
    assert "--upgrade pip" not in text


def test_the_test_jobs_install_the_pinned_pip():
    # Every job that installs tools bootstraps the hash-pinned pip first and
    # then installs from the hashed requirements (v0.27.0, fifth review).
    for name in ("tests.yml", "publish.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        runs = [ln for ln in text.splitlines() if "--require-hashes -r requirements-ci.txt" in ln]
        assert runs, name                      # tools come from the hashed file
        assert PIP_WHEEL in text               # pip itself bootstrapped by hash
        # a tools install either bootstraps the pinned pip on the same line
        # (test/lint jobs) or sits after the build job's own pip-bootstrap step
        assert all(PIP_WHEEL in ln or "build --version" in text for ln in runs), name


def test_dependabot_moves_the_actions():
    conf = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert any(u["package-ecosystem"] == "github-actions" for u in conf["updates"])


def _tag_check_code():
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(text)["jobs"]
    steps = jobs["build"]["steps"]
    names = [s.get("name", "") for s in steps]
    i = names.index("Refuse a tag that is not this release's version")
    assert i < names.index("Build sdist and wheel")
    run = steps[i]["run"]
    return run.split("<<'PY'\n", 1)[1].rsplit("PY", 1)[0]


@pytest.mark.parametrize("tag, ok", [("0.26.1", True), ("9.9.9", False), ("1x.2.3y", False),
                                     ("v0.26.1", False), ("0.26.1-rc1", False)])
def test_only_the_bare_version_of_pyproject_is_built(tag, ok, tmp_path, monkeypatch):
    """Found by the external review: the release environment's tag rule is an
    fnmatch glob ([0-9]*.[0-9]*.[0-9]* matches "1x.2.3y"), and the trigger keeps
    v*. The build refuses any tag other than pyproject.toml's version."""
    import os
    import subprocess
    import sys
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.26.1"\n')
    res = subprocess.run([sys.executable, "-c", _tag_check_code()], cwd=tmp_path,
                         env={**os.environ, "TAG": tag}, capture_output=True, text=True)
    assert (res.returncode == 0) is ok, res.stderr


def test_the_ci_tools_are_installed_from_the_hashed_requirements():
    """v0.27.0, fifth review — pinning pip by hash does not pin what pip then
    installs. The test, lint and build jobs install their tools with
    `pip install --require-hashes -r requirements-ci.txt`, and never a bare
    `pip install pytest`/`ruff`/`build`."""
    for wf in WORKFLOWS:
        text = wf.read_text(encoding="utf-8")
        for run in re.findall(r"run:.*", text):
            if "pip install" not in run:
                continue
            if re.search(r"pip install\b(?!.*--require-hashes)(?:(?!&&).)*\b(pytest|ruff|build|beautifulsoup4)\b", run):
                # a tool install that is not the hashed one — unless it is the
                # package itself (`pip install -e .` / `pip install .`)
                raise AssertionError(f"{wf.name}: unpinned tool install: {run.strip()}")


def test_requirements_ci_is_fully_hashed():
    req = (ROOT / "requirements-ci.txt")
    assert req.exists(), "requirements-ci.txt is missing"
    lines = [l.strip() for l in req.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.strip().startswith("#")]
    # every package line (==) is followed by at least one --hash on its block
    text = req.read_text(encoding="utf-8")
    for pkg in re.findall(r"^([A-Za-z0-9_.-]+)==", text, re.MULTILINE):
        block = re.search(rf"^{re.escape(pkg)}==.*?(?=^\S|\Z)", text, re.MULTILINE | re.DOTALL).group(0)
        assert "--hash=sha256:" in block, f"{pkg} has no hash"
    assert "pytest==" in text and "ruff==" in text and "build==" in text and "beautifulsoup4==" in text
    # pip itself is still bootstrapped by hash in the workflows (the emSign floor)
    assert any("pip-26.2.2" in wf.read_text(encoding="utf-8") for wf in WORKFLOWS)


def test_requirements_ci_matches_the_generator_pins():
    """v0.27.0, seventh review — the committed requirements-ci.txt must match
    the generator's pin list, so a hand-edit that drops or changes a version
    cannot drift from scripts/gen_ci_requirements.py unnoticed. Offline: PINS
    is a module constant, read without touching PyPI."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gen_ci_requirements", ROOT / "scripts" / "gen_ci_requirements.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pinned = {f"{n}=={v}" for n, v, _ in mod.PINS}
    text = (ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
    in_file = set(re.findall(r"^([A-Za-z0-9_.-]+==[^\s;]+)", text, re.MULTILINE))
    assert in_file == pinned, f"requirements-ci.txt drifted from the generator: {in_file ^ pinned}"
